#!/usr/bin/env bash
# ==============================================================================
# NADS Full Automated Ubuntu Server Setup Script
# Sets up:
#   1. Unbound DNS Resolver (UDP/TCP 53)
#   2. Suricata 8.x IDS with EVE JSON DNS + Alert logging on active NIC (e.g. ens33)
#   3. Server Config (/etc/nads/config.yaml) with auto-detected interface & IP
#   4. Python FastAPI Backend + Log Ingest systemd services (nads-api, nads-ingest)
#   5. React Production Build + Nginx Reverse Proxy on Port 80
#
# Usage on Ubuntu:
#   sudo bash backend/setup-ubuntu-dns.sh [INTERFACE]
# ==============================================================================
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND_DIR="${PROJECT_DIR}/backend"
IFACE="${1:-$(ip route | awk '/default/ {print $5; exit}')}"
IFACE="${IFACE:-ens33}"
SERVER_IP="$(ip -4 addr show "${IFACE}" 2>/dev/null | awk '/inet / {split($2,a,"/"); print a[1]; exit}')"
SERVER_IP="${SERVER_IP:-127.0.0.1}"
SERVER_HOSTNAME="$(hostname)"

echo "=============================================================================="
echo "Starting Automated NADS Setup on ${SERVER_HOSTNAME}"
echo "  Project Directory : ${PROJECT_DIR}"
echo "  Network Interface : ${IFACE}"
echo "  Server IP         : ${SERVER_IP}"
echo "=============================================================================="

echo "[1/7] Installing system packages (Unbound, Suricata, Python3, Nginx, Node.js)..."
apt-get update -y
apt-get install -y software-properties-common curl git jq dnsutils unbound python3-pip python3-venv nginx
add-apt-repository -y ppa:oisf/suricata-stable
apt-get update -y
apt-get install -y suricata

if ! command -v node >/dev/null 2>&1; then
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y nodejs
fi

echo "[2/7] Configuring Unbound DNS Resolver (/etc/unbound/unbound.conf.d/nads-dns.conf)..."
cat <<EOF >/etc/unbound/unbound.conf.d/nads-dns.conf
server:
    interface: 0.0.0.0
    port: 53
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    access-control: 127.0.0.0/8 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 192.168.0.0/16 allow
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes
    use-syslog: yes
    log-queries: yes
    log-replies: yes

forward-zone:
    name: "."
    forward-addr: 1.1.1.1
    forward-addr: 8.8.8.8
EOF

if systemctl is-active --quiet systemd-resolved; then
    mkdir -p /etc/systemd/resolved.conf.d
    cat <<EOF >/etc/systemd/resolved.conf.d/nads-nostub.conf
[Resolve]
DNSStubListener=no
DNS=127.0.0.1
EOF
    systemctl restart systemd-resolved
fi

systemctl enable --now unbound
systemctl restart unbound

echo "[3/7] Writing /etc/nads/config.yaml and configuring Suricata 8.x on ${IFACE}..."
mkdir -p /etc/nads
cp "${BACKEND_DIR}/config.yaml" /etc/nads/config.yaml
sed -i "s/name: .*/name: \"${SERVER_HOSTNAME}\"/" /etc/nads/config.yaml
sed -i "s/listen_interface: .*/listen_interface: \"${IFACE}\"/" /etc/nads/config.yaml
sed -i "s/public_ip: .*/public_ip: \"${SERVER_IP}\"/" /etc/nads/config.yaml
sed -i "s|react_app_url: .*|react_app_url: \"http://${SERVER_IP}\"|" /etc/nads/config.yaml
sed -i "s|api_url: .*|api_url: \"http://${SERVER_IP}/api\"|" /etc/nads/config.yaml

# Suricata 8.x: create /etc/default/suricata AND update interface in /etc/suricata/suricata.yaml
echo "IFACE=${IFACE}" >/etc/default/suricata
if [ -f /etc/suricata/suricata.yaml ]; then
    sed -i "s/interface: eth0/interface: ${IFACE}/g" /etc/suricata/suricata.yaml
fi

# Ensure Suricata rules file exists so suricata.service starts cleanly
mkdir -p /var/lib/suricata/rules
touch /var/lib/suricata/rules/suricata.rules
suricata-update || true

systemctl enable --now suricata
systemctl restart suricata

echo "[4/7] Setting up Python virtual environment & FastAPI dependencies..."
python3 -m venv "${BACKEND_DIR}/.venv"
"${BACKEND_DIR}/.venv/bin/pip" install --upgrade pip
"${BACKEND_DIR}/.venv/bin/pip" install -r "${BACKEND_DIR}/requirements.txt"

echo "[5/7] Creating & starting systemd services (nads-api.service & nads-ingest.service)..."
cat <<EOF >/etc/systemd/system/nads-api.service
[Unit]
Description=NADS FastAPI Anomaly Detection Service
After=network.target suricata.service

[Service]
WorkingDirectory=${BACKEND_DIR}
EnvironmentFile=-${PROJECT_DIR}/.env
ExecStart=${BACKEND_DIR}/.venv/bin/uvicorn app:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

cat <<EOF >/etc/systemd/system/nads-ingest.service
[Unit]
Description=NADS Suricata EVE JSON Log Ingest Service
After=network.target suricata.service nads-api.service

[Service]
WorkingDirectory=${BACKEND_DIR}
ExecStart=${BACKEND_DIR}/.venv/bin/python ${BACKEND_DIR}/ingest.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now nads-api.service
systemctl enable --now nads-ingest.service

echo "[6/7] Building React frontend & configuring Nginx reverse proxy..."
cd "${PROJECT_DIR}"
npm install
VITE_API_URL="http://${SERVER_IP}" npm run build

cat <<EOF >/etc/nginx/sites-available/nads
server {
    listen 80;
    server_name _;

    root ${PROJECT_DIR}/dist;
    index index.html;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    location /ws/ {
        proxy_pass http://127.0.0.1:8000/ws/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

ln -sf /etc/nginx/sites-available/nads /etc/nginx/sites-enabled/nads
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable --now nginx
systemctl reload nginx

echo "[7/7] Configuring UFW firewall rules (if UFW is active)..."
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow 22/tcp
    ufw allow 53/udp
    ufw allow 53/tcp
    ufw allow 80/tcp
    ufw allow 8000/tcp
fi

echo "=============================================================================="
echo "NADS Ubuntu Server Setup Complete!"
echo "  Dashboard URL  : http://${SERVER_IP}"
echo "  Backend API    : http://${SERVER_IP}:8000/api/status"
echo "  Server Config  : /etc/nads/config.yaml"
echo "  Test DNS       : dig @127.0.0.1 login-verify.xyz"
echo "=============================================================================="
