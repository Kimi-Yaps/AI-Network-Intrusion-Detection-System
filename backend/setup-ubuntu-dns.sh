#!/usr/bin/env bash
# ==============================================================================
# NADS Ubuntu Linux DNS Server (Unbound) + Suricata DNS Sensor Setup Script
# Usage: sudo bash backend/setup-ubuntu-dns.sh [INTERFACE]
# Example: sudo bash backend/setup-ubuntu-dns.sh eth0
# ==============================================================================
set -euo pipefail

IFACE="${1:-$(ip route | awk '/default/ {print $5; exit}')}"
IFACE="${IFACE:-eth0}"

echo "[1/5] Detecting active Ubuntu network interface: ${IFACE}"

echo "[2/5] Installing Unbound DNS server, Suricata IDS, and DNS utilities..."
apt-get update -y
apt-get install -y software-properties-common curl jq dnsutils unbound
add-apt-repository -y ppa:oisf/suricata-stable
apt-get update -y
apt-get install -y suricata

echo "[3/5] Configuring Unbound DNS Resolver (/etc/unbound/unbound.conf.d/nads-dns.conf)..."
cat <<EOF >/etc/unbound/unbound.conf.d/nads-dns.conf
server:
    interface: 0.0.0.0
    port: 53
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    # Allow RFC1918 private LAN & localhost clients to query this DNS server
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

# Disable systemd-resolved stub listener on 127.0.0.53:53 if it conflicts with Unbound on port 53
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

echo "[4/5] Configuring Suricata interface (${IFACE}) and /etc/nads/config.yaml..."
sed -i "s/^IFACE=.*/IFACE=${IFACE}/" /etc/default/suricata || echo "IFACE=${IFACE}" >>/etc/default/suricata

mkdir -p /etc/nads
if [ ! -f /etc/nads/config.yaml ]; then
    cp "$(dirname "$0")/config.yaml" /etc/nads/config.yaml
    sed -i "s/listen_interface: .*/listen_interface: \"${IFACE}\"/" /etc/nads/config.yaml
fi

systemctl enable --now suricata
systemctl restart suricata

echo "[5/5] Opening DNS (53/tcp, 53/udp) and NADS API (8000/tcp) in UFW if active..."
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow 53/udp
    ufw allow 53/tcp
    ufw allow 8000/tcp
fi

echo "=============================================================================="
echo "Ubuntu DNS + Suricata Sensor is active on interface: ${IFACE}"
echo "Test DNS resolution:   dig @127.0.0.1 example.com"
echo "Test Suspicious TLD:   dig @127.0.0.1 login-verify.xyz"
echo "Watch Suricata DNS:    sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type==\"dns\")'"
echo "=============================================================================="
