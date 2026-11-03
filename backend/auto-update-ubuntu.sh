#!/usr/bin/env bash
# ==============================================================================
# NADS Safe Auto-Updater for Ubuntu Server
# Pulls latest website & backend updates from GitHub WITHOUT deleting .env
# or any local server files, then rebuilds React and restarts NADS services.
#
# Usage:
#   bash backend/auto-update-ubuntu.sh
#   bash backend/auto-update-ubuntu.sh --install-timer   # Auto-check every 60s
# ==============================================================================
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${PROJECT_DIR}"

BRANCH="${NADS_GIT_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"
BACKUP_DIR="/tmp/nads-local-backup"
mkdir -p "${BACKUP_DIR}"

# 1. Always preserve local .env so git never deletes it
if [ -f "${PROJECT_DIR}/.env" ]; then
    cp -a "${PROJECT_DIR}/.env" "${BACKUP_DIR}/.env.bak"
fi

# 2. Install systemd timer if requested (--install-timer)
if [ "${1:-}" = "--install-timer" ]; then
    echo "[nads-update] Installing automatic 60-second Git auto-update systemd timer..."
    sudo tee /etc/systemd/system/nads-autoupdate.service >/dev/null <<EOF
[Unit]
Description=NADS Safe Git Auto-Update Service
After=network-online.target

[Service]
Type=oneshot
User=$(stat -c '%U' "${PROJECT_DIR}")
WorkingDirectory=${PROJECT_DIR}
ExecStart=/bin/bash ${PROJECT_DIR}/backend/auto-update-ubuntu.sh
EOF

    sudo tee /etc/systemd/system/nads-autoupdate.timer >/dev/null <<EOF
[Unit]
Description=Run NADS Safe Auto-Update every 60 seconds

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
Unit=nads-autoupdate.service

[Install]
WantedBy=timers.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable --now nads-autoupdate.timer
    echo "[nads-update] Auto-update timer enabled! Check with: systemctl status nads-autoupdate.timer"
    exit 0
fi

# 3. Fetch latest commits from origin
git fetch origin "${BRANCH}" --quiet

LOCAL_SHA="$(git rev-parse HEAD)"
REMOTE_SHA="$(git rev-parse "origin/${BRANCH}")"

if [ "${LOCAL_SHA}" = "${REMOTE_SHA}" ]; then
    # Restore .env if needed and exit quietly when already up-to-date
    if [ -f "${BACKUP_DIR}/.env.bak" ] && [ ! -f "${PROJECT_DIR}/.env" ]; then
        cp -a "${BACKUP_DIR}/.env.bak" "${PROJECT_DIR}/.env"
    fi
    echo "[nads-update] Already up to date (${LOCAL_SHA:0:7})."
    exit 0
fi

echo "[nads-update] New update detected (${LOCAL_SHA:0:7} -> ${REMOTE_SHA:0:7}). Updating safely..."

# 4. Stash any local modifications (without touching untracked files)
STASHED=0
if ! git diff --quiet || ! git diff --cached --quiet; then
    git stash push -m "nads-auto-update-$(date +%s)" --quiet || true
    STASHED=1
fi

# 5. Update tracked files to match remote branch (never runs git clean, so untracked files stay safe)
git reset --hard "origin/${BRANCH}"

# 6. Re-apply stashed local edits if any
if [ "${STASHED}" -eq 1 ]; then
    git stash pop --quiet || echo "[nads-update] Note: local edits kept in 'git stash list'"
fi

# 7. Restore .env if git removed it during transition from old commit
if [ -f "${BACKUP_DIR}/.env.bak" ]; then
    cp -a "${BACKUP_DIR}/.env.bak" "${PROJECT_DIR}/.env"
fi

# 8. Rebuild React website and restart backend service
IFACE="$(ip route | awk '/default/ {print $5; exit}')"
SERVER_IP="$(ip -4 addr show "${IFACE:-ens33}" 2>/dev/null | awk '/inet / {split($2,a,"/"); print a[1]; exit}')"
SERVER_IP="${SERVER_IP:-127.0.0.1}"

npm install --no-audit --no-fund
VITE_API_URL="http://${SERVER_IP}" npm run build

if [ -d "${PROJECT_DIR}/backend/.venv" ]; then
    "${PROJECT_DIR}/backend/.venv/bin/pip" install -q -r "${PROJECT_DIR}/backend/requirements.txt"
fi

if systemctl is-active --quiet nads-api.service; then
    sudo systemctl restart nads-api.service
fi
if systemctl is-active --quiet nginx; then
    sudo systemctl reload nginx
fi

echo "[nads-update] Website & backend updated to ${REMOTE_SHA:0:7} without deleting local files!"
