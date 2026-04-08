#!/bin/bash
set -euo pipefail

echo "═══════════════════════════════════════════════"
echo "  SambaGuard — Control, Secure, Monitor"
echo "═══════════════════════════════════════════════"

# Ensure required directories exist with correct permissions
mkdir -p /var/lib/sambaguard/backups
mkdir -p /var/log/sambaguard
mkdir -p /etc/samba
mkdir -p /srv/samba

# Initialize Samba if no config exists
if [ ! -f /etc/samba/smb.conf ]; then
    echo "[INFO] No smb.conf found, creating minimal default..."
    cat > /etc/samba/smb.conf << 'EOF'
[global]
   workgroup = WORKGROUP
   server string = Samba Server
   security = user
   map to guest = Bad User
   dns proxy = no
   log level = 1
   max log size = 50
EOF
fi

# Start nmbd in background (NetBIOS name resolution)
if command -v nmbd &>/dev/null; then
    echo "[INFO] Starting nmbd..."
    nmbd --daemon --no-process-group 2>/dev/null || echo "[WARN] nmbd failed to start (optional)"
fi

# Start smbd in background
if command -v smbd &>/dev/null; then
    echo "[INFO] Starting smbd..."
    smbd --daemon --no-process-group || echo "[WARN] smbd failed to start"
fi

echo "[INFO] Starting SambaGuard on :${PORT:-8080}"
exec /usr/local/bin/sambaguard "$@"
