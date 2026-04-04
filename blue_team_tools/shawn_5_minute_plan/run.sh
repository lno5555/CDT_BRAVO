#!/bin/bash

echo "[+] Starting Blue Team 5-Minute Hardening Script..."

# 1. Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "[-] Please run as root (sudo ./script.sh)"
   exit 1
fi

# 2. Argument Handling
DO_BACKUP=false

if [[ "$1" == "--backup" ]]; then
    DO_BACKUP=true

elif [[ "$1" == "--restore" ]]; then
    if [[ -z "$2" ]]; then
        echo "Usage: $0 --restore <backup_file>"
        exit 1
    fi

    echo "[!] Restoring full backup: $2"
    tar -xzf "$2" -C /
    echo "[+] Restore complete."
    exit 0

elif [[ "$1" == "--restore-nginx" ]]; then
    if [[ -z "$2" ]]; then
        echo "Usage: $0 --restore-nginx <backup_file>"
        exit 1
    fi

    echo "[!] Restoring Nginx from backup: $2"
    tar -xzf "$2" -C /

    echo "[+] Testing Nginx configuration..."
    if nginx -t; then
        echo "[+] Restarting Nginx..."
        systemctl restart nginx
        echo "[+] Nginx restored and restarted successfully."
    else
        echo "[-] Nginx config is invalid! Not restarting."
    fi

    exit 0
fi

# 3. Backup Function
backup_dir() {
    SRC_DIR="$1"
    BACKUP_BASE="/opt/turf_backups"
    TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")

    if [ ! -d "$SRC_DIR" ]; then
        echo "[-] Directory $SRC_DIR does not exist!"
        return 1
    fi

    mkdir -p "$BACKUP_BASE"

    BACKUP_FILE="$BACKUP_BASE/$(basename $SRC_DIR)_$TIMESTAMP.tar.gz"

    echo "[+] Backing up $SRC_DIR to $BACKUP_FILE ..."
    tar -czf "$BACKUP_FILE" "$SRC_DIR"

    echo "[+] Backup complete."
}

# 4. Optional Backup Step
if [ "$DO_BACKUP" = true ]; then
    echo "[+] Backup mode enabled..."

    backup_dir "/etc/nginx"
    backup_dir "/var/www"

    echo "[+] Available backups:"
    ls -lh /opt/turf_backups
fi

# 5. Update system
echo "[+] Updating system packages..."
apt update -y && apt upgrade -y

# 6. Install essential tools
echo "[+] Installing security tools..."
apt install -y ufw net-tools lsof curl

# 7. Configure firewall
echo "[+] Configuring UFW firewall..."
ufw --force reset
ufw default allow outgoing

ufw allow 22/tcp   # SSH
ufw allow 80/tcp   # HTTP
ufw allow 443/tcp  # HTTPS
ufw default deny incoming
ufw --force enable
ufw status verbose

# 8. Check active connections
echo "[+] Listing active network connections..."
ss -tulnp
lsof -i -n -P | head -20

# 9. Process inspection
echo "[+] Top CPU processes:"
ps aux --sort=-%cpu | head -10
echo "[!] Review processes manually before killing."

# 10. Secure Nginx
echo "[+] Securing Nginx..."

NGINX_CONF="/etc/nginx/nginx.conf"

if [ -f "$NGINX_CONF" ]; then
    sed -i 's/autoindex on;/autoindex off;/g' "$NGINX_CONF"

    echo "[+] Testing Nginx config..."
    if nginx -t; then
        systemctl restart nginx
        echo "[+] Nginx hardened and restarted."
    else
        echo "[-] Nginx config invalid! Skipping restart."
    fi
else
    echo "[!] Nginx not found, skipping..."
fi

# 11. Inspect web directory
echo "[+] Checking /var/www for recent changes..."
if [ -d "/var/www" ]; then
    find /var/www -type f -mtime -1
fi

# 12. Persistence checks
echo "[+] Checking cron jobs..."
crontab -l 2>/dev/null

echo "[+] System cron directories:"
ls /etc/cron.*

echo "[+] Enabled services:"
systemctl list-unit-files --type=service | grep enabled

# 13. User review
echo "[+] Listing system users:"
cut -d: -f1 /etc/passwd

echo "[!] Lock suspicious accounts manually:"
echo "    usermod -L <username>"

echo "[+] Initial hardening complete!"
echo "[!] Continue with deeper forensic analysis."
