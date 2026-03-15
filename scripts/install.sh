#!/bin/bash
#
# WRU Installation Script
# Installs the Zero-Trust USB Security System
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} WRU - Zero-Trust USB Security System ${NC}"
echo -e "${GREEN}========================================${NC}"
echo

# Check for root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${YELLOW}Installing from: ${PROJECT_DIR}${NC}"
echo

# Step 1: Install Python package
echo -e "${GREEN}[1/7] Installing Python package...${NC}"
cd "$PROJECT_DIR"
pip3 install -e . || {
    echo -e "${YELLOW}pip install failed, trying with --break-system-packages${NC}"
    pip3 install -e . --break-system-packages
}

# Step 2: Create directories
echo -e "${GREEN}[2/7] Creating directories...${NC}"
mkdir -p /etc/wru
mkdir -p /var/log/wru
mkdir -p /run/wru
chmod 700 /etc/wru
chmod 700 /var/log/wru
chmod 755 /run/wru

# Step 3: Install configuration files
echo -e "${GREEN}[3/7] Installing configuration files...${NC}"
cp -n "${PROJECT_DIR}/config/threat-rules.yaml" /etc/wru/ 2>/dev/null || true
cp -n "${PROJECT_DIR}/config/policy.json" /etc/wru/ 2>/dev/null || true
cp -n "${PROJECT_DIR}/config/cve-database.json" /etc/wru/ 2>/dev/null || true
# Deploy default daemon config (never overwrite existing)
cp -n "${PROJECT_DIR}/config/daemon.json" /etc/wru/ 2>/dev/null || true
echo "  Deployed daemon.json"

# Step 4: Install udev rules
echo -e "${GREEN}[4/7] Installing udev rules...${NC}"
cp "${PROJECT_DIR}/udev/80-usb-quarantine.rules" /etc/udev/rules.d/
udevadm control --reload-rules

# Step 5: Install systemd services
echo -e "${GREEN}[5/7] Installing systemd services...${NC}"
cp "${PROJECT_DIR}/systemd/wru-daemon.service" /etc/systemd/system/
cp "${PROJECT_DIR}/systemd/wru-hid-monitor@.service" /etc/systemd/system/
systemctl daemon-reload

# Step 6: Set up USB hub defaults (immediate effect)
echo -e "${GREEN}[6/7] Configuring USB hub security...${NC}"
for hub in /sys/bus/usb/devices/usb*; do
    if [ -f "$hub/authorized_default" ]; then
        echo 0 > "$hub/authorized_default"
        echo "  Set $(basename $hub)/authorized_default=0"
    fi
done

# Step 7: Enable and start service
echo -e "${GREEN}[7/7] Enabling WRU daemon...${NC}"
systemctl enable wru-daemon.service
echo

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN} Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo
echo "To start WRU now:"
echo "  sudo systemctl start wru-daemon"
echo
echo "To view status:"
echo "  wru status"
echo
echo "To list connected devices:"
echo "  wru list"
echo
echo -e "${YELLOW}NOTE: Currently connected USB devices will remain accessible.${NC}"
echo -e "${YELLOW}New devices will be quarantined until approved.${NC}"
echo
echo -e "${GREEN}For full protection, reboot your system.${NC}"
