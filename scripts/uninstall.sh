#!/bin/bash
#
# WRU Uninstall Script
# Removes the Zero-Trust USB Security System
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW} WRU - Uninstall${NC}"
echo -e "${YELLOW}========================================${NC}"
echo

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Confirm
read -p "Are you sure you want to uninstall WRU? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

# Stop service
echo -e "${GREEN}[1/5] Stopping WRU daemon...${NC}"
systemctl stop wru-daemon.service 2>/dev/null || true
systemctl disable wru-daemon.service 2>/dev/null || true

# Remove systemd services
echo -e "${GREEN}[2/5] Removing systemd services...${NC}"
rm -f /etc/systemd/system/wru-daemon.service
rm -f /etc/systemd/system/wru-hid-monitor@.service
systemctl daemon-reload

# Remove udev rules
echo -e "${GREEN}[3/5] Removing udev rules...${NC}"
rm -f /etc/udev/rules.d/80-usb-quarantine.rules
udevadm control --reload-rules

# Restore USB hub defaults
echo -e "${GREEN}[4/5] Restoring USB hub defaults...${NC}"
for hub in /sys/bus/usb/devices/usb*; do
    if [ -f "$hub/authorized_default" ]; then
        echo 1 > "$hub/authorized_default"
        echo "  Restored $(basename $hub)/authorized_default=1"
    fi
done

# Uninstall Python package
echo -e "${GREEN}[5/5] Removing Python package...${NC}"
pip3 uninstall wru -y 2>/dev/null || true

echo
echo -e "${GREEN}WRU has been uninstalled.${NC}"
echo
echo "Configuration files preserved in /etc/wru/"
echo "Log files preserved in /var/log/wru/"
echo
echo "To remove all data:"
echo "  rm -rf /etc/wru /var/log/wru"
