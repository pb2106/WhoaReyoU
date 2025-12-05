#!/usr/bin/env python3
"""
WRU Initramfs Agent

This script runs during early boot (initramfs stage) BEFORE systemd-udevd.
It sets authorized_default=0 on all USB hubs to prevent automatic device
authorization.

This is Layer 0 of the WRU security system - the earliest possible
intervention point.

Install via:
- Dracut: /usr/lib/dracut/modules.d/99usb-security/
- initramfs-tools: /etc/initramfs-tools/scripts/init-premount/
"""

import os
import sys
import socket
import logging
from pathlib import Path

# Configure logging (minimal for initramfs)
logging.basicConfig(
    level=logging.INFO,
    format='WRU-INIT: %(message)s'
)
logger = logging.getLogger(__name__)

# Constants
SYSFS_USB_BASE = Path("/sys/bus/usb/devices")
SOCKET_PATH = "/run/usb-init-policy.sock"


def set_hub_defaults():
    """
    Set authorized_default=0 on all USB hubs.
    
    This ensures all USB devices connected during boot remain
    unauthorized until explicitly approved.
    """
    count = 0
    
    if not SYSFS_USB_BASE.exists():
        logger.warning("USB sysfs not mounted yet")
        return 0
    
    for hub_path in SYSFS_USB_BASE.glob("usb*"):
        auth_default = hub_path / "authorized_default"
        
        try:
            if auth_default.exists():
                current = auth_default.read_text().strip()
                
                if current != "0":
                    auth_default.write_text("0")
                    logger.info(f"Set {hub_path.name}/authorized_default=0")
                    count += 1
                else:
                    logger.debug(f"{hub_path.name} already secure")
                    
        except PermissionError:
            logger.error(f"Permission denied: {auth_default}")
        except Exception as e:
            logger.error(f"Failed to set {hub_path.name}: {e}")
    
    return count


def deauthorize_all_devices():
    """
    Deauthorize any USB devices that were authorized during kernel init.
    """
    if not SYSFS_USB_BASE.exists():
        return 0
    
    count = 0
    
    for device_path in SYSFS_USB_BASE.iterdir():
        if not device_path.is_dir():
            continue
            
        # Skip hubs (usb1, usb2, etc.)
        if device_path.name.startswith("usb"):
            continue
            
        # Skip interfaces (1-2:1.0)
        if ":" in device_path.name:
            continue
        
        auth_path = device_path / "authorized"
        
        try:
            if auth_path.exists():
                current = auth_path.read_text().strip()
                if current == "1":
                    auth_path.write_text("0")
                    logger.info(f"Deauthorized device: {device_path.name}")
                    count += 1
                    
        except Exception as e:
            logger.debug(f"Cannot deauthorize {device_path.name}: {e}")
    
    return count


def run_socket_server():
    """
    Run Unix socket server for authorization requests.
    
    Protocol:
    - Client sends: "AUTHORIZE <bus-id>\n"
    - Server responds: "OK\n" or "ERROR <message>\n"
    """
    # Create socket directory
    socket_dir = Path(SOCKET_PATH).parent
    socket_dir.mkdir(parents=True, exist_ok=True)
    
    # Remove old socket if exists
    try:
        os.unlink(SOCKET_PATH)
    except FileNotFoundError:
        pass
    
    # Create socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o700)  # Root only
    sock.listen(1)
    sock.settimeout(1.0)  # Allow checking for shutdown
    
    logger.info(f"Listening on {SOCKET_PATH}")
    
    running = True
    
    while running:
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        except Exception as e:
            logger.error(f"Socket accept error: {e}")
            continue
        
        try:
            data = conn.recv(1024).decode().strip()
            
            if not data:
                continue
            
            parts = data.split(maxsplit=1)
            command = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""
            
            if command == "AUTHORIZE" and arg:
                if authorize_device(arg):
                    conn.send(b"OK\n")
                else:
                    conn.send(f"ERROR Failed to authorize {arg}\n".encode())
                    
            elif command == "DEAUTHORIZE" and arg:
                if deauthorize_device(arg):
                    conn.send(b"OK\n")
                else:
                    conn.send(f"ERROR Failed to deauthorize {arg}\n".encode())
                    
            elif command == "QUIT":
                conn.send(b"OK\n")
                running = False
                
            else:
                conn.send(b"ERROR Unknown command\n")
                
        except Exception as e:
            logger.error(f"Socket error: {e}")
        finally:
            conn.close()
    
    sock.close()
    try:
        os.unlink(SOCKET_PATH)
    except Exception:
        pass


def authorize_device(bus_id: str) -> bool:
    """Authorize a specific USB device."""
    auth_path = SYSFS_USB_BASE / bus_id / "authorized"
    
    try:
        if auth_path.exists():
            auth_path.write_text("1")
            logger.info(f"Authorized: {bus_id}")
            return True
    except Exception as e:
        logger.error(f"Failed to authorize {bus_id}: {e}")
    
    return False


def deauthorize_device(bus_id: str) -> bool:
    """Deauthorize a specific USB device."""
    auth_path = SYSFS_USB_BASE / bus_id / "authorized"
    
    try:
        if auth_path.exists():
            auth_path.write_text("0")
            logger.info(f"Deauthorized: {bus_id}")
            return True
    except Exception as e:
        logger.error(f"Failed to deauthorize {bus_id}: {e}")
    
    return False


def main():
    """Main entry point."""
    logger.info("WRU Initramfs Agent starting...")
    
    # Phase 1: Lock down all USB hubs
    hub_count = set_hub_defaults()
    logger.info(f"Secured {hub_count} USB hub(s)")
    
    # Phase 2: Deauthorize any already-connected devices
    device_count = deauthorize_all_devices()
    if device_count > 0:
        logger.info(f"Deauthorized {device_count} device(s) connected during boot")
    
    # Phase 3: Run authorization socket server
    # This allows the main WRU daemon to request authorization
    # once it starts in userspace
    
    if "--daemon" in sys.argv:
        # Run socket server (for testing)
        run_socket_server()
    else:
        # Just configure and exit (normal initramfs mode)
        logger.info("USB security configured, exiting")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
