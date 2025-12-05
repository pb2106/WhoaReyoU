"""
Device Authorization Module

Handles USB device authorization/deauthorization via sysfs.
Implements the dual-barrier enforcement strategy.
"""

import os
import stat
import asyncio
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum, auto

logger = logging.getLogger(__name__)


class AuthorizationState(Enum):
    """Device authorization states."""
    UNAUTHORIZED = auto()
    AUTHORIZED = auto()
    QUARANTINED = auto()
    DENIED = auto()


@dataclass
class DeviceInfo:
    """USB device information extracted from sysfs."""
    
    bus_id: str  # e.g., "1-2" or "1-2:1.0"
    vendor_id: str = ""
    product_id: str = ""
    serial: str = ""
    manufacturer: str = ""
    product: str = ""
    device_class: str = ""
    device_subclass: str = ""
    device_protocol: str = ""
    interfaces: list[str] = field(default_factory=list)
    num_interfaces: int = 0
    speed: str = ""
    authorized: bool = False
    sysfs_path: Path = field(default_factory=Path)
    dev_nodes: list[Path] = field(default_factory=list)
    
    @property
    def device_id(self) -> str:
        """Unique device identifier."""
        return f"{self.vendor_id}:{self.product_id}:{self.serial or 'no-serial'}"
    
    @property
    def is_composite(self) -> bool:
        """Check if device has multiple interface classes."""
        if len(self.interfaces) < 2:
            return False
        classes = set(iface.split(":")[0] if ":" in iface else iface[:2] 
                      for iface in self.interfaces)
        return len(classes) > 1
    
    def has_interface_class(self, class_code: str) -> bool:
        """Check if device has a specific interface class."""
        return any(iface.startswith(class_code) for iface in self.interfaces)
    
    @property
    def has_hid(self) -> bool:
        """Check if device has HID interface (keyboard/mouse)."""
        return self.has_interface_class("03")
    
    @property
    def has_storage(self) -> bool:
        """Check if device has mass storage interface."""
        return self.has_interface_class("08")
    
    @property
    def has_network(self) -> bool:
        """Check if device has network interface."""
        return self.has_interface_class("02") or self.has_interface_class("0a")


class DeviceAuthorization:
    """
    Manages USB device authorization via sysfs.
    
    Implements dual-barrier enforcement:
    1. Kernel authorization (sysfs authorized attribute)
    2. Filesystem permissions (chmod 000 on device nodes)
    """
    
    SYSFS_USB_BASE = Path("/sys/bus/usb/devices")
    DEV_BASE = Path("/dev")
    
    # USB interface class codes
    CLASS_HID = "03"
    CLASS_STORAGE = "08"
    CLASS_NETWORK_COMM = "02"  # CDC Communications
    CLASS_NETWORK_DATA = "0a"  # CDC Data
    CLASS_VENDOR = "ff"  # Vendor-specific
    
    def __init__(self):
        self._authorization_lock = asyncio.Lock()
    
    def get_device_info(self, bus_id: str) -> Optional[DeviceInfo]:
        """
        Extract device information from sysfs.
        
        Args:
            bus_id: USB bus ID (e.g., "1-2" or "usb1")
            
        Returns:
            DeviceInfo or None if device not found
        """
        sysfs_path = self.SYSFS_USB_BASE / bus_id
        
        if not sysfs_path.exists():
            logger.warning(f"Device {bus_id} not found in sysfs")
            return None
        
        info = DeviceInfo(
            bus_id=bus_id,
            sysfs_path=sysfs_path,
        )
        
        # Read basic attributes
        info.vendor_id = self._read_sysfs_attr(sysfs_path, "idVendor", "0000")
        info.product_id = self._read_sysfs_attr(sysfs_path, "idProduct", "0000")
        info.serial = self._read_sysfs_attr(sysfs_path, "serial", "")
        info.manufacturer = self._read_sysfs_attr(sysfs_path, "manufacturer", "")
        info.product = self._read_sysfs_attr(sysfs_path, "product", "")
        info.device_class = self._read_sysfs_attr(sysfs_path, "bDeviceClass", "00")
        info.device_subclass = self._read_sysfs_attr(sysfs_path, "bDeviceSubClass", "00")
        info.device_protocol = self._read_sysfs_attr(sysfs_path, "bDeviceProtocol", "00")
        info.num_interfaces = self._read_sysfs_int(sysfs_path, "bNumInterfaces", 0)
        info.speed = self._read_sysfs_attr(sysfs_path, "speed", "")
        info.authorized = self._read_sysfs_attr(sysfs_path, "authorized", "0") == "1"
        
        # Get interface classes
        info.interfaces = self._get_interface_classes(sysfs_path)
        
        # Find associated device nodes
        info.dev_nodes = self._find_device_nodes(bus_id)
        
        return info
    
    def _read_sysfs_attr(self, device_path: Path, attr: str, default: str = "") -> str:
        """Read a sysfs attribute file."""
        attr_path = device_path / attr
        try:
            if attr_path.exists():
                value = attr_path.read_text().strip()
                # Return default if value is empty (device may be deauthorized)
                return value if value else default
        except (PermissionError, OSError) as e:
            logger.debug(f"Cannot read {attr_path}: {e}")
        return default
    
    def _read_sysfs_int(self, device_path: Path, attr: str, default: int = 0) -> int:
        """Read a sysfs attribute file and convert to int."""
        value = self._read_sysfs_attr(device_path, attr, "")
        try:
            return int(value) if value else default
        except ValueError:
            return default
    
    def _get_interface_classes(self, device_path: Path) -> list[str]:
        """Get all interface classes for a device."""
        interfaces = []
        
        try:
            for child in device_path.iterdir():
                if not child.is_dir():
                    continue
                # Interface directories look like "1-2:1.0"
                if ":" not in child.name:
                    continue
                    
                iface_class = self._read_sysfs_attr(child, "bInterfaceClass", "")
                iface_subclass = self._read_sysfs_attr(child, "bInterfaceSubClass", "")
                iface_protocol = self._read_sysfs_attr(child, "bInterfaceProtocol", "")
                
                if iface_class:
                    interfaces.append(f"{iface_class}:{iface_subclass}:{iface_protocol}")
        except PermissionError:
            logger.warning(f"Permission denied accessing {device_path}")
            
        return interfaces
    
    def _find_device_nodes(self, bus_id: str) -> list[Path]:
        """Find /dev nodes associated with a USB device."""
        nodes = []
        
        # Check common device node patterns
        patterns = [
            ("sd*", self.DEV_BASE),  # Storage devices
            ("hidraw*", self.DEV_BASE),  # HID raw devices  
            ("event*", self.DEV_BASE / "input"),  # Input events
            ("usb*", self.DEV_BASE / "bus" / "usb"),  # USB bus nodes
        ]
        
        sysfs_path = self.SYSFS_USB_BASE / bus_id
        
        for pattern, base_path in patterns:
            if not base_path.exists():
                continue
            try:
                for node in base_path.glob(pattern):
                    # Check if this node is associated with our device
                    # by looking at its sysfs link
                    uevent_path = Path(f"/sys/class/block/{node.name}/device") if "sd" in pattern else None
                    if uevent_path and uevent_path.exists():
                        try:
                            real_path = uevent_path.resolve()
                            if bus_id in str(real_path):
                                nodes.append(node)
                        except OSError:
                            pass
            except PermissionError:
                pass
                
        return nodes
    
    async def authorize(self, bus_id: str) -> bool:
        """
        Authorize a USB device.
        
        Args:
            bus_id: USB bus ID (e.g., "1-2")
            
        Returns:
            True if authorization succeeded
        """
        async with self._authorization_lock:
            auth_path = self.SYSFS_USB_BASE / bus_id / "authorized"
            
            try:
                if not auth_path.exists():
                    logger.error(f"Authorization path not found: {auth_path}")
                    return False
                
                auth_path.write_text("1")
                logger.info(f"Authorized device {bus_id}")
                
                # Give the kernel time to enumerate interfaces
                await asyncio.sleep(0.5)
                
                # Trigger driver binding for the device interfaces
                await self._bind_drivers(bus_id)
                
                # Restore device node permissions after authorization
                info = self.get_device_info(bus_id)
                if info:
                    await self._restore_device_node_permissions(info)
                
                return True
                
            except PermissionError:
                logger.error(f"Permission denied authorizing {bus_id}")
                return False
            except OSError as e:
                logger.error(f"Failed to authorize {bus_id}: {e}")
                return False
    
    async def _bind_drivers(self, bus_id: str) -> None:
        """
        Trigger driver binding for device interfaces after authorization.
        
        This is needed because when a device is authorized, the kernel
        enumerates interfaces but doesn't automatically bind drivers.
        """
        import subprocess
        
        try:
            # Find all interfaces for this device
            device_path = self.SYSFS_USB_BASE / bus_id
            for child in device_path.iterdir():
                if not child.is_dir() or ":" not in child.name:
                    continue
                    
                interface_id = child.name  # e.g., "1-6:1.0"
                
                # Check interface class
                iface_class = self._read_sysfs_attr(child, "bInterfaceClass", "")
                
                # Bind appropriate driver based on interface class
                if iface_class == "03":  # HID
                    await self._try_bind_driver(interface_id, "usbhid")
                elif iface_class == "08":  # Mass storage
                    await self._try_bind_driver(interface_id, "usb-storage")
                elif iface_class in ("02", "0a"):  # CDC (network)
                    await self._try_bind_driver(interface_id, "cdc_ether")
                    
            # Also trigger udevadm to apply any udev rules
            subprocess.run(
                ["udevadm", "trigger", "--subsystem-match=usb", 
                 "--attr-match=busnum=" + bus_id.split("-")[0]],
                capture_output=True,
                timeout=5
            )
            
        except Exception as e:
            logger.warning(f"Error binding drivers for {bus_id}: {e}")
    
    async def _try_bind_driver(self, interface_id: str, driver_name: str) -> None:
        """Try to bind a driver to an interface."""
        bind_path = Path(f"/sys/bus/usb/drivers/{driver_name}/bind")
        
        try:
            if bind_path.exists():
                bind_path.write_text(interface_id)
                logger.debug(f"Bound {driver_name} to {interface_id}")
        except OSError as e:
            # Driver might already be bound or interface not compatible
            if "No such device" not in str(e) and "busy" not in str(e).lower():
                logger.debug(f"Could not bind {driver_name} to {interface_id}: {e}")
    
    async def deauthorize(self, bus_id: str) -> bool:
        """
        Deauthorize a USB device (dual-barrier enforcement).
        
        Args:
            bus_id: USB bus ID (e.g., "1-2")
            
        Returns:
            True if deauthorization succeeded
        """
        async with self._authorization_lock:
            # Get device info first (before deauthorization)
            info = self.get_device_info(bus_id)
            
            # Layer 1: Kernel authorization
            auth_path = self.SYSFS_USB_BASE / bus_id / "authorized"
            
            try:
                if auth_path.exists():
                    auth_path.write_text("0")
                    logger.info(f"Deauthorized device {bus_id}")
            except (PermissionError, OSError) as e:
                logger.error(f"Failed to deauthorize {bus_id}: {e}")
                return False
            
            # Layer 2: Device node permissions
            if info:
                await self._quarantine_device_nodes(info)
            
            return True
    
    async def _quarantine_device_nodes(self, info: DeviceInfo) -> None:
        """
        Apply chmod 000 to all device nodes (Layer 2 enforcement).
        """
        for node in info.dev_nodes:
            try:
                if node.exists():
                    os.chmod(node, 0o000)
                    logger.debug(f"Quarantined device node: {node}")
            except (PermissionError, OSError) as e:
                logger.warning(f"Cannot quarantine {node}: {e}")
    
    async def _restore_device_node_permissions(self, info: DeviceInfo) -> None:
        """
        Restore normal permissions to device nodes after authorization.
        """
        for node in info.dev_nodes:
            try:
                if node.exists():
                    # Default permissions: owner read/write, group read
                    os.chmod(node, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
                    logger.debug(f"Restored permissions for: {node}")
            except (PermissionError, OSError) as e:
                logger.warning(f"Cannot restore permissions for {node}: {e}")
    
    def set_hub_defaults(self) -> int:
        """
        Set authorized_default=0 on all USB hubs.
        
        This is the earliest intervention point to prevent
        automatic device authorization.
        
        Returns:
            Number of hubs configured
        """
        count = 0
        
        for hub_path in self.SYSFS_USB_BASE.glob("usb*"):
            auth_default = hub_path / "authorized_default"
            try:
                if auth_default.exists():
                    auth_default.write_text("0")
                    logger.info(f"Set authorized_default=0 on {hub_path.name}")
                    count += 1
            except (PermissionError, OSError) as e:
                logger.error(f"Cannot set authorized_default on {hub_path.name}: {e}")
                
        return count
    
    def get_all_devices(self) -> list[DeviceInfo]:
        """Get information for all connected USB devices."""
        devices = []
        
        for device_path in self.SYSFS_USB_BASE.iterdir():
            if not device_path.is_dir():
                continue
            # Skip hub entries (usb1, usb2, etc.)
            if device_path.name.startswith("usb"):
                continue
            # Skip interface entries (contain ":")
            if ":" in device_path.name:
                continue
                
            info = self.get_device_info(device_path.name)
            if info:
                devices.append(info)
                
        return devices
