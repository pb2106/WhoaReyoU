"""
USB Event Handler Module

Handles pyudev events for USB device add/remove/change operations.
Implements async processing pipeline for real-time event handling.
"""

import asyncio
import logging
from typing import Optional, Callable, Awaitable
from dataclasses import dataclass
from enum import Enum, auto

import pyudev

from wru.core.authorization import DeviceAuthorization, DeviceInfo

logger = logging.getLogger(__name__)


class DeviceAction(Enum):
    """USB device event actions."""
    ADD = auto()
    REMOVE = auto()
    CHANGE = auto()
    BIND = auto()
    UNBIND = auto()


@dataclass
class USBEvent:
    """Represents a USB device event."""
    action: DeviceAction
    device_path: str
    bus_id: str
    subsystem: str
    device_type: Optional[str]
    vendor_id: Optional[str]
    product_id: Optional[str]
    serial: Optional[str]
    raw_device: pyudev.Device
    
    @classmethod
    def from_pyudev(cls, device: pyudev.Device, action: str) -> "USBEvent":
        """Create USBEvent from pyudev device."""
        try:
            action_enum = DeviceAction[action.upper()]
        except KeyError:
            action_enum = DeviceAction.CHANGE
            
        # Extract bus ID from device path
        # e.g., /sys/devices/pci0000:00/0000:00:14.0/usb1/1-2 -> 1-2
        bus_id = ""
        devpath = device.get("DEVPATH", "")
        if "/usb" in devpath:
            parts = devpath.split("/")
            for i, part in enumerate(parts):
                if part.startswith("usb"):
                    # Next part after hub is the device
                    if i + 1 < len(parts):
                        bus_id = parts[i + 1]
                        # If it's an interface, get the parent device
                        if ":" in bus_id and i + 1 < len(parts):
                            bus_id = bus_id.split(":")[0]
                    break
        
        return cls(
            action=action_enum,
            device_path=devpath,
            bus_id=bus_id,
            subsystem=device.subsystem or "",
            device_type=device.get("DEVTYPE"),
            vendor_id=device.get("ID_VENDOR_ID"),
            product_id=device.get("ID_MODEL_ID"),
            serial=device.get("ID_SERIAL_SHORT"),
            raw_device=device,
        )


# Type for event callbacks
EventCallback = Callable[[USBEvent, Optional[DeviceInfo]], Awaitable[None]]


class USBEventHandler:
    """
    Handles USB device events from udev.
    
    Monitors the USB subsystem and dispatches events to registered callbacks.
    Implements immediate deauthorization on device add events.
    """
    
    def __init__(self, authorization: DeviceAuthorization):
        self._authorization = authorization
        self._context = pyudev.Context()
        self._monitor: Optional[pyudev.Monitor] = None
        self._observer: Optional[pyudev.MonitorObserver] = None
        self._callbacks: list[EventCallback] = []
        self._event_queue: asyncio.Queue[USBEvent] = asyncio.Queue()
        self._running = False
        self._processor_task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
    
    def register_callback(self, callback: EventCallback) -> None:
        """Register an async callback for USB events."""
        self._callbacks.append(callback)
        logger.debug(f"Registered callback: {callback.__name__}")
    
    def unregister_callback(self, callback: EventCallback) -> None:
        """Unregister a callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)
            logger.debug(f"Unregistered callback: {callback.__name__}")
    
    async def start(self) -> None:
        """Start monitoring USB events."""
        if self._running:
            logger.warning("Event handler already running")
            return
            
        self._running = True
        self._loop = asyncio.get_running_loop()
        
        # Create udev monitor
        self._monitor = pyudev.Monitor.from_netlink(self._context)
        self._monitor.filter_by(subsystem="usb")
        
        # Start async event processor
        self._processor_task = asyncio.create_task(self._process_events())
        
        # Create observer with threadsafe callback
        self._observer = pyudev.MonitorObserver(
            self._monitor,
            callback=self._on_device_event,
            name="wru-udev-observer"
        )
        self._observer.start()
        
        logger.info("USB event handler started")
    
    async def stop(self) -> None:
        """Stop monitoring USB events."""
        self._running = False
        
        if self._observer:
            self._observer.stop()
            self._observer = None
            
        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass
            self._processor_task = None
            
        self._monitor = None
        logger.info("USB event handler stopped")
    
    def _on_device_event(self, device: pyudev.Device) -> None:
        """
        Callback from pyudev observer (runs in separate thread).
        
        Creates event and schedules it for async processing.
        """
        action = device.action
        if not action:
            return
            
        try:
            event = USBEvent.from_pyudev(device, action)
            
            # Schedule event for async processing
            if self._loop and self._running:
                self._loop.call_soon_threadsafe(
                    self._event_queue.put_nowait,
                    event
                )
        except Exception as e:
            logger.error(f"Error creating USB event: {e}")
    
    async def _process_events(self) -> None:
        """Async event processor loop."""
        while self._running:
            try:
                # Wait for events with timeout to allow shutdown
                try:
                    event = await asyncio.wait_for(
                        self._event_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                await self._handle_event(event)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing event: {e}", exc_info=True)
    
    async def _handle_event(self, event: USBEvent) -> None:
        """
        Handle a single USB event.
        
        Implements immediate deauthorization on ADD events.
        """
        logger.info(
            f"USB event: {event.action.name} - {event.bus_id} "
            f"({event.vendor_id or '?'}:{event.product_id or '?'})"
        )
        
        # Skip non-device events (interfaces, etc.)
        if not event.bus_id or event.device_type != "usb_device":
            logger.debug(f"Skipping non-device event: {event.device_path}")
            return
        
        # Get device info from sysfs
        device_info = self._authorization.get_device_info(event.bus_id)
        
        # CRITICAL: Immediately deauthorize new devices
        if event.action == DeviceAction.ADD:
            logger.info(f"New device detected, applying immediate deauthorization: {event.bus_id}")
            await self._authorization.deauthorize(event.bus_id)
        
        # Dispatch to registered callbacks
        for callback in self._callbacks:
            try:
                await callback(event, device_info)
            except Exception as e:
                logger.error(f"Callback {callback.__name__} failed: {e}", exc_info=True)
    
    def get_current_devices(self) -> list[pyudev.Device]:
        """Get list of currently connected USB devices."""
        devices = []
        for device in self._context.list_devices(subsystem="usb"):
            if device.get("DEVTYPE") == "usb_device":
                devices.append(device)
        return devices
