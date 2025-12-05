"""
HID Runtime Monitor

Continuously monitors HID (keyboard/mouse) devices for suspicious
activity patterns that indicate BadUSB keystroke injection.

Uses statistical analysis of keystroke timing to distinguish
human typing from automated injection.
"""

import asyncio
import logging
import time
import subprocess
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable, Awaitable
from statistics import mean, stdev

logger = logging.getLogger(__name__)


@dataclass
class KeystrokeStats:
    """Statistics about keystroke patterns."""
    total_keystrokes: int = 0
    keystrokes_per_second: float = 0.0
    coefficient_of_variation: float = 0.0  # CV < 0.1 = machine, CV > 0.3 = human
    is_suspicious: bool = False
    suspicious_reason: str = ""


@dataclass 
class HIDAlert:
    """Alert from HID monitor."""
    device_path: str
    alert_type: str  # "rapid_injection", "automated_timing", "suspicious_pattern"
    keystroke_rate: float
    coefficient_of_variation: float
    timestamp: float = field(default_factory=time.time)
    details: dict = field(default_factory=dict)


# Type for alert callbacks
AlertCallback = Callable[[HIDAlert], Awaitable[None]]


class HIDMonitor:
    """
    Monitors HID input devices for BadUSB attacks.
    
    Detection methods:
    1. Keystroke rate analysis (humans: 3-8 keys/s, machines: 10-50+ keys/s)
    2. Timing variance (humans: high variance, machines: uniform)
    3. Statistical coefficient of variation (CV < 0.1 = automated)
    
    When attack detected:
    - Immediately lock screen
    - Deauthorize device
    - Alert security team
    """
    
    # Thresholds
    HUMAN_MAX_RATE = 10.0  # keys per second
    MACHINE_MIN_RATE = 15.0  # keys per second 
    HUMAN_MIN_CV = 0.3  # Coefficient of variation
    MACHINE_MAX_CV = 0.15  # Coefficient of variation
    
    WINDOW_SIZE = 50  # Number of keystrokes to analyze
    ALERT_COOLDOWN = 5.0  # Seconds between alerts
    
    def __init__(self, device_path: str):
        """
        Initialize HID monitor for a device.
        
        Args:
            device_path: Path to input device (e.g., /dev/input/event5)
        """
        self._device_path = device_path
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._callbacks: list[AlertCallback] = []
        
        # Keystroke timing tracking
        self._keystroke_times: deque[float] = deque(maxlen=self.WINDOW_SIZE)
        self._inter_key_intervals: deque[float] = deque(maxlen=self.WINDOW_SIZE - 1)
        
        # Alert throttling
        self._last_alert_time = 0.0
    
    def register_callback(self, callback: AlertCallback) -> None:
        """Register alert callback."""
        self._callbacks.append(callback)
    
    async def start(self) -> None:
        """Start monitoring the HID device."""
        if self._running:
            return
            
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        logger.info(f"HID monitor started for {self._device_path}")
    
    async def stop(self) -> None:
        """Stop monitoring."""
        self._running = False
        
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
            
        logger.info(f"HID monitor stopped for {self._device_path}")
    
    async def _monitor_loop(self) -> None:
        """Main monitoring loop using evdev."""
        try:
            from evdev import InputDevice, ecodes, categorize
        except ImportError:
            logger.error("evdev not installed, HID monitoring disabled")
            return
        
        try:
            device = InputDevice(self._device_path)
            logger.info(f"Monitoring HID device: {device.name}")
            
            async for event in device.async_read_loop():
                if not self._running:
                    break
                    
                # Only process keypress events (not key release)
                if event.type == ecodes.EV_KEY and event.value == 1:
                    await self._process_keystroke(event.timestamp())
                    
        except PermissionError:
            logger.error(f"Permission denied reading {self._device_path}")
        except FileNotFoundError:
            logger.error(f"Device not found: {self._device_path}")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"HID monitor error: {e}", exc_info=True)
    
    async def _process_keystroke(self, timestamp: float) -> None:
        """Process a single keystroke event."""
        now = timestamp
        
        # Calculate inter-key interval
        if self._keystroke_times:
            interval = now - self._keystroke_times[-1]
            self._inter_key_intervals.append(interval)
        
        self._keystroke_times.append(now)
        
        # Need enough data for analysis
        if len(self._keystroke_times) < 10:
            return
        
        # Analyze current pattern
        stats = self._analyze_pattern()
        
        if stats.is_suspicious:
            await self._trigger_alert(stats)
    
    def _analyze_pattern(self) -> KeystrokeStats:
        """Analyze current keystroke pattern."""
        stats = KeystrokeStats()
        
        if len(self._keystroke_times) < 2:
            return stats
        
        # Calculate keystroke rate over last second
        now = self._keystroke_times[-1]
        recent = [t for t in self._keystroke_times if now - t <= 1.0]
        stats.total_keystrokes = len(recent)
        stats.keystrokes_per_second = len(recent)
        
        # Calculate coefficient of variation for inter-key intervals
        if len(self._inter_key_intervals) >= 5:
            intervals = list(self._inter_key_intervals)
            
            try:
                mean_interval = mean(intervals)
                if mean_interval > 0:
                    std_interval = stdev(intervals) if len(intervals) > 1 else 0
                    stats.coefficient_of_variation = std_interval / mean_interval
            except Exception:
                pass
        
        # Check for suspicious patterns
        
        # 1. High keystroke rate
        if stats.keystrokes_per_second > self.MACHINE_MIN_RATE:
            stats.is_suspicious = True
            stats.suspicious_reason = (
                f"Rapid keystrokes: {stats.keystrokes_per_second:.1f}/s "
                f"(threshold: {self.MACHINE_MIN_RATE})"
            )
        
        # 2. Low timing variance (machine-like)
        elif stats.coefficient_of_variation < self.MACHINE_MAX_CV and len(self._inter_key_intervals) >= 10:
            stats.is_suspicious = True
            stats.suspicious_reason = (
                f"Automated timing pattern: CV={stats.coefficient_of_variation:.3f} "
                f"(human threshold: >{self.HUMAN_MIN_CV})"
            )
        
        return stats
    
    async def _trigger_alert(self, stats: KeystrokeStats) -> None:
        """Trigger BadUSB alert."""
        now = time.time()
        
        # Throttle alerts
        if now - self._last_alert_time < self.ALERT_COOLDOWN:
            return
            
        self._last_alert_time = now
        
        alert = HIDAlert(
            device_path=self._device_path,
            alert_type="badusb_detected",
            keystroke_rate=stats.keystrokes_per_second,
            coefficient_of_variation=stats.coefficient_of_variation,
            details={"reason": stats.suspicious_reason}
        )
        
        logger.critical(
            f"BadUSB ATTACK DETECTED on {self._device_path}: "
            f"{stats.suspicious_reason}"
        )
        
        # Trigger immediate response
        await self._emergency_response()
        
        # Notify callbacks
        for callback in self._callbacks:
            try:
                await callback(alert)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")
    
    async def _emergency_response(self) -> None:
        """
        Emergency response to detected attack.
        
        1. Lock screen immediately
        2. Alert will trigger device deauthorization via callback
        """
        # Lock screen using loginctl
        try:
            subprocess.run(
                ["loginctl", "lock-sessions"],
                check=False,
                capture_output=True,
                timeout=2
            )
            logger.info("Screen locked due to BadUSB detection")
        except Exception as e:
            logger.error(f"Failed to lock screen: {e}")
            
            # Try alternative methods
            try:
                # Try gnome-screensaver
                subprocess.run(
                    ["gnome-screensaver-command", "-l"],
                    check=False,
                    capture_output=True,
                    timeout=2
                )
            except Exception:
                pass
    
    def get_stats(self) -> KeystrokeStats:
        """Get current keystroke statistics."""
        return self._analyze_pattern()


class HIDMonitorManager:
    """
    Manages HID monitors for multiple devices.
    """
    
    def __init__(self):
        self._monitors: dict[str, HIDMonitor] = {}
    
    async def start_monitor(
        self,
        device_path: str,
        callback: Optional[AlertCallback] = None
    ) -> HIDMonitor:
        """Start monitoring a HID device."""
        if device_path in self._monitors:
            return self._monitors[device_path]
        
        monitor = HIDMonitor(device_path)
        
        if callback:
            monitor.register_callback(callback)
        
        await monitor.start()
        self._monitors[device_path] = monitor
        
        return monitor
    
    async def stop_monitor(self, device_path: str) -> None:
        """Stop monitoring a device."""
        monitor = self._monitors.pop(device_path, None)
        if monitor:
            await monitor.stop()
    
    async def stop_all(self) -> None:
        """Stop all monitors."""
        for monitor in self._monitors.values():
            await monitor.stop()
        self._monitors.clear()
    
    def get_monitor(self, device_path: str) -> Optional[HIDMonitor]:
        """Get monitor for a device."""
        return self._monitors.get(device_path)
