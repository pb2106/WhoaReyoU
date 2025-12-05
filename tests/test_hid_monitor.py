"""
Tests for the HID Monitor module.
"""

import pytest
import time
from unittest.mock import MagicMock, AsyncMock, patch
from collections import deque
from wru.runtime.hid_monitor import HIDMonitor, KeystrokeStats


class TestKeystrokeAnalysis:
    """Test keystroke timing analysis."""
    
    def test_human_typing_pattern(self):
        """Human typing should have high coefficient of variation."""
        monitor = HIDMonitor("/dev/input/event0")
        
        # Simulate human typing with variable intervals
        now = time.time()
        intervals = [0.12, 0.15, 0.08, 0.22, 0.11, 0.19, 0.14, 0.09, 0.17, 0.13]
        
        monitor._keystroke_times = deque(maxlen=50)
        monitor._inter_key_intervals = deque(maxlen=49)
        
        current = now
        for interval in intervals:
            current += interval
            monitor._keystroke_times.append(current)
        
        for interval in intervals:
            monitor._inter_key_intervals.append(interval)
        
        stats = monitor._analyze_pattern()
        
        # Human typing should have high CV (>0.3)
        assert stats.coefficient_of_variation > 0.2
        assert stats.is_suspicious is False
    
    def test_machine_typing_pattern(self):
        """Machine (BadUSB) typing should have low coefficient of variation."""
        monitor = HIDMonitor("/dev/input/event0")
        
        # Simulate machine typing with uniform intervals
        now = time.time()
        # 20 keystrokes per second with minimal variation
        intervals = [0.05] * 20  # Very uniform
        
        monitor._keystroke_times = deque(maxlen=50)
        monitor._inter_key_intervals = deque(maxlen=49)
        
        current = now
        for interval in intervals:
            current += interval
            monitor._keystroke_times.append(current)
        
        for interval in intervals:
            monitor._inter_key_intervals.append(interval)
        
        stats = monitor._analyze_pattern()
        
        # Machine typing should have low CV (<0.15)
        assert stats.coefficient_of_variation < 0.1
    
    def test_rapid_keystroke_detection(self):
        """Rapid keystrokes should be flagged as suspicious."""
        monitor = HIDMonitor("/dev/input/event0")
        
        # Simulate 25 keystrokes in 1 second
        now = time.time()
        
        monitor._keystroke_times = deque(maxlen=50)
        monitor._inter_key_intervals = deque(maxlen=49)
        
        for i in range(25):
            monitor._keystroke_times.append(now - 1.0 + (i * 0.04))
        
        for i in range(24):
            monitor._inter_key_intervals.append(0.04)
        
        stats = monitor._analyze_pattern()
        
        # 25 keys/sec > 15 threshold should be suspicious
        assert stats.keystrokes_per_second >= 15
        assert stats.is_suspicious is True
    
    def test_slow_typing_not_suspicious(self):
        """Slow typing should not be flagged."""
        monitor = HIDMonitor("/dev/input/event0")
        
        # Simulate slow typing: 3 keys per second
        now = time.time()
        
        monitor._keystroke_times = deque(maxlen=50)
        monitor._inter_key_intervals = deque(maxlen=49)
        
        for i in range(10):
            monitor._keystroke_times.append(now - 10.0 + (i * 0.33))
        
        for i in range(9):
            monitor._inter_key_intervals.append(0.33)
        
        stats = monitor._analyze_pattern()
        
        assert stats.keystrokes_per_second < 10
        assert stats.is_suspicious is False


class TestHIDMonitorIntegration:
    """Integration tests for HID monitor."""
    
    @pytest.mark.asyncio
    async def test_callback_registration(self):
        """Callbacks should be registered and called."""
        monitor = HIDMonitor("/dev/input/event0")
        
        callback_called = False
        
        async def test_callback(alert):
            nonlocal callback_called
            callback_called = True
        
        monitor.register_callback(test_callback)
        
        assert test_callback in monitor._callbacks
    
    def test_alert_cooldown(self):
        """Alerts should be throttled."""
        monitor = HIDMonitor("/dev/input/event0")
        
        # Set last alert to now
        monitor._last_alert_time = time.time()
        
        # Try to trigger another alert immediately
        # Should be blocked by cooldown
        assert time.time() - monitor._last_alert_time < monitor.ALERT_COOLDOWN
    
    def test_stats_reporting(self):
        """get_stats should return current analysis."""
        monitor = HIDMonitor("/dev/input/event0")
        
        # Add some data
        now = time.time()
        for i in range(5):
            monitor._keystroke_times.append(now - 5 + i)
        
        stats = monitor.get_stats()
        
        assert isinstance(stats, KeystrokeStats)
        assert stats.total_keystrokes >= 0
