"""
Temporal Pattern Analysis Module

Analyzes USB device behavior patterns over time to detect
anomalous activity that might indicate an attack.
"""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from wru.core.authorization import DeviceInfo

logger = logging.getLogger(__name__)


@dataclass
class DeviceEvent:
    """A single device activity event."""
    timestamp: float
    event_type: str  # "connect", "disconnect", "authorize", "data_transfer"
    details: dict = field(default_factory=dict)


@dataclass
class PatternAnalysis:
    """Results from pattern analysis."""
    is_anomalous: bool
    anomaly_score: int
    patterns_detected: list[str]
    details: dict = field(default_factory=dict)


class PatternAnalyzer:
    """
    Analyzes temporal patterns in USB device behavior.
    
    Detects:
    - Rapid connect/disconnect cycles (enumeration fuzzing)
    - Coordinated multi-device activity
    - Time-based attack patterns (delayed enumeration)
    - Unusual timing patterns
    """
    
    # Configuration defaults
    RAPID_CYCLE_THRESHOLD = 3  # events in window
    RAPID_CYCLE_WINDOW = 60.0  # seconds
    DELAYED_ENUM_THRESHOLD = 5.0  # seconds
    MULTI_DEVICE_WINDOW = 2.0  # seconds between device connections
    
    def __init__(self):
        # Track events per device
        self._device_events: dict[str, list[DeviceEvent]] = defaultdict(list)
        
        # Track global events for correlation
        self._global_events: list[DeviceEvent] = []
        
        # Track known descriptors for mutation detection
        self._device_descriptors: dict[str, list[tuple[float, str]]] = defaultdict(list)
    
    def record_event(
        self,
        device: DeviceInfo,
        event_type: str,
        details: Optional[dict] = None
    ) -> None:
        """Record a device event for pattern analysis."""
        event = DeviceEvent(
            timestamp=time.time(),
            event_type=event_type,
            details=details or {}
        )
        
        self._device_events[device.device_id].append(event)
        self._global_events.append(event)
        
        # Limit history size
        self._cleanup_old_events()
    
    def record_descriptors(self, device: DeviceInfo, descriptors: str) -> None:
        """Record device descriptors for mutation tracking."""
        self._device_descriptors[device.device_id].append(
            (time.time(), descriptors)
        )
        
        # Limit history
        if len(self._device_descriptors[device.device_id]) > 20:
            self._device_descriptors[device.device_id] = \
                self._device_descriptors[device.device_id][-20:]
    
    def analyze(self, device: DeviceInfo) -> PatternAnalysis:
        """
        Analyze patterns for a specific device.
        
        Returns anomaly assessment with detected patterns.
        """
        patterns = []
        total_score = 0
        details = {}
        
        device_id = device.device_id
        events = self._device_events.get(device_id, [])
        
        # Check rapid connect/disconnect cycles
        rapid_result = self._check_rapid_cycles(events)
        if rapid_result:
            patterns.append("rapid_cycles")
            total_score += rapid_result["score"]
            details["rapid_cycles"] = rapid_result
        
        # Check delayed enumeration
        delayed_result = self._check_delayed_enumeration(events)
        if delayed_result:
            patterns.append("delayed_enumeration")
            total_score += delayed_result["score"]
            details["delayed_enumeration"] = delayed_result
        
        # Check descriptor mutations
        mutation_result = self._check_descriptor_mutations(device_id)
        if mutation_result:
            patterns.append("descriptor_mutation")
            total_score += mutation_result["score"]
            details["descriptor_mutation"] = mutation_result
        
        # Check coordinated multi-device activity
        multi_result = self._check_multi_device_correlation(device_id)
        if multi_result:
            patterns.append("coordinated_activity")
            total_score += multi_result["score"]
            details["coordinated_activity"] = multi_result
        
        return PatternAnalysis(
            is_anomalous=len(patterns) > 0,
            anomaly_score=total_score,
            patterns_detected=patterns,
            details=details
        )
    
    def _check_rapid_cycles(self, events: list[DeviceEvent]) -> Optional[dict]:
        """Check for rapid connect/disconnect cycles."""
        now = time.time()
        
        # Filter to connect events in window
        recent_connects = [
            e for e in events
            if e.event_type == "connect"
            and now - e.timestamp < self.RAPID_CYCLE_WINDOW
        ]
        
        if len(recent_connects) >= self.RAPID_CYCLE_THRESHOLD:
            return {
                "score": 25,
                "count": len(recent_connects),
                "window_seconds": self.RAPID_CYCLE_WINDOW,
                "reason": f"Device connected {len(recent_connects)} times in {self.RAPID_CYCLE_WINDOW}s"
            }
        
        return None
    
    def _check_delayed_enumeration(self, events: list[DeviceEvent]) -> Optional[dict]:
        """
        Check for delayed enumeration pattern.
        
        Some attack devices delay full enumeration to evade detection.
        """
        connect_events = [e for e in events if e.event_type == "connect"]
        auth_events = [e for e in events if e.event_type == "authorize"]
        
        if not connect_events or not auth_events:
            return None
        
        # Check time between last connect and any auth attempt
        last_connect = connect_events[-1]
        
        for auth in auth_events:
            if auth.timestamp > last_connect.timestamp:
                delay = auth.timestamp - last_connect.timestamp
                
                if delay > self.DELAYED_ENUM_THRESHOLD:
                    return {
                        "score": 15,
                        "delay_seconds": delay,
                        "reason": f"Delayed enumeration: {delay:.1f}s between connect and authorize"
                    }
        
        return None
    
    def _check_descriptor_mutations(self, device_id: str) -> Optional[dict]:
        """Check for descriptor changes over time."""
        history = self._device_descriptors.get(device_id, [])
        
        if len(history) < 2:
            return None
        
        # Compare consecutive descriptors
        mutations = 0
        for i in range(1, len(history)):
            if history[i][1] != history[i-1][1]:
                mutations += 1
        
        if mutations > 0:
            return {
                "score": 45,
                "mutation_count": mutations,
                "history_length": len(history),
                "reason": f"Descriptor mutated {mutations} time(s)"
            }
        
        return None
    
    def _check_multi_device_correlation(self, device_id: str) -> Optional[dict]:
        """
        Check for coordinated multi-device activity.
        
        Multiple devices connecting in rapid succession could indicate
        a coordinated attack.
        """
        now = time.time()
        
        # Get recent connect events for all devices
        recent_global = [
            e for e in self._global_events
            if e.event_type == "connect"
            and now - e.timestamp < self.MULTI_DEVICE_WINDOW * 5  # 10 second window
        ]
        
        if len(recent_global) < 2:
            return None
        
        # Check for multiple different devices connecting together
        timestamps = sorted([e.timestamp for e in recent_global])
        
        # Count devices within tight window
        clusters = []
        current_cluster = [timestamps[0]]
        
        for i in range(1, len(timestamps)):
            if timestamps[i] - timestamps[i-1] < self.MULTI_DEVICE_WINDOW:
                current_cluster.append(timestamps[i])
            else:
                if len(current_cluster) >= 2:
                    clusters.append(current_cluster)
                current_cluster = [timestamps[i]]
        
        if len(current_cluster) >= 2:
            clusters.append(current_cluster)
        
        if clusters:
            max_cluster = max(len(c) for c in clusters)
            if max_cluster >= 2:
                return {
                    "score": 20,
                    "cluster_count": len(clusters),
                    "max_cluster_size": max_cluster,
                    "reason": f"Coordinated activity: {max_cluster} devices within {self.MULTI_DEVICE_WINDOW}s"
                }
        
        return None
    
    def _cleanup_old_events(self, max_age: float = 300.0) -> None:
        """Remove events older than max_age seconds."""
        now = time.time()
        cutoff = now - max_age
        
        # Clean device events
        for device_id in list(self._device_events.keys()):
            self._device_events[device_id] = [
                e for e in self._device_events[device_id]
                if e.timestamp > cutoff
            ]
            if not self._device_events[device_id]:
                del self._device_events[device_id]
        
        # Clean global events
        self._global_events = [
            e for e in self._global_events
            if e.timestamp > cutoff
        ]
    
    def clear_device(self, device_id: str) -> None:
        """Clear all tracking data for a device."""
        self._device_events.pop(device_id, None)
        self._device_descriptors.pop(device_id, None)
    
    def clear_all(self) -> None:
        """Clear all tracking data."""
        self._device_events.clear()
        self._global_events.clear()
        self._device_descriptors.clear()
