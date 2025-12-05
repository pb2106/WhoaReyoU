"""
Threat Scoring Heuristics Module

Implements individual scoring functions for USB device threat indicators.
Each heuristic evaluates a specific risk factor and returns a score.
"""

import logging
import re
from dataclasses import dataclass
from typing import Optional
from collections import defaultdict
import time

from wru.core.authorization import DeviceInfo

logger = logging.getLogger(__name__)


@dataclass
class HeuristicResult:
    """Result from a heuristic evaluation."""
    score: int
    reason: str
    indicator: str
    details: Optional[dict] = None


class HeuristicScorer:
    """
    Evaluates USB devices against threat heuristics.
    
    Each heuristic returns a score and reason that contribute
    to the overall threat assessment.
    """
    
    # Default score weights (configurable via threat-rules.yaml)
    DEFAULT_WEIGHTS = {
        "hid_storage_composite": 50,
        "hid_network_composite": 40,
        "missing_serial": 30,
        "vendor_specific_interface": 25,
        "multiple_interfaces": 20,
        "high_risk_vendor": 35,
        "unknown_manufacturer": 15,
        "rapid_replug": 25,
        "descriptor_mutation": 45,
        "cve_match": 60,
    }
    
    # High-risk vendor IDs (development boards, attack tools)
    HIGH_RISK_VENDORS = {
        "1234",  # Generic test VID
        "16c0",  # Teensy/PJRC (used in attack tools)
        "2341",  # Arduino (common in DIY attacks)
        "0483",  # STMicroelectronics (used in BadUSB)
        "1d50",  # OpenMoko (development)
        "03eb",  # Atmel (programmable chips)
        "1fc9",  # NXP (LPC microcontrollers)
        "0403",  # FTDI (can be abused)
    }
    
    # Known generic/suspicious serial patterns
    GENERIC_SERIAL_PATTERNS = [
        r"^0+$",  # All zeros
        r"^1+$",  # All ones
        r"^[0-9a-f]{4}$",  # Too short (4 chars)
        r"^000000",  # Starts with zeros
        r"^[A-Z]$",  # Single letter
        r"^(.)\\1+$",  # All same character
    ]
    
    def __init__(self, weights: Optional[dict[str, int]] = None):
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()
        self._replug_tracker: dict[str, list[float]] = defaultdict(list)
        self._descriptor_history: dict[str, list[str]] = defaultdict(list)
    
    def evaluate_all(self, device: DeviceInfo) -> list[HeuristicResult]:
        """
        Evaluate device against all heuristics.
        
        Returns list of HeuristicResult for triggered heuristics.
        """
        results = []
        
        # Check each heuristic
        heuristics = [
            self._check_hid_storage_composite,
            self._check_hid_network_composite,
            self._check_missing_serial,
            self._check_vendor_specific_interface,
            self._check_multiple_interfaces,
            self._check_high_risk_vendor,
            self._check_unknown_manufacturer,
            self._check_rapid_replug,
        ]
        
        for heuristic in heuristics:
            try:
                result = heuristic(device)
                if result and result.score > 0:
                    results.append(result)
            except Exception as e:
                logger.error(f"Heuristic {heuristic.__name__} failed: {e}")
        
        return results
    
    def _check_hid_storage_composite(self, device: DeviceInfo) -> Optional[HeuristicResult]:
        """
        Check for HID + Storage composite device.
        
        This is the classic BadUSB signature - a device that presents
        both as a keyboard and a storage device.
        """
        if device.has_hid and device.has_storage:
            return HeuristicResult(
                score=self.weights["hid_storage_composite"],
                reason="Composite HID+Storage device (BadUSB signature)",
                indicator="hid_storage_composite",
                details={
                    "hid_interfaces": [i for i in device.interfaces if i.startswith("03")],
                    "storage_interfaces": [i for i in device.interfaces if i.startswith("08")],
                }
            )
        return None
    
    def _check_hid_network_composite(self, device: DeviceInfo) -> Optional[HeuristicResult]:
        """
        Check for HID + Network composite device.
        
        Could indicate keystroke logger with exfiltration capability.
        """
        if device.has_hid and device.has_network:
            return HeuristicResult(
                score=self.weights["hid_network_composite"],
                reason="Composite HID+Network device (potential exfiltration)",
                indicator="hid_network_composite",
                details={
                    "hid_interfaces": [i for i in device.interfaces if i.startswith("03")],
                    "network_interfaces": [
                        i for i in device.interfaces 
                        if i.startswith("02") or i.startswith("0a")
                    ],
                }
            )
        return None
    
    def _check_missing_serial(self, device: DeviceInfo) -> Optional[HeuristicResult]:
        """
        Check for missing or generic serial number.
        
        Legitimate devices usually have unique serial numbers.
        Attack devices often lack them or have generic patterns.
        """
        serial = device.serial.strip() if device.serial else ""
        
        if not serial:
            return HeuristicResult(
                score=self.weights["missing_serial"],
                reason="Missing serial number",
                indicator="missing_serial",
            )
        
        # Check for generic patterns
        for pattern in self.GENERIC_SERIAL_PATTERNS:
            if re.match(pattern, serial, re.IGNORECASE):
                return HeuristicResult(
                    score=self.weights["missing_serial"],
                    reason=f"Generic serial number pattern: {serial}",
                    indicator="missing_serial",
                    details={"serial": serial, "pattern": pattern}
                )
        
        return None
    
    def _check_vendor_specific_interface(self, device: DeviceInfo) -> Optional[HeuristicResult]:
        """
        Check for vendor-specific interface class (0xFF).
        
        While some legitimate devices use this, it's also common
        in malware and exploits that don't follow USB standards.
        """
        vendor_interfaces = [i for i in device.interfaces if i.startswith("ff")]
        
        if vendor_interfaces:
            return HeuristicResult(
                score=self.weights["vendor_specific_interface"],
                reason=f"Vendor-specific interface class (0xFF): {len(vendor_interfaces)} interface(s)",
                indicator="vendor_specific_interface",
                details={"interfaces": vendor_interfaces}
            )
        return None
    
    def _check_multiple_interfaces(self, device: DeviceInfo) -> Optional[HeuristicResult]:
        """
        Check for excessive number of interfaces.
        
        Complex devices with many interfaces have larger attack surface.
        """
        if len(device.interfaces) >= 3:
            # Get unique interface classes
            classes = set(
                iface.split(":")[0] if ":" in iface else iface[:2]
                for iface in device.interfaces
            )
            
            return HeuristicResult(
                score=self.weights["multiple_interfaces"],
                reason=f"Complex device with {len(device.interfaces)} interfaces, {len(classes)} classes",
                indicator="multiple_interfaces",
                details={
                    "interface_count": len(device.interfaces),
                    "class_count": len(classes),
                    "classes": list(classes)
                }
            )
        return None
    
    def _check_high_risk_vendor(self, device: DeviceInfo) -> Optional[HeuristicResult]:
        """
        Check for high-risk vendor ID.
        
        These are VIDs commonly used in development boards and attack tools.
        """
        vid = device.vendor_id.lower()
        
        if vid in self.HIGH_RISK_VENDORS:
            return HeuristicResult(
                score=self.weights["high_risk_vendor"],
                reason=f"High-risk vendor ID: 0x{vid}",
                indicator="high_risk_vendor",
                details={"vendor_id": vid}
            )
        return None
    
    def _check_unknown_manufacturer(self, device: DeviceInfo) -> Optional[HeuristicResult]:
        """
        Check for missing or unknown manufacturer string.
        
        Legitimate devices usually provide manufacturer information.
        """
        manufacturer = device.manufacturer.strip() if device.manufacturer else ""
        
        if not manufacturer or manufacturer.lower() in ["unknown", "n/a", "generic"]:
            return HeuristicResult(
                score=self.weights["unknown_manufacturer"],
                reason="Missing or unknown manufacturer",
                indicator="unknown_manufacturer",
            )
        return None
    
    def _check_rapid_replug(self, device: DeviceInfo) -> Optional[HeuristicResult]:
        """
        Check for rapid plug/unplug pattern.
        
        This can indicate enumeration fuzzing or attack device probing.
        Tracks device_id over time.
        """
        now = time.time()
        device_id = device.device_id
        
        # Clean old entries (older than 60 seconds)
        self._replug_tracker[device_id] = [
            t for t in self._replug_tracker[device_id]
            if now - t < 60
        ]
        
        # Add current plug event
        self._replug_tracker[device_id].append(now)
        
        # Check for rapid replug (>3 times in 60 seconds)
        if len(self._replug_tracker[device_id]) > 3:
            return HeuristicResult(
                score=self.weights["rapid_replug"],
                reason=f"Rapid replug detected: {len(self._replug_tracker[device_id])} times in 60s",
                indicator="rapid_replug",
                details={
                    "count": len(self._replug_tracker[device_id]),
                    "window_seconds": 60
                }
            )
        return None
    
    def check_descriptor_mutation(
        self,
        device: DeviceInfo,
        descriptors: str
    ) -> Optional[HeuristicResult]:
        """
        Check for descriptor mutation over time.
        
        This indicates active firmware manipulation - a device that
        changes its descriptors after enumeration.
        
        Called externally after monitoring device behavior.
        """
        device_id = device.device_id
        
        if device_id in self._descriptor_history:
            previous = self._descriptor_history[device_id][-1]
            if previous != descriptors:
                return HeuristicResult(
                    score=self.weights["descriptor_mutation"],
                    reason="USB descriptor mutation detected",
                    indicator="descriptor_mutation",
                    details={
                        "mutation_count": len(self._descriptor_history[device_id]),
                    }
                )
        
        # Store current descriptor snapshot
        self._descriptor_history[device_id].append(descriptors)
        
        # Limit history size
        if len(self._descriptor_history[device_id]) > 10:
            self._descriptor_history[device_id] = self._descriptor_history[device_id][-10:]
        
        return None
    
    def check_cve_match(
        self,
        device: DeviceInfo,
        cve_database: dict
    ) -> Optional[HeuristicResult]:
        """
        Check device against CVE database.
        
        Called externally with loaded CVE database.
        """
        device_key = f"{device.vendor_id}:{device.product_id}"
        
        if device_key in cve_database:
            cve_info = cve_database[device_key]
            return HeuristicResult(
                score=self.weights["cve_match"],
                reason=f"Known CVE match: {cve_info.get('cve_id', 'Unknown')}",
                indicator="cve_match",
                details=cve_info
            )
        return None
    
    def update_weights(self, weights: dict[str, int]) -> None:
        """Update heuristic weights from configuration."""
        self.weights.update(weights)
        logger.info(f"Updated heuristic weights: {weights}")
    
    def clear_history(self, device_id: Optional[str] = None) -> None:
        """Clear tracking history for a device or all devices."""
        if device_id:
            self._replug_tracker.pop(device_id, None)
            self._descriptor_history.pop(device_id, None)
        else:
            self._replug_tracker.clear()
            self._descriptor_history.clear()
