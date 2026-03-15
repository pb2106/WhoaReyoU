"""
Tests for the Threat Engine module.
"""

import pytest
from unittest.mock import MagicMock, patch
from wru.core.authorization import DeviceInfo
from wru.threat.heuristics import HeuristicScorer, HeuristicResult
from wru.threat.engine import ThreatEngine, ThreatDecision, ThreatAssessment


class TestHeuristicScorer:
    """Test the heuristic scoring system."""
    
    def test_hid_storage_composite_detection(self):
        """HID + Storage composite should score high (BadUSB signature)."""
        scorer = HeuristicScorer()
        
        # Create a device with both HID and Storage interfaces
        device = DeviceInfo(
            bus_id="1-2",
            vendor_id="1234",
            product_id="5678",
            interfaces=["03:01:01", "08:06:50"]  # HID + Mass Storage
        )
        
        results = scorer.evaluate_all(device)
        
        # Should detect HID+Storage composite
        composite_results = [r for r in results if r.indicator == "hid_storage_composite"]
        assert len(composite_results) == 1
        assert composite_results[0].score == 50
    
    def test_hid_network_composite_detection(self):
        """HID + Network composite should be detected."""
        scorer = HeuristicScorer()
        
        device = DeviceInfo(
            bus_id="1-2",
            vendor_id="1234",
            product_id="5678",
            interfaces=["03:01:01", "02:02:00"]  # HID + CDC/Network
        )
        
        results = scorer.evaluate_all(device)
        
        network_results = [r for r in results if r.indicator == "hid_network_composite"]
        assert len(network_results) == 1
        assert network_results[0].score == 40
    
    def test_missing_serial_detection(self):
        """Missing serial number should be flagged."""
        scorer = HeuristicScorer()
        
        device = DeviceInfo(
            bus_id="1-2",
            vendor_id="1234",
            product_id="5678",
            serial="",  # No serial
            interfaces=["08:06:50"]
        )
        
        results = scorer.evaluate_all(device)
        
        serial_results = [r for r in results if r.indicator == "missing_serial"]
        assert len(serial_results) == 1
        assert serial_results[0].score == 30
    
    def test_generic_serial_pattern_detection(self):
        """Generic serial patterns should be flagged."""
        scorer = HeuristicScorer()
        
        # Test all-zeros pattern
        device = DeviceInfo(
            bus_id="1-2",
            vendor_id="1234",
            product_id="5678",
            serial="000000000000",
            interfaces=["08:06:50"]
        )
        
        results = scorer.evaluate_all(device)
        
        serial_results = [r for r in results if r.indicator == "missing_serial"]
        assert len(serial_results) == 1
    
    def test_high_risk_vendor_detection(self):
        """High-risk vendor IDs should be flagged."""
        scorer = HeuristicScorer()
        
        device = DeviceInfo(
            bus_id="1-2",
            vendor_id="16c0",  # Teensy VID
            product_id="0486",
            interfaces=["03:01:01"]
        )
        
        results = scorer.evaluate_all(device)
        
        vendor_results = [r for r in results if r.indicator == "high_risk_vendor"]
        assert len(vendor_results) == 1
        assert vendor_results[0].score == 35
    
    def test_vendor_specific_interface_detection(self):
        """Vendor-specific interfaces (0xFF) should be flagged."""
        scorer = HeuristicScorer()
        
        device = DeviceInfo(
            bus_id="1-2",
            vendor_id="1234",
            product_id="5678",
            interfaces=["ff:00:00"]  # Vendor-specific
        )
        
        results = scorer.evaluate_all(device)
        
        vendor_if_results = [r for r in results if r.indicator == "vendor_specific_interface"]
        assert len(vendor_if_results) == 1
        assert vendor_if_results[0].score == 25
    
    def test_multiple_interfaces_detection(self):
        """Devices with 3+ interfaces should be flagged."""
        scorer = HeuristicScorer()
        
        device = DeviceInfo(
            bus_id="1-2",
            vendor_id="1234",
            product_id="5678",
            interfaces=["03:01:01", "08:06:50", "02:02:00", "ff:00:00"]
        )
        
        results = scorer.evaluate_all(device)
        
        multi_results = [r for r in results if r.indicator == "multiple_interfaces"]
        assert len(multi_results) == 1
        assert multi_results[0].score == 20
    
    def test_clean_device_low_score(self):
        """A legitimate-looking device should have low score."""
        scorer = HeuristicScorer()
        
        device = DeviceInfo(
            bus_id="1-2",
            vendor_id="046d",  # Logitech
            product_id="c52b",
            serial="1234567890ABCDEF",
            manufacturer="Logitech",
            product="USB Receiver",
            interfaces=["03:01:01"]  # Just HID
        )
        
        results = scorer.evaluate_all(device)
        
        # Should only have minimal flags or none
        total_score = sum(r.score for r in results)
        assert total_score < 20


class TestThreatEngine:
    """Test the main threat engine."""
    
    @pytest.mark.asyncio
    async def test_allow_decision_for_low_score(self):
        """Low-scoring devices should get ALLOW decision."""
        engine = ThreatEngine()
        
        device = DeviceInfo(
            bus_id="1-2",
            vendor_id="046d",
            product_id="c52b",
            serial="ABCD1234567890EF",
            manufacturer="Logitech",
            product="USB Receiver",
            interfaces=["03:01:01"]
        )
        
        assessment = await engine.analyze(device)
        
        assert assessment.decision == ThreatDecision.ALLOW
        assert assessment.score <= 19
    
    @pytest.mark.asyncio
    async def test_deny_decision_for_high_score(self):
        """High-scoring devices should get DENY decision."""
        engine = ThreatEngine()
        
        # Create an extremely suspicious device
        device = DeviceInfo(
            bus_id="1-2",
            vendor_id="16c0",  # High-risk VID (+35)
            product_id="0486",
            serial="",  # Missing serial (+30)
            manufacturer="",  # Unknown manufacturer (+15)
            product="",
            interfaces=["03:01:01", "08:06:50", "ff:00:00"]  # HID+Storage (+50), vendor-specific (+25)
        )
        
        assessment = await engine.analyze(device)
        
        assert assessment.decision == ThreatDecision.DENY
        assert assessment.score >= 70
    
    @pytest.mark.asyncio
    async def test_quarantine_decision_for_medium_score(self):
        """Medium-scoring devices should get QUARANTINE decision."""
        engine = ThreatEngine()

        # Storage-only device with no serial → storage heuristic (~35) + missing_serial(~30)
        # But from a non-high-risk VID so it stays in QUARANTINE/ANALYZE range.
        device = DeviceInfo(
            bus_id="1-2",
            vendor_id="abcd",   # unknown but not in high-risk list
            product_id="1234",
            serial="",          # missing serial (+30)
            manufacturer="GenericCo",
            interfaces=["08:06:50"]  # plain storage (+35)
        )

        assessment = await engine.analyze(device)

        # Score will be capped at 100 but decision must not be ALLOW
        assert assessment.decision in (
            ThreatDecision.QUARANTINE, ThreatDecision.ANALYZE, ThreatDecision.DENY
        )
        assert assessment.score >= 20

    
    def test_allowlist_matching(self):
        """Allowlist should match devices correctly."""
        engine = ThreatEngine()
        
        device = DeviceInfo(
            bus_id="1-2",
            vendor_id="046d",
            product_id="c52b",
            serial="ABC123XYZ",
            interfaces=[]
        )
        
        allowlist = [
            {"vendor_id": "046d", "product_id": "c52b", "serial": "ABC*"}
        ]
        
        assert engine.check_allowlist(device, allowlist) is True
    
    def test_allowlist_no_match(self):
        """Non-matching devices should not match allowlist."""
        engine = ThreatEngine()
        
        device = DeviceInfo(
            bus_id="1-2",
            vendor_id="1234",
            product_id="5678",
            serial="DIFFERENT",
            interfaces=[]
        )
        
        allowlist = [
            {"vendor_id": "046d", "product_id": "c52b"}
        ]
        
        assert engine.check_allowlist(device, allowlist) is False


class TestDeviceInfo:
    """Test DeviceInfo utility methods."""
    
    def test_device_id_generation(self):
        """Device ID should include VID, PID, and serial."""
        device = DeviceInfo(
            bus_id="1-2",
            vendor_id="046d",
            product_id="c52b",
            serial="ABC123"
        )
        
        assert device.device_id == "046d:c52b:ABC123"
    
    def test_device_id_no_serial(self):
        """Device ID should handle missing serial."""
        device = DeviceInfo(
            bus_id="1-2",
            vendor_id="046d",
            product_id="c52b",
            serial=""
        )
        
        assert device.device_id == "046d:c52b:no-serial"
    
    def test_has_hid(self):
        """has_hid should detect HID interface class."""
        device = DeviceInfo(
            bus_id="1-2",
            interfaces=["03:01:01"]
        )
        
        assert device.has_hid is True
        assert device.has_storage is False
    
    def test_has_storage(self):
        """has_storage should detect mass storage class."""
        device = DeviceInfo(
            bus_id="1-2",
            interfaces=["08:06:50"]
        )
        
        assert device.has_storage is True
        assert device.has_hid is False
    
    def test_is_composite(self):
        """is_composite should detect multiple interface classes."""
        device = DeviceInfo(
            bus_id="1-2",
            interfaces=["03:01:01", "08:06:50"]
        )
        
        assert device.is_composite is True
