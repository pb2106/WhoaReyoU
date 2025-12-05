"""
QEMU VM-Based Behavioral Analysis

Provides disposable VM for analyzing suspicious USB devices.
Detects descriptor mutations, delayed enumeration, and other
behavioral attacks that can't be detected statically.
"""

import asyncio
import logging
import json
import tempfile
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class VMAnalysisResult:
    """Results from VM-based analysis."""
    vendor_id: str
    product_id: str
    success: bool = False
    descriptor_mutation_detected: bool = False
    network_activity_detected: bool = False
    hid_injection_detected: bool = False
    anomalies: list[str] = field(default_factory=list)
    descriptors_before: str = ""
    descriptors_after: str = ""
    analysis_duration_seconds: float = 0.0
    error: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "success": self.success,
            "descriptor_mutation": self.descriptor_mutation_detected,
            "network_activity": self.network_activity_detected,
            "hid_injection": self.hid_injection_detected,
            "anomalies": self.anomalies,
            "duration": self.analysis_duration_seconds,
            "error": self.error,
        }


class VMAnalyzer:
    """
    QEMU-based USB behavioral analysis.
    
    Creates a disposable VM, passes the USB device through,
    and monitors for suspicious behavior.
    
    Requires:
    - QEMU installed
    - Analysis VM image
    - USB passthrough capability
    """
    
    DEFAULT_VM_IMAGE = Path("/etc/wru/vm-analysis-image.qcow2")
    DEFAULT_ANALYSIS_TIMEOUT = 30.0  # seconds
    
    def __init__(
        self,
        vm_image: Optional[Path] = None,
        timeout: float = DEFAULT_ANALYSIS_TIMEOUT
    ):
        self._vm_image = vm_image or self.DEFAULT_VM_IMAGE
        self._timeout = timeout
        self._temp_dir = Path(tempfile.gettempdir()) / "wru-vm"
        self._temp_dir.mkdir(parents=True, exist_ok=True)
    
    async def check_available(self) -> bool:
        """Check if VM analysis is available."""
        # Check QEMU
        try:
            proc = await asyncio.create_subprocess_exec(
                "qemu-system-x86_64", "--version",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await proc.wait()
            if proc.returncode != 0:
                return False
        except FileNotFoundError:
            return False
        
        # Check VM image
        if not self._vm_image.exists():
            return False
        
        return True
    
    async def analyze(
        self,
        vendor_id: str,
        product_id: str,
        bus_path: Optional[str] = None
    ) -> VMAnalysisResult:
        """
        Analyze a USB device in a disposable VM.
        
        Args:
            vendor_id: USB vendor ID (hex string, e.g., "046d")
            product_id: USB product ID (hex string, e.g., "c52b")
            bus_path: Optional USB bus path for passthrough
            
        Returns:
            VMAnalysisResult with findings
        """
        import time
        start_time = time.time()
        
        result = VMAnalysisResult(
            vendor_id=vendor_id,
            product_id=product_id
        )
        
        if not await self.check_available():
            result.error = "VM analysis not available (QEMU or image missing)"
            return result
        
        # Create output directory for this analysis
        output_dir = self._temp_dir / f"analysis-{vendor_id}-{product_id}-{int(time.time())}"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Build QEMU command
            monitor_sock = output_dir / "monitor.sock"
            serial_log = output_dir / "serial.log"
            
            cmd = self._build_qemu_command(
                vendor_id,
                product_id,
                monitor_sock,
                serial_log
            )
            
            logger.info(f"Starting VM analysis for {vendor_id}:{product_id}")
            
            # Run VM with timeout
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(output_dir)
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self._timeout
                )
            except asyncio.TimeoutError:
                # Expected - VM runs until we kill it
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    proc.kill()
            
            # Parse results from serial log
            if serial_log.exists():
                await self._parse_results(serial_log, result)
            
            result.success = True
            
        except Exception as e:
            logger.error(f"VM analysis failed: {e}", exc_info=True)
            result.error = str(e)
            
        finally:
            # Cleanup
            try:
                import shutil
                shutil.rmtree(output_dir)
            except Exception:
                pass
        
        result.analysis_duration_seconds = time.time() - start_time
        return result
    
    def _build_qemu_command(
        self,
        vendor_id: str,
        product_id: str,
        monitor_sock: Path,
        serial_log: Path
    ) -> list[str]:
        """Build QEMU command line."""
        return [
            "qemu-system-x86_64",
            "-m", "512",  # 512MB RAM
            "-snapshot",  # Don't modify disk image
            "-display", "none",  # Headless
            "-no-reboot",
            "-drive", f"file={self._vm_image},format=qcow2,snapshot=on",
            "-device", f"usb-host,vendorid=0x{vendor_id},productid=0x{product_id}",
            "-device", "qemu-xhci",  # USB 3.0 controller
            "-net", "none",  # No network
            "-monitor", f"unix:{monitor_sock},server,nowait",
            "-serial", f"file:{serial_log}",
            "-enable-kvm",  # Use KVM if available
        ]
    
    async def _parse_results(
        self,
        serial_log: Path,
        result: VMAnalysisResult
    ) -> None:
        """Parse VM analysis results from serial output."""
        try:
            content = serial_log.read_text()
            
            # Look for specific markers in output
            lines = content.splitlines()
            
            in_descriptors_before = False
            in_descriptors_after = False
            
            for line in lines:
                line = line.strip()
                
                if "DESCRIPTORS_BEFORE:" in line:
                    in_descriptors_before = True
                    in_descriptors_after = False
                    continue
                elif "DESCRIPTORS_AFTER:" in line:
                    in_descriptors_before = False
                    in_descriptors_after = True
                    continue
                elif "END_DESCRIPTORS" in line:
                    in_descriptors_before = False
                    in_descriptors_after = False
                    continue
                
                if in_descriptors_before:
                    result.descriptors_before += line + "\n"
                elif in_descriptors_after:
                    result.descriptors_after += line + "\n"
                
                # Check for specific findings
                if "MUTATION_DETECTED" in line:
                    result.descriptor_mutation_detected = True
                    result.anomalies.append("Descriptor mutation during analysis")
                    
                if "NETWORK_ACTIVITY" in line:
                    result.network_activity_detected = True
                    result.anomalies.append("Network activity from USB device")
                    
                if "HID_INJECTION" in line:
                    result.hid_injection_detected = True
                    result.anomalies.append("HID keystroke injection detected")
                    
                if "ANOMALY:" in line:
                    anomaly = line.split("ANOMALY:", 1)[1].strip()
                    result.anomalies.append(anomaly)
            
            # Compare descriptors if both captured
            if result.descriptors_before and result.descriptors_after:
                if result.descriptors_before.strip() != result.descriptors_after.strip():
                    result.descriptor_mutation_detected = True
                    if "Descriptor mutation" not in str(result.anomalies):
                        result.anomalies.append("Descriptor changed during monitoring")
                        
        except Exception as e:
            logger.warning(f"Failed to parse VM results: {e}")


# VM Analysis Script (to be run inside the VM)
VM_ANALYSIS_SCRIPT = """#!/bin/bash
# WRU VM Analysis Script
# Runs inside disposable QEMU VM

echo "=== WRU VM Analysis Started ==="

# Capture initial descriptors
echo "DESCRIPTORS_BEFORE:"
lsusb -v 2>/dev/null | head -100
echo "END_DESCRIPTORS"

# Wait for delayed enumeration attacks
sleep 5

# Capture descriptors again
echo "DESCRIPTORS_AFTER:"
lsusb -v 2>/dev/null | head -100
echo "END_DESCRIPTORS"

# Check for descriptor changes
if ! diff -q <(lsusb -v 2>/dev/null) <(lsusb -v 2>/dev/null) > /dev/null 2>&1; then
    echo "MUTATION_DETECTED"
fi

# Monitor for HID events
timeout 3 cat /dev/input/event* 2>/dev/null | head -c 100 > /tmp/hid_events
if [ -s /tmp/hid_events ]; then
    echo "HID_INJECTION"
fi

# Check for unexpected network activity
if ip link show | grep -q "usb"; then
    echo "NETWORK_ACTIVITY"
fi

echo "=== WRU VM Analysis Complete ==="
poweroff
"""


async def create_vm_image(output_path: Path) -> bool:
    """Create a minimal VM image for analysis."""
    logger.info("VM image creation not implemented - use pre-built image")
    return False
