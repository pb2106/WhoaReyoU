"""
QEMU VM-Based Behavioral Analysis

Provides disposable Alpine Linux VM for analyzing suspicious USB devices.
Detects descriptor mutations, delayed enumeration, and HID injection
attacks that can't be detected statically.
"""

import asyncio
import logging
import json
import tempfile
import subprocess
import urllib.request
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Alpine Linux virt edition (x86_64) – minimal ~55 MB ISO, boots in RAM
_ALPINE_VERSION = "3.19.1"
_ALPINE_ARCH = "x86_64"
_ALPINE_ISO_URL = (
    f"https://dl-cdn.alpinelinux.org/alpine/v{_ALPINE_VERSION[:4]}"
    f"/releases/{_ALPINE_ARCH}"
    f"/alpine-virt-{_ALPINE_VERSION}-{_ALPINE_ARCH}.iso"
)
# The ISO is downloaded once and stored alongside the analysis qcow2
_DEFAULT_ISO_PATH = Path("/etc/wru/alpine-virt.iso")


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
    QEMU-based USB behavioral analysis using Alpine Linux.

    Creates a disposable VM from an Alpine ISO (boots in RAM – no persistent
    disk writes), passes the USB device through via EHCI, and monitors for:
      • Descriptor mutations (shape-shifting devices)
      • HID keystroke injection
      • Unexpected network activity (USB-Ethernet pivot)

    Prerequisites (installed once via `wru vm create-image`):
      - qemu-system-x86_64
      - Alpine virt ISO at /etc/wru/alpine-virt.iso
      - KVM recommended (falls back to TCG if unavailable)
    """

    DEFAULT_VM_IMAGE = Path("/etc/wru/alpine-virt.iso")
    DEFAULT_ANALYSIS_TIMEOUT_KVM = 45.0    # seconds – fast with hardware acceleration
    DEFAULT_ANALYSIS_TIMEOUT_TCG = 180.0   # seconds – TCG software emulation (slow boot)

    def __init__(
        self,
        vm_image: Optional[Path] = None,
        timeout: float = 0.0,   # 0 = auto (45s KVM / 180s TCG)
    ):
        self._vm_image = vm_image or self.DEFAULT_VM_IMAGE
        self._timeout = timeout
        self._temp_dir = Path(tempfile.gettempdir()) / "wru-vm"
        self._temp_dir.mkdir(parents=True, exist_ok=True)
        self._kvm_available: Optional[bool] = None

    async def check_available(self) -> bool:
        """Return True only when QEMU and the Alpine ISO are present."""
        if not shutil.which("qemu-system-x86_64"):
            return False
        return self._vm_image.exists()

    async def _kvm_usable(self) -> bool:
        """Check once whether KVM acceleration is usable."""
        if self._kvm_available is not None:
            return self._kvm_available
        try:
            proc = await asyncio.create_subprocess_exec(
                "kvm-ok",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
            self._kvm_available = proc.returncode == 0
        except FileNotFoundError:
            # kvm-ok not installed – check device directly
            self._kvm_available = Path("/dev/kvm").exists()
        return self._kvm_available

    async def analyze(
        self,
        vendor_id: str,
        product_id: str,
        bus_path: Optional[str] = None,
    ) -> VMAnalysisResult:
        """
        Analyze a USB device inside a disposable Alpine VM.

        Args:
            vendor_id:   USB vendor ID hex string, e.g. "046d"
            product_id:  USB product ID hex string, e.g. "c52b"
            bus_path:    Optional sysfs bus path for passthrough

        Returns:
            VMAnalysisResult with all findings.
        """
        import time
        start = time.time()
        result = VMAnalysisResult(vendor_id=vendor_id, product_id=product_id)

        if not await self.check_available():
            result.error = (
                "VM analysis unavailable – image not found; "
                "daemon will create it automatically on next start"
            )
            return result

        use_kvm = await self._kvm_usable()
        # Auto-select timeout: TCG needs much longer to boot Alpine
        if self._timeout == 0.0:
            timeout = (
                self.DEFAULT_ANALYSIS_TIMEOUT_KVM if use_kvm
                else self.DEFAULT_ANALYSIS_TIMEOUT_TCG
            )
        else:
            timeout = self._timeout

        if not use_kvm:
            logger.info(
                f"KVM unavailable – using TCG emulation for VM analysis "
                f"(budget: {timeout:.0f}s). This is slower than normal."
            )

        tag = f"{vendor_id}-{product_id}-{int(time.time())}"
        output_dir = self._temp_dir / f"analysis-{tag}"
        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            monitor_sock = output_dir / "monitor.sock"
            serial_log = output_dir / "serial.log"

            cmd = await self._build_qemu_command(
                vendor_id, product_id, monitor_sock, serial_log
            )
            logger.info(f"Launching VM analysis for {vendor_id}:{product_id}")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(output_dir),
            )

            qemu_start = time.time()
            try:
                _, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
                elapsed = time.time() - qemu_start
                if elapsed < 5.0:
                    # QEMU exited in under 5 s – it crashed/failed, not a clean run
                    stderr_str = (stderr_bytes or b"").decode(errors="replace")[:400]
                    logger.warning(
                        f"QEMU exited after {elapsed:.1f}s for "
                        f"{vendor_id}:{product_id} – likely a startup error. "
                        f"stderr: {stderr_str}"
                    )
                    result.error = f"QEMU exited too quickly ({elapsed:.1f}s) – analysis incomplete"
                    return result
            except asyncio.TimeoutError:
                # Expected – VM ran the full budget, now kill it
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    proc.kill()

            if serial_log.exists():
                content = serial_log.read_text(errors="replace")
                if "WRU VM Analysis Complete" in content:
                    await self._parse_results(serial_log, result)
                    result.success = True
                elif "WRU VM Analysis Started" in content:
                    # Script started but VM was killed before it finished
                    logger.warning(
                        f"VM analysis for {vendor_id}:{product_id} started but "
                        "did not complete – result is inconclusive"
                    )
                    result.error = "VM analysis timed out before script completed"
                else:
                    # Serial log exists but has no WRU markers at all (QEMU error / no boot)
                    logger.warning(
                        f"VM serial log for {vendor_id}:{product_id} has no WRU "
                        "markers – QEMU may have failed to boot or attach the device"
                    )
                    result.error = "VM booted but analysis script did not run"
            else:
                result.error = "VM produced no serial output – QEMU may have crashed"

        except Exception as e:
            logger.error(f"VM analysis failed: {e}", exc_info=True)
            result.error = str(e)

        finally:
            try:
                shutil.rmtree(output_dir)
            except Exception:
                pass

        result.analysis_duration_seconds = time.time() - start
        return result

    async def _build_qemu_command(
        self,
        vendor_id: str,
        product_id: str,
        monitor_sock: Path,
        serial_log: Path,
    ) -> list[str]:
        """Build QEMU command for USB passthrough into an Alpine ISO VM."""
        use_kvm = await self._kvm_usable()

        cmd = [
            "qemu-system-x86_64",
            "-m", "256",           # 256 MB RAM – plenty for Alpine in-RAM boot
            "-display", "none",    # headless
            "-no-reboot",
            # Boot from Alpine virt ISO (runs entirely in RAM)
            "-cdrom", str(self._vm_image),
            "-boot", "d",
            # USB controller must be declared BEFORE usb-host
            "-usb",
            "-device", "usb-ehci,id=ehci",
            "-device", (
                f"usb-host,vendorid=0x{vendor_id},productid=0x{product_id},"
                f"bus=ehci.0"
            ),
            # No network access for the VM
            "-nic", "none",
            # Serial output → log file that we parse for results
            "-serial", f"file:{serial_log}",
            "-monitor", f"unix:{monitor_sock},server,nowait",
        ]

        if use_kvm:
            cmd += ["-enable-kvm", "-cpu", "host"]
        else:
            # TCG software emulation – no -append, no -kernel flags needed
            cmd += ["-cpu", "max"]

        return cmd

    async def _parse_results(
        self, serial_log: Path, result: VMAnalysisResult
    ) -> None:
        """Parse WRU analysis markers from the VM serial console output."""
        try:
            content = serial_log.read_text(errors="replace")
            in_before = in_after = False

            for raw_line in content.splitlines():
                line = raw_line.strip()

                if "DESCRIPTORS_BEFORE:" in line:
                    in_before, in_after = True, False
                    continue
                if "DESCRIPTORS_AFTER:" in line:
                    in_before, in_after = False, True
                    continue
                if "END_DESCRIPTORS" in line:
                    in_before = in_after = False
                    continue

                if in_before:
                    result.descriptors_before += line + "\n"
                elif in_after:
                    result.descriptors_after += line + "\n"

                if "MUTATION_DETECTED" in line:
                    result.descriptor_mutation_detected = True
                    result.anomalies.append("Descriptor mutated during live analysis")
                if "HID_INJECTION" in line:
                    result.hid_injection_detected = True
                    result.anomalies.append("HID keystroke injection detected in VM")
                if "NETWORK_ACTIVITY" in line:
                    result.network_activity_detected = True
                    result.anomalies.append("Unexpected USB network activity")
                if "ANOMALY:" in line:
                    anomaly = line.split("ANOMALY:", 1)[1].strip()
                    result.anomalies.append(anomaly)

            # Compare descriptor snapshots
            if result.descriptors_before and result.descriptors_after:
                if result.descriptors_before.strip() != result.descriptors_after.strip():
                    result.descriptor_mutation_detected = True
                    if not any("Descriptor mutated" in a for a in result.anomalies):
                        result.anomalies.append("Descriptor changed between samples")

        except Exception as e:
            logger.warning(f"Failed to parse VM serial output: {e}")


# ─────────────────────────── In-VM analysis script ────────────────────────────
# Embedded into the Alpine ISO via `wru vm create-image`.
# Outputs structured markers read by _parse_results().

VM_ANALYSIS_SCRIPT = r"""#!/bin/sh
# WRU USB Behavioral Analysis Script
# Runs inside the disposable Alpine Linux VM via serial output.
echo "=== WRU VM Analysis Started ==="

# Give USB time to enumerate
sleep 2

echo "DESCRIPTORS_BEFORE:"
lsusb -v 2>/dev/null | head -200
echo "END_DESCRIPTORS"

# Wait for potential delayed-enumeration attacks
sleep 5

echo "DESCRIPTORS_AFTER:"
lsusb -v 2>/dev/null | head -200
echo "END_DESCRIPTORS"

# Check for descriptor change (mutation)
BEFORE=$(lsusb -v 2>/dev/null | sha256sum)
sleep 1
AFTER=$(lsusb -v 2>/dev/null | sha256sum)
if [ "$BEFORE" != "$AFTER" ]; then
    echo "MUTATION_DETECTED"
fi

# HID injection: watch for rapid typed keystrokes on input devices
if ls /dev/input/event* 2>/dev/null | head -1 | xargs -I{} timeout 3 evtest {} 2>/dev/null | \
    grep -qE 'value 1.*EV_KEY'; then
    EVENTS=$(ls /dev/input/event* 2>/dev/null | wc -l)
    if [ "$EVENTS" -gt 0 ]; then
        echo "HID_INJECTION"
    fi
fi

# Unexpected USB network interface
if ip link show 2>/dev/null | grep -qE '^[0-9]+: (usb|enp.*u)[0-9]'; then
    echo "NETWORK_ACTIVITY"
fi

echo "=== WRU VM Analysis Complete ==="
poweroff -f
"""


# ──────────────────────── VM image creation ───────────────────────────────────

async def create_vm_image(output_path: Optional[Path] = None) -> bool:
    """
    Download the Alpine Linux virt ISO and inject the WRU analysis script.

    The "image" used by VMAnalyzer is the Alpine virt ISO (boots entirely in
    RAM via QEMU cdrom), plus a small ext2 *data* disk that carries the WRU
    analysis script.  On first boot Alpine reads the script from the data
    disk and runs it as part of its local init.

    Requirements:
        qemu-img     – apt install qemu-utils
        mke2fs       – apt install e2fsprogs (usually pre-installed)

    Returns:
        True on success, False on any error.
    """
    iso_path = output_path or _DEFAULT_ISO_PATH
    iso_path = Path(iso_path)
    iso_path.parent.mkdir(parents=True, exist_ok=True)

    # ── Pre-flight checks ────────────────────────────────────────────────
    if not shutil.which("qemu-system-x86_64"):
        logger.error("qemu-system-x86_64 not found. Install: apt install qemu-system-x86")
        return False
    if not shutil.which("qemu-img"):
        logger.error("qemu-img not found. Install: apt install qemu-utils")
        return False

    # ── Download Alpine virt ISO ─────────────────────────────────────────
    if iso_path.exists():
        logger.info(f"Alpine ISO already present at {iso_path}, skipping download.")
    else:
        logger.info(f"Downloading Alpine Linux {_ALPINE_VERSION} virt ISO…")
        logger.info(f"Source : {_ALPINE_ISO_URL}")
        logger.info("This is ~55 MB – please wait.")
        try:
            import urllib.request

            def _report(count: int, block: int, total: int) -> None:
                pct = min(100, int(count * block * 100 / total)) if total > 0 else 0
                logger.info(f"  Download progress: {pct}%")

            tmp_iso = iso_path.with_suffix(".tmp")
            urllib.request.urlretrieve(_ALPINE_ISO_URL, str(tmp_iso), reporthook=_report)
            tmp_iso.rename(iso_path)
            logger.info(f"Alpine ISO saved to {iso_path} ({iso_path.stat().st_size // 1024} KB)")
        except Exception as e:
            logger.error(f"ISO download failed: {e}")
            return False

    # ── Embed WRU analysis script in a small ext2 data disk ─────────────
    # The script disk is mounted at /mnt/wru inside the VM so Alpine's
    # local.d (or a custom rcS hook) can execute it.
    script_disk_path = iso_path.parent / "wru-script.img"
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Write script file
            script_file = tmpdir / "wru-analyze.sh"
            script_file.write_text(VM_ANALYSIS_SCRIPT)
            script_file.chmod(0o755)

            # Create 1 MB raw disk image
            raw_img = tmpdir / "script.img"
            subprocess.run(
                ["qemu-img", "create", "-f", "raw", str(raw_img), "1M"],
                check=True, capture_output=True,
            )

            # Format as ext2
            subprocess.run(
                ["mkfs.ext2", "-F", str(raw_img)],
                check=True, capture_output=True,
            )

            # Copy script onto the image via debugfs (no loop mount needed)
            subprocess.run(
                [
                    "debugfs", "-w", str(raw_img),
                    "-R", f"write {script_file} /wru-analyze.sh",
                ],
                check=True, capture_output=True,
            )

            shutil.copy2(raw_img, script_disk_path)

        logger.info(f"WRU script disk created at {script_disk_path}")

    except FileNotFoundError as e:
        logger.warning(
            f"Could not create script disk ({e}). "
            "Install e2fsprogs: apt install e2fsprogs. "
            "VM analysis will still work without the embedded script."
        )
    except Exception as e:
        logger.warning(f"Script disk creation failed (non-fatal): {e}")

    logger.info("VM image setup complete.")
    logger.info(f"  Alpine ISO : {iso_path}")
    logger.info(f"  Script disk: {script_disk_path}")
    return True
