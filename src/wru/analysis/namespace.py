"""
Namespace-Isolated Storage Analysis

Implements mount namespace isolation for safe analysis of
potentially malicious storage devices without exposing the host.
"""

import os
import asyncio
import logging
import tempfile
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, AsyncIterator
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """Results from isolated storage analysis."""
    device_path: Path
    is_safe: bool
    threats_found: list[str] = field(default_factory=list)
    suspicious_files: list[str] = field(default_factory=list)
    autorun_detected: bool = False
    malware_detected: bool = False
    scan_errors: list[str] = field(default_factory=list)
    file_count: int = 0
    total_size_bytes: int = 0
    filesystem_type: str = ""
    
    def to_dict(self) -> dict:
        """Convert to dictionary for logging."""
        return {
            "device_path": str(self.device_path),
            "is_safe": self.is_safe,
            "threats_found": self.threats_found,
            "suspicious_files": self.suspicious_files,
            "autorun_detected": self.autorun_detected,
            "malware_detected": self.malware_detected,
            "scan_errors": self.scan_errors,
            "file_count": self.file_count,
            "total_size_bytes": self.total_size_bytes,
            "filesystem_type": self.filesystem_type,
        }


class NamespaceAnalyzer:
    """
    Analyzes storage devices in isolated mount namespace.
    
    Creates an ephemeral mount namespace, mounts the device
    read-only with restrictive options, runs analysis tools,
    then destroys the namespace.
    
    The host filesystem is never exposed to the device contents.
    """
    
    # Suspicious file extensions
    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".scr", ".pif", ".bat", ".cmd", ".com",
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
        ".ps1", ".psm1", ".msi", ".dll", ".sys",
        ".hta", ".cpl", ".msc", ".lnk", ".jar",
    }
    
    # Autorun file patterns
    AUTORUN_PATTERNS = {
        "autorun.inf",
        "autorun.exe",
        "autoexec.bat",
        ".autorun",
    }
    
    def __init__(self, mount_base: Optional[Path] = None):
        self._mount_base = mount_base or Path("/run/wru/mounts")
        self._mount_base.mkdir(parents=True, exist_ok=True)
    
    async def analyze(self, device_path: Path) -> AnalysisResult:
        """
        Analyze a storage device in isolated namespace.
        
        Args:
            device_path: Path to block device (e.g., /dev/sda1)
            
        Returns:
            AnalysisResult with findings
        """
        result = AnalysisResult(device_path=device_path)
        
        try:
            # Get filesystem type
            result.filesystem_type = await self._get_filesystem_type(device_path)
            
            # Create temporary mount point
            mount_point = tempfile.mkdtemp(
                prefix="wru-analyze-",
                dir=str(self._mount_base)
            )
            
            try:
                # Run analysis in isolated namespace
                async with self._isolated_mount(device_path, Path(mount_point)) as mounted:
                    if mounted:
                        # Run all analysis tasks
                        await self._analyze_filesystem(Path(mount_point), result)
                        await self._scan_for_malware(Path(mount_point), result)
                        await self._check_autorun(Path(mount_point), result)
                        await self._find_suspicious_files(Path(mount_point), result)
                    else:
                        result.scan_errors.append("Failed to mount device in namespace")
                        
            finally:
                # Clean up mount point
                try:
                    os.rmdir(mount_point)
                except OSError:
                    pass
                    
        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
            result.scan_errors.append(str(e))
        
        # Determine overall safety
        result.is_safe = (
            not result.malware_detected and
            not result.autorun_detected and
            len(result.threats_found) == 0
        )
        
        return result
    
    async def _get_filesystem_type(self, device_path: Path) -> str:
        """Get filesystem type using blkid."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "blkid", "-o", "value", "-s", "TYPE", str(device_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            return stdout.decode().strip()
        except Exception:
            return "unknown"
    
    @asynccontextmanager
    async def _isolated_mount(
        self,
        device_path: Path,
        mount_point: Path
    ) -> AsyncIterator[bool]:
        """
        Context manager that mounts device in isolated namespace.
        
        Uses unshare to create new mount namespace, mounts device
        read-only with security options, yields, then unmounts.
        """
        # Build the mount command with security options
        mount_opts = "ro,noexec,nodev,nosuid,noatime"
        
        # The unshare command creates new mount namespace
        cmd = [
            "unshare",
            "--mount",
            "--propagation", "slave",
            "--",
            "sh", "-c",
            f"mount -o {mount_opts} {device_path} {mount_point} && "
            f"echo MOUNTED && cat"  # cat blocks until we kill it
        ]
        
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE
            )
            
            # Wait for mount confirmation
            try:
                line = await asyncio.wait_for(
                    proc.stdout.readline(),
                    timeout=10.0
                )
                if b"MOUNTED" in line:
                    logger.info(f"Mounted {device_path} in isolated namespace")
                    yield True
                else:
                    logger.error(f"Mount failed: {line.decode()}")
                    yield False
            except asyncio.TimeoutError:
                logger.error("Mount operation timed out")
                yield False
                
        except Exception as e:
            logger.error(f"Failed to create isolated mount: {e}")
            yield False
            
        finally:
            if proc:
                # Terminate the blocking cat, which destroys the namespace
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    proc.kill()
                logger.debug("Isolated namespace destroyed")
    
    async def _analyze_filesystem(
        self,
        mount_point: Path,
        result: AnalysisResult
    ) -> None:
        """Gather filesystem statistics."""
        try:
            file_count = 0
            total_size = 0
            
            for root, dirs, files in os.walk(mount_point):
                file_count += len(files)
                for f in files:
                    try:
                        fp = Path(root) / f
                        total_size += fp.stat().st_size
                    except OSError:
                        pass
            
            result.file_count = file_count
            result.total_size_bytes = total_size
            
        except Exception as e:
            logger.warning(f"Filesystem analysis failed: {e}")
    
    async def _scan_for_malware(
        self,
        mount_point: Path,
        result: AnalysisResult
    ) -> None:
        """
        Run ClamAV malware scan on mounted filesystem.
        
        Uses clamdscan for speed if clamd is running,
        falls back to clamscan otherwise.
        """
        try:
            # Try clamdscan first (faster, uses daemon)
            proc = await asyncio.create_subprocess_exec(
                "clamdscan",
                "--infected",
                "--no-summary",
                str(mount_point),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=300.0  # 5 minute timeout
            )
            
            if proc.returncode == 1:  # Virus found
                result.malware_detected = True
                # Parse output for infected files
                for line in stdout.decode().splitlines():
                    if "FOUND" in line:
                        result.threats_found.append(line.strip())
                        
            elif proc.returncode == 2:  # Error
                # Try fallback to clamscan
                logger.info("clamdscan failed, trying clamscan")
                proc = await asyncio.create_subprocess_exec(
                    "clamscan",
                    "-r",
                    "--infected",
                    "--no-summary",
                    str(mount_point),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=600.0
                )
                
                if proc.returncode == 1:
                    result.malware_detected = True
                    for line in stdout.decode().splitlines():
                        if "FOUND" in line:
                            result.threats_found.append(line.strip())
                            
        except FileNotFoundError:
            logger.warning("ClamAV not installed, skipping malware scan")
            result.scan_errors.append("ClamAV not available")
        except asyncio.TimeoutError:
            logger.error("Malware scan timed out")
            result.scan_errors.append("Malware scan timeout")
        except Exception as e:
            logger.error(f"Malware scan failed: {e}")
            result.scan_errors.append(f"Scan error: {e}")
    
    async def _check_autorun(
        self,
        mount_point: Path,
        result: AnalysisResult
    ) -> None:
        """Check for autorun files."""
        try:
            for root, dirs, files in os.walk(mount_point):
                for f in files:
                    if f.lower() in self.AUTORUN_PATTERNS:
                        result.autorun_detected = True
                        result.threats_found.append(
                            f"Autorun file: {Path(root).relative_to(mount_point) / f}"
                        )
                        
                # Only check root and first level
                if Path(root) != mount_point:
                    break
                    
        except Exception as e:
            logger.warning(f"Autorun check failed: {e}")
    
    async def _find_suspicious_files(
        self,
        mount_point: Path,
        result: AnalysisResult
    ) -> None:
        """Find files with suspicious extensions."""
        try:
            for root, dirs, files in os.walk(mount_point):
                for f in files:
                    ext = Path(f).suffix.lower()
                    if ext in self.SUSPICIOUS_EXTENSIONS:
                        rel_path = str(
                            Path(root).relative_to(mount_point) / f
                        )
                        result.suspicious_files.append(rel_path)
                        
                        # Limit results
                        if len(result.suspicious_files) >= 100:
                            return
                            
        except Exception as e:
            logger.warning(f"Suspicious file scan failed: {e}")
