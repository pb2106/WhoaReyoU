"""
ClamAV Integration Module

Provides async interface to ClamAV antivirus scanning.
"""

import asyncio
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result from ClamAV scan."""
    path: Path
    is_clean: bool
    infected_files: list[str] = field(default_factory=list)
    virus_names: list[str] = field(default_factory=list)
    files_scanned: int = 0
    errors: list[str] = field(default_factory=list)
    scan_time_seconds: float = 0.0


class ClamAVScanner:
    """
    Async ClamAV scanner interface.
    
    Uses clamdscan for fast daemon-based scanning when available,
    falls back to clamscan for standalone operation.
    """
    
    def __init__(self, timeout: float = 300.0):
        self._timeout = timeout
        self._daemon_available: Optional[bool] = None
    
    async def check_daemon(self) -> bool:
        """Check if clamd daemon is running."""
        if self._daemon_available is not None:
            return self._daemon_available
            
        try:
            proc = await asyncio.create_subprocess_exec(
                "clamdscan", "--ping",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.wait_for(proc.wait(), timeout=5.0)
            self._daemon_available = proc.returncode == 0
        except Exception:
            self._daemon_available = False
            
        return self._daemon_available
    
    async def scan_path(self, path: Path) -> ScanResult:
        """
        Scan a file or directory.
        
        Args:
            path: Path to scan
            
        Returns:
            ScanResult with findings
        """
        import time
        start_time = time.time()
        
        result = ScanResult(path=path, is_clean=True)
        
        try:
            # Choose scanner based on daemon availability
            use_daemon = await self.check_daemon()
            
            if use_daemon:
                await self._scan_with_daemon(path, result)
            else:
                await self._scan_with_clamscan(path, result)
                
        except FileNotFoundError:
            result.errors.append("ClamAV not installed")
        except Exception as e:
            result.errors.append(str(e))
            
        result.scan_time_seconds = time.time() - start_time
        return result
    
    async def _scan_with_daemon(self, path: Path, result: ScanResult) -> None:
        """Scan using clamdscan (daemon mode)."""
        cmd = [
            "clamdscan",
            "--infected",
            "--multiscan",  # Use multiple threads
            str(path)
        ]
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self._timeout
            )
            
            self._parse_output(stdout.decode(), result)
            
            if proc.returncode == 1:
                result.is_clean = False
            elif proc.returncode != 0:
                result.errors.append(f"clamdscan error: {stderr.decode()}")
                
        except asyncio.TimeoutError:
            result.errors.append("Scan timed out")
    
    async def _scan_with_clamscan(self, path: Path, result: ScanResult) -> None:
        """Scan using clamscan (standalone mode)."""
        cmd = [
            "clamscan",
            "-r",  # Recursive
            "--infected",
            str(path)
        ]
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self._timeout
            )
            
            self._parse_output(stdout.decode(), result)
            
            if proc.returncode == 1:
                result.is_clean = False
            elif proc.returncode != 0:
                result.errors.append(f"clamscan error: {stderr.decode()}")
                
        except asyncio.TimeoutError:
            result.errors.append("Scan timed out")
    
    def _parse_output(self, output: str, result: ScanResult) -> None:
        """Parse ClamAV output."""
        for line in output.splitlines():
            line = line.strip()
            
            if ": " in line and "FOUND" in line:
                # Format: /path/to/file: VirusName FOUND
                parts = line.rsplit(":", 1)
                if len(parts) == 2:
                    filepath = parts[0]
                    virus = parts[1].replace("FOUND", "").strip()
                    result.infected_files.append(filepath)
                    result.virus_names.append(virus)
                    
            elif "Scanned files:" in line:
                try:
                    count = int(line.split()[-1])
                    result.files_scanned = count
                except ValueError:
                    pass
    
    async def update_database(self) -> bool:
        """Update ClamAV virus database."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "freshclam",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.wait(), timeout=120.0)
            return proc.returncode == 0
        except Exception as e:
            logger.error(f"Database update failed: {e}")
            return False
