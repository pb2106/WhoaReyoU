"""
Filesystem Analysis Module

Analyzes filesystem contents for suspicious patterns
without executing any files.
"""

import os
import asyncio
import logging
import hashlib
import struct
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class FileInfo:
    """Information about a single file."""
    path: str
    size: int
    extension: str
    mime_type: str = ""
    sha256: str = ""
    is_executable: bool = False
    is_hidden: bool = False
    entropy: float = 0.0
    suspicious_score: int = 0
    suspicious_reasons: list[str] = field(default_factory=list)


@dataclass
class FilesystemReport:
    """Complete filesystem analysis report."""
    root_path: Path
    total_files: int = 0
    total_size_bytes: int = 0
    suspicious_files: list[FileInfo] = field(default_factory=list)
    executables_found: list[FileInfo] = field(default_factory=list)
    hidden_files: list[str] = field(default_factory=list)
    extension_breakdown: dict[str, int] = field(default_factory=dict)
    high_entropy_files: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "root_path": str(self.root_path),
            "total_files": self.total_files,
            "total_size_bytes": self.total_size_bytes,
            "suspicious_count": len(self.suspicious_files),
            "executables_count": len(self.executables_found),
            "hidden_count": len(self.hidden_files),
            "extensions": self.extension_breakdown,
        }


class FilesystemAnalyzer:
    """
    Analyzes filesystem for suspicious content.
    
    Does NOT execute any files - purely static analysis.
    """
    
    # Suspicious file extensions
    SUSPICIOUS_EXTENSIONS = {
        ".exe": 10, ".scr": 15, ".pif": 15, ".bat": 8, ".cmd": 8,
        ".com": 10, ".vbs": 12, ".vbe": 12, ".js": 8, ".jse": 10,
        ".wsf": 10, ".wsh": 10, ".ps1": 10, ".psm1": 10, ".msi": 8,
        ".dll": 5, ".sys": 5, ".hta": 12, ".cpl": 10, ".msc": 8,
        ".lnk": 6, ".jar": 8, ".reg": 8,
    }
    
    # High entropy threshold (packed/encrypted files)
    ENTROPY_THRESHOLD = 7.5
    
    def __init__(self, max_file_size: int = 50 * 1024 * 1024):
        self._max_file_size = max_file_size
        self._magic_available = False
        
        try:
            import magic
            self._magic = magic.Magic(mime=True)
            self._magic_available = True
        except ImportError:
            logger.warning("python-magic not available, MIME detection disabled")
    
    async def analyze(self, path: Path) -> FilesystemReport:
        """Analyze filesystem at given path."""
        report = FilesystemReport(root_path=path)
        
        try:
            for root, dirs, files in os.walk(path):
                for filename in files:
                    filepath = Path(root) / filename
                    
                    try:
                        await self._analyze_file(filepath, path, report)
                    except Exception as e:
                        logger.debug(f"Cannot analyze {filepath}: {e}")
                        
        except Exception as e:
            logger.error(f"Filesystem analysis failed: {e}")
            
        return report
    
    async def _analyze_file(
        self,
        filepath: Path,
        root: Path,
        report: FilesystemReport
    ) -> None:
        """Analyze a single file."""
        try:
            stat = filepath.stat()
        except OSError:
            return
            
        report.total_files += 1
        report.total_size_bytes += stat.st_size
        
        # Get relative path
        rel_path = str(filepath.relative_to(root))
        
        # Extension tracking
        ext = filepath.suffix.lower()
        report.extension_breakdown[ext] = report.extension_breakdown.get(ext, 0) + 1
        
        # Check for hidden files
        if filepath.name.startswith("."):
            report.hidden_files.append(rel_path)
        
        # Create file info
        info = FileInfo(
            path=rel_path,
            size=stat.st_size,
            extension=ext,
            is_hidden=filepath.name.startswith("."),
        )
        
        # Check suspicious extension
        if ext in self.SUSPICIOUS_EXTENSIONS:
            info.suspicious_score += self.SUSPICIOUS_EXTENSIONS[ext]
            info.suspicious_reasons.append(f"Suspicious extension: {ext}")
            info.is_executable = True
            report.executables_found.append(info)
        
        # Get MIME type if magic available
        if self._magic_available and stat.st_size < self._max_file_size:
            try:
                info.mime_type = self._magic.from_file(str(filepath))
                
                # Check for executable MIME types
                if "executable" in info.mime_type or "application/x-dosexec" in info.mime_type:
                    if not info.is_executable:
                        info.is_executable = True
                        info.suspicious_score += 5
                        info.suspicious_reasons.append(f"Executable MIME: {info.mime_type}")
                        report.executables_found.append(info)
                        
            except Exception:
                pass
        
        # Check entropy for packed/encrypted files (skip large files)
        if stat.st_size > 1024 and stat.st_size < 5 * 1024 * 1024:
            try:
                entropy = await self._calculate_entropy(filepath)
                info.entropy = entropy
                
                if entropy > self.ENTROPY_THRESHOLD:
                    info.suspicious_score += 10
                    info.suspicious_reasons.append(f"High entropy: {entropy:.2f}")
                    report.high_entropy_files.append(rel_path)
                    
            except Exception:
                pass
        
        # Add to suspicious list if score is high enough
        if info.suspicious_score >= 10:
            report.suspicious_files.append(info)
    
    async def _calculate_entropy(self, filepath: Path) -> float:
        """
        Calculate Shannon entropy of a file.
        
        High entropy (>7.5) often indicates encryption or packing.
        """
        import math
        
        byte_counts = [0] * 256
        total_bytes = 0
        
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                    
                for byte in chunk:
                    byte_counts[byte] += 1
                total_bytes += len(chunk)
                
                # Limit analysis to first 1MB
                if total_bytes >= 1024 * 1024:
                    break
        
        if total_bytes == 0:
            return 0.0
        
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / total_bytes
                entropy -= p * math.log2(p)
        
        return entropy
    
    async def hash_file(self, filepath: Path) -> str:
        """Calculate SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                sha256.update(chunk)
        
        return sha256.hexdigest()
    
    async def detect_pe_header(self, filepath: Path) -> bool:
        """Check if file has PE header (Windows executable)."""
        try:
            with open(filepath, "rb") as f:
                # Check DOS header
                if f.read(2) != b"MZ":
                    return False
                    
                # Get PE header offset
                f.seek(60)
                pe_offset = struct.unpack("<I", f.read(4))[0]
                
                # Check PE signature
                f.seek(pe_offset)
                return f.read(4) == b"PE\x00\x00"
                
        except Exception:
            return False
