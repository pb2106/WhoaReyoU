"""
Tests for the Namespace Analysis module.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch
from wru.analysis.namespace import NamespaceAnalyzer, AnalysisResult
from wru.analysis.filesystem import FilesystemAnalyzer, FileInfo


class TestFilesystemAnalyzer:
    """Test filesystem analysis without actual devices."""
    
    def test_suspicious_extension_detection(self):
        """Suspicious file extensions should be identified."""
        analyzer = FilesystemAnalyzer()
        
        suspicious = analyzer.SUSPICIOUS_EXTENSIONS
        
        assert ".exe" in suspicious
        assert ".bat" in suspicious
        assert ".ps1" in suspicious
        assert ".scr" in suspicious
    
    @pytest.mark.asyncio
    async def test_analyze_directory(self):
        """Should analyze directory contents."""
        analyzer = FilesystemAnalyzer()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            (Path(tmpdir) / "normal.txt").write_text("Hello")
            (Path(tmpdir) / "suspicious.exe").write_text("MZ" + "\x00" * 100)
            (Path(tmpdir) / ".hidden").write_text("secret")
            
            report = await analyzer.analyze(Path(tmpdir))
            
            assert report.total_files == 3
            assert len(report.hidden_files) >= 1
            assert ".txt" in report.extension_breakdown
            assert ".exe" in report.extension_breakdown
    
    @pytest.mark.asyncio
    async def test_entropy_calculation(self):
        """Entropy calculation should work."""
        analyzer = FilesystemAnalyzer()
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            # Low entropy: repeated pattern
            f.write(b"AAAA" * 1000)
            f.flush()
            
            entropy = await analyzer._calculate_entropy(Path(f.name))
            
            # Single character has 0 entropy
            assert entropy == 0.0
            
        os.unlink(f.name)
    
    @pytest.mark.asyncio
    async def test_high_entropy_detection(self):
        """High entropy files (random data) should be detected."""
        analyzer = FilesystemAnalyzer()
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            # High entropy: random bytes
            import random
            f.write(bytes([random.randint(0, 255) for _ in range(10000)]))
            f.flush()
            
            entropy = await analyzer._calculate_entropy(Path(f.name))
            
            # Random data should have high entropy (close to 8)
            assert entropy > 7.0
            
        os.unlink(f.name)


class TestNamespaceAnalyzer:
    """Test namespace isolation (basic unit tests)."""
    
    def test_autorun_patterns(self):
        """Should identify autorun patterns."""
        # Use temp directory to avoid permission issues
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = NamespaceAnalyzer(mount_base=Path(tmpdir))
            
            assert "autorun.inf" in analyzer.AUTORUN_PATTERNS
            assert "autorun.exe" in analyzer.AUTORUN_PATTERNS
    
    def test_suspicious_extensions(self):
        """Should have comprehensive suspicious extension list."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = NamespaceAnalyzer(mount_base=Path(tmpdir))
            
            assert ".exe" in analyzer.SUSPICIOUS_EXTENSIONS
            assert ".vbs" in analyzer.SUSPICIOUS_EXTENSIONS
            assert ".ps1" in analyzer.SUSPICIOUS_EXTENSIONS


class TestAnalysisResult:
    """Test AnalysisResult dataclass."""
    
    def test_to_dict(self):
        """Should serialize to dictionary."""
        result = AnalysisResult(
            device_path=Path("/dev/sda1"),
            is_safe=False,
            threats_found=["Malware.Test"],
            autorun_detected=True,
            malware_detected=True,
            file_count=100,
            total_size_bytes=1024000,
            filesystem_type="vfat"
        )
        
        d = result.to_dict()
        
        assert d["is_safe"] is False
        assert "Malware.Test" in d["threats_found"]
        assert d["autorun_detected"] is True
        assert d["malware_detected"] is True
        assert d["file_count"] == 100
    
    def test_safe_result(self):
        """Clean device should be marked safe."""
        result = AnalysisResult(
            device_path=Path("/dev/sda1"),
            is_safe=True,
            threats_found=[],
            autorun_detected=False,
            malware_detected=False
        )
        
        assert result.is_safe is True
        assert len(result.threats_found) == 0
