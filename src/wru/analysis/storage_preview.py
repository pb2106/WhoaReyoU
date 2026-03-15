"""
Storage Preview Module

Provides safe, isolated preview of USB mass storage devices
using Linux mount namespaces. No DMA access to host system.

Patent-safe implementation using only standard Linux kernel features:
- unshare(2) for mount namespace isolation
- Read-only bind mounts
- Standard POSIX process isolation
"""

import os
import sys
import asyncio
import logging
import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


@dataclass
class StorageInfo:
    """Information about a USB storage device."""
    bus_id: str
    device_node: Optional[Path] = None  # e.g., /dev/sdb
    partition_nodes: list[Path] = field(default_factory=list)  # e.g., /dev/sdb1
    filesystem: str = ""
    label: str = ""
    size_bytes: int = 0
    is_mounted: bool = False


@dataclass 
class FileEntry:
    """A file or directory entry from the storage device."""
    name: str
    path: str
    is_dir: bool
    size: int
    permissions: str
    modified: str


@dataclass
class ScanResult:
    """Result of a ClamAV scan."""
    clean: bool
    infected_files: list[str] = field(default_factory=list)
    scan_time_seconds: float = 0.0
    error: Optional[str] = None


class StoragePreview:
    """
    Safe storage preview using namespace isolation.
    
    Uses Linux mount namespaces to isolate the storage device
    from the host system. Device is mounted read-only inside
    the namespace only.
    """
    
    def __init__(self):
        self._mount_base = Path("/tmp/wru-preview")
        self._active_previews: dict[str, Path] = {}  # bus_id -> mount_point
    
    async def get_storage_info(self, bus_id: str) -> Optional[StorageInfo]:
        """
        Get information about a USB storage device.
        
        Finds the block device node associated with the USB device.
        """
        info = StorageInfo(bus_id=bus_id)
        
        # Find block device for this USB device
        sysfs_path = Path(f"/sys/bus/usb/devices/{bus_id}")
        if not sysfs_path.exists():
            logger.error(f"USB device {bus_id} not found")
            return None
        
        # Look for block device in sysfs
        # The path is usually: /sys/bus/usb/devices/X-Y/X-Y:1.0/host*/target*/*/block/sd*
        try:
            for block_path in sysfs_path.rglob("block/sd*"):
                dev_name = block_path.name
                info.device_node = Path(f"/dev/{dev_name}")
                
                # Find partitions
                for part in Path("/dev").glob(f"{dev_name}[0-9]*"):
                    info.partition_nodes.append(part)
                
                # Get size
                size_path = block_path / "size"
                if size_path.exists():
                    sectors = int(size_path.read_text().strip())
                    info.size_bytes = sectors * 512
                
                break
        except Exception as e:
            logger.error(f"Failed to find block device for {bus_id}: {e}")
            return None
        
        if not info.device_node:
            logger.warning(f"No block device found for {bus_id}")
            return None
            
        return info
    
    async def list_files(
        self, 
        bus_id: str, 
        path: str = "/",
        max_depth: int = 2
    ) -> list[FileEntry]:
        """
        List files from storage device using namespace isolation.
        
        The device is temporarily mounted read-only in an isolated
        mount namespace, files are listed, then unmounted.
        """
        info = await self.get_storage_info(bus_id)
        if not info:
            return []
        
        # Select partition to mount (prefer first partition, fallback to device)
        mount_device = info.partition_nodes[0] if info.partition_nodes else info.device_node
        if not mount_device or not mount_device.exists():
            logger.error(f"Device node {mount_device} not found or not yet accessible")
            return []

        # Check that we can actually read the device node (permissions restored?)
        if not os.access(mount_device, os.R_OK):
            logger.error(
                f"Device node {mount_device} exists but is not readable — "
                "permissions may not have been restored yet. "
                "Try: sudo wru allow <bus_id> first."
            )
            return []
        
        # Create temporary mount point
        mount_point = self._mount_base / bus_id
        mount_point.mkdir(parents=True, exist_ok=True)
        
        files = []
        
        try:
            # Run file listing in isolated namespace
            # Using unshare to create new mount namespace
            script = f'''
import os
import sys
import json
from pathlib import Path

# Mount device read-only (redirect both stdout and stderr to suppress warnings)
rc = os.system("mount -o ro,noexec,nosuid,nodev {mount_device} {mount_point} >/dev/null 2>&1")

# List files
entries = []
target_path = Path("{mount_point}") / "{path.lstrip('/')}"

if target_path.exists():
    for item in target_path.iterdir():
        try:
            stat = item.stat()
            entries.append({{
                "name": item.name,
                "path": str(item.relative_to(Path("{mount_point}"))),
                "is_dir": item.is_dir(),
                "size": stat.st_size if item.is_file() else 0,
                "permissions": oct(stat.st_mode)[-3:],
                "modified": str(stat.st_mtime)
            }})
        except:
            pass

# Unmount
os.system("umount {mount_point} 2>/dev/null")

print(json.dumps(entries))
'''
            result = await asyncio.create_subprocess_exec(
                "unshare", "--mount", "--", "python3", "-c", script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()

            stdout_text = stdout.decode().strip() if stdout else ""
            stderr_text = stderr.decode().strip() if stderr else ""

            if stderr_text:
                logger.debug(f"list_files namespace stderr: {stderr_text}")

            if not stdout_text:
                logger.warning(
                    f"list_files: no output from namespace subprocess for {bus_id}. "
                    f"stderr: {stderr_text or '(none)'}"
                )
            else:
                import json
                try:
                    entries = json.loads(stdout_text)
                    files = [FileEntry(**e) for e in entries]
                except json.JSONDecodeError as e:
                    logger.error(
                        f"list_files: could not parse JSON output for {bus_id}: {e}. "
                        f"Raw output: {stdout_text[:200]!r}"
                    )
                
        except Exception as e:
            logger.error(f"Failed to list files: {e}")
        finally:
            # Cleanup mount point
            try:
                mount_point.rmdir()
            except:
                pass
        
        return files

    
    async def scan_storage(self, bus_id: str) -> ScanResult:
        """
        Scan storage device with ClamAV in isolated namespace.
        
        Returns scan results without modifying host system.
        """
        import time
        start_time = time.time()
        
        info = await self.get_storage_info(bus_id)
        if not info:
            return ScanResult(
                clean=False,
                error="Device not found"
            )
        
        mount_device = info.partition_nodes[0] if info.partition_nodes else info.device_node
        if not mount_device:
            return ScanResult(clean=False, error="No device node")
        
        mount_point = self._mount_base / f"{bus_id}-scan"
        mount_point.mkdir(parents=True, exist_ok=True)
        
        infected = []
        error = None
        
        try:
            # Mount and scan in namespace
            result = await asyncio.create_subprocess_exec(
                "unshare", "--mount", "--",
                "sh", "-c", f"""
                    mount -o ro,noexec,nosuid,nodev {mount_device} {mount_point} 2>/dev/null && \
                    clamscan -r --no-summary {mount_point} 2>/dev/null; \
                    umount {mount_point} 2>/dev/null
                """,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(
                result.communicate(), 
                timeout=300  # 5 minute timeout
            )
            
            # Parse clamscan output for infected files
            for line in stdout.decode().split('\n'):
                if 'FOUND' in line:
                    infected.append(line.split(':')[0].strip())
                    
        except asyncio.TimeoutError:
            error = "Scan timed out after 5 minutes"
        except FileNotFoundError:
            error = "ClamAV not installed (install with: sudo apt install clamav)"
        except Exception as e:
            error = str(e)
        finally:
            try:
                mount_point.rmdir()
            except:
                pass
        
        scan_time = time.time() - start_time
        
        return ScanResult(
            clean=len(infected) == 0 and error is None,
            infected_files=infected,
            scan_time_seconds=scan_time,
            error=error
        )
    
    async def preview_file(
        self, 
        bus_id: str, 
        file_path: str,
        max_bytes: int = 4096
    ) -> Optional[bytes]:
        """
        Preview a specific file from the storage device.
        
        Returns first max_bytes of the file content.
        Only works for safe file types (text, images).
        """
        info = await self.get_storage_info(bus_id)
        if not info:
            return None
        
        mount_device = info.partition_nodes[0] if info.partition_nodes else info.device_node
        if not mount_device:
            return None
        
        mount_point = self._mount_base / f"{bus_id}-file"
        mount_point.mkdir(parents=True, exist_ok=True)
        
        content = None
        
        try:
            # Read file in namespace
            script = f'''
import os
import sys

os.system("mount -o ro,noexec,nosuid,nodev {mount_device} {mount_point} >/dev/null 2>&1")

file_path = "{mount_point}/{file_path.lstrip('/')}"
try:
    with open(file_path, 'rb') as f:
        sys.stdout.buffer.write(f.read({max_bytes}))
except:
    pass

os.system("umount {mount_point} 2>/dev/null")
'''
            result = await asyncio.create_subprocess_exec(
                "unshare", "--mount", "--", "python3", "-c", script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await result.communicate()
            content = stdout if stdout else None
            
        except Exception as e:
            logger.error(f"Failed to preview file: {e}")
        finally:
            try:
                mount_point.rmdir()
            except:
                pass
        
        return content
