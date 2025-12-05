"""
Forensic Logger Module

Provides structured JSON logging for USB security events.
Supports SIEM integration and incident investigation.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, Any
from collections import deque

from wru.core.authorization import DeviceInfo

logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    """A structured log entry."""
    timestamp: str
    event_type: str
    severity: str  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    details: dict
    device_id: Optional[str] = None
    bus_id: Optional[str] = None
    threat_score: Optional[int] = None
    decision: Optional[str] = None
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(asdict(self), separators=(",", ":"))
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


class ForensicLogger:
    """
    Structured logging for forensic analysis and SIEM integration.
    
    Features:
    - JSON-formatted log files
    - Separate files for events vs incidents
    - Automatic log rotation
    - Async file writing for performance
    - In-memory buffer for recent events
    """
    
    def __init__(
        self,
        log_dir: Path,
        buffer_size: int = 1000,
        max_file_size: int = 50 * 1024 * 1024  # 50MB
    ):
        self._log_dir = log_dir
        self._buffer_size = buffer_size
        self._max_file_size = max_file_size
        
        # In-memory buffer for recent events
        self._recent_events: deque[LogEntry] = deque(maxlen=buffer_size)
        
        # File handles
        self._event_file: Optional[Any] = None
        self._incident_file: Optional[Any] = None
        
        # Write queue for async logging
        self._write_queue: asyncio.Queue[LogEntry] = asyncio.Queue()
        self._writer_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def start(self) -> None:
        """Initialize logging system."""
        # Create log directory
        self._log_dir.mkdir(parents=True, exist_ok=True)
        
        # Start async writer
        self._running = True
        self._writer_task = asyncio.create_task(self._writer_loop())
        
        logger.info(f"Forensic logger started, writing to {self._log_dir}")
    
    async def stop(self) -> None:
        """Shutdown logging system."""
        self._running = False
        
        # Drain remaining queue
        while not self._write_queue.empty():
            await asyncio.sleep(0.1)
        
        if self._writer_task:
            self._writer_task.cancel()
            try:
                await self._writer_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Forensic logger stopped")
    
    async def _writer_loop(self) -> None:
        """Async loop that writes log entries to files."""
        while self._running:
            try:
                try:
                    entry = await asyncio.wait_for(
                        self._write_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                await self._write_entry(entry)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error writing log entry: {e}")
    
    async def _write_entry(self, entry: LogEntry) -> None:
        """Write a log entry to the appropriate file."""
        # Determine target file
        if entry.severity in ("ERROR", "CRITICAL"):
            filename = "incidents.jsonl"
        else:
            filename = "events.jsonl"
        
        filepath = self._log_dir / filename
        
        # Check for rotation
        await self._rotate_if_needed(filepath)
        
        # Write entry
        try:
            import aiofiles
            async with aiofiles.open(filepath, "a") as f:
                await f.write(entry.to_json() + "\n")
        except ImportError:
            # Fallback to sync write
            with open(filepath, "a") as f:
                f.write(entry.to_json() + "\n")
    
    async def _rotate_if_needed(self, filepath: Path) -> None:
        """Rotate log file if it exceeds max size."""
        if not filepath.exists():
            return
            
        try:
            size = filepath.stat().st_size
            if size > self._max_file_size:
                # Rotate: rename current file with timestamp
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                rotated = filepath.with_suffix(f".{timestamp}.jsonl")
                filepath.rename(rotated)
                logger.info(f"Rotated log file to {rotated}")
        except Exception as e:
            logger.warning(f"Log rotation failed: {e}")
    
    def _create_entry(
        self,
        event_type: str,
        severity: str,
        details: dict,
        device_info: Optional[DeviceInfo] = None,
        threat_score: Optional[int] = None,
        decision: Optional[str] = None
    ) -> LogEntry:
        """Create a log entry."""
        entry = LogEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            severity=severity,
            details=details,
            threat_score=threat_score,
            decision=decision,
        )
        
        if device_info:
            entry.device_id = device_info.device_id
            entry.bus_id = device_info.bus_id
            entry.details["device"] = {
                "vendor_id": device_info.vendor_id,
                "product_id": device_info.product_id,
                "serial": device_info.serial,
                "manufacturer": device_info.manufacturer,
                "product": device_info.product,
                "interfaces": device_info.interfaces,
            }
        
        return entry
    
    async def log_event(
        self,
        event_type: str,
        details: dict,
        severity: str = "INFO"
    ) -> None:
        """Log a general event."""
        entry = self._create_entry(
            event_type=event_type,
            severity=severity,
            details=details
        )
        
        self._recent_events.append(entry)
        await self._write_queue.put(entry)
    
    async def log_device_event(
        self,
        event_type: str,
        device: DeviceInfo,
        assessment: Optional[Any] = None,
        severity: str = "INFO"
    ) -> None:
        """Log a device-related event."""
        details = {}
        threat_score = None
        decision = None
        
        if assessment:
            threat_score = assessment.score
            decision = assessment.decision.name
            details["reasons"] = assessment.reasons
            
            # Escalate severity based on threat score
            if assessment.score >= 70:
                severity = "CRITICAL"
            elif assessment.score >= 40:
                severity = "WARNING"
        
        entry = self._create_entry(
            event_type=event_type,
            severity=severity,
            details=details,
            device_info=device,
            threat_score=threat_score,
            decision=decision
        )
        
        self._recent_events.append(entry)
        await self._write_queue.put(entry)
    
    async def log_incident(
        self,
        incident_type: str,
        device: Optional[DeviceInfo],
        details: dict,
        severity: str = "CRITICAL"
    ) -> None:
        """Log a security incident."""
        entry = self._create_entry(
            event_type=f"incident_{incident_type}",
            severity=severity,
            details=details,
            device_info=device
        )
        
        self._recent_events.append(entry)
        await self._write_queue.put(entry)
        
        # Also log to system logger for immediate visibility
        logger.critical(f"SECURITY INCIDENT: {incident_type} - {details}")
    
    def get_recent_events(
        self,
        count: int = 100,
        event_type: Optional[str] = None,
        device_id: Optional[str] = None
    ) -> list[LogEntry]:
        """Get recent events from buffer."""
        events = list(self._recent_events)
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        if device_id:
            events = [e for e in events if e.device_id == device_id]
        
        return events[-count:]
    
    async def search_logs(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        device_id: Optional[str] = None,
        limit: int = 1000
    ) -> list[dict]:
        """Search log files for matching entries."""
        results = []
        
        for log_file in self._log_dir.glob("*.jsonl"):
            try:
                with open(log_file) as f:
                    for line in f:
                        if len(results) >= limit:
                            break
                            
                        try:
                            entry = json.loads(line)
                            
                            # Apply filters
                            if event_type and entry.get("event_type") != event_type:
                                continue
                            if severity and entry.get("severity") != severity:
                                continue
                            if device_id and entry.get("device_id") != device_id:
                                continue
                            
                            if start_time:
                                entry_time = datetime.fromisoformat(
                                    entry["timestamp"].replace("Z", "+00:00")
                                )
                                if entry_time < start_time:
                                    continue
                            
                            if end_time:
                                entry_time = datetime.fromisoformat(
                                    entry["timestamp"].replace("Z", "+00:00")
                                )
                                if entry_time > end_time:
                                    continue
                            
                            results.append(entry)
                            
                        except json.JSONDecodeError:
                            continue
                            
            except Exception as e:
                logger.warning(f"Error reading log file {log_file}: {e}")
        
        return results
    
    def get_stats(self) -> dict:
        """Get logging statistics."""
        return {
            "buffer_size": len(self._recent_events),
            "queue_size": self._write_queue.qsize(),
            "log_directory": str(self._log_dir),
        }
