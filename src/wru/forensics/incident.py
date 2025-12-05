"""
Incident Response Module

Automated response to high-severity USB security incidents.
"""

import asyncio
import logging
import subprocess
import json
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from wru.core.authorization import DeviceInfo

logger = logging.getLogger(__name__)


@dataclass
class Incident:
    """Security incident record."""
    id: str
    timestamp: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    incident_type: str
    device_id: Optional[str]
    bus_id: Optional[str]
    threat_score: int
    description: str
    actions_taken: list[str] = field(default_factory=list)
    status: str = "OPEN"  # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "incident_type": self.incident_type,
            "device_id": self.device_id,
            "bus_id": self.bus_id,
            "threat_score": self.threat_score,
            "description": self.description,
            "actions_taken": self.actions_taken,
            "status": self.status,
        }


class IncidentResponder:
    """
    Automated incident response for USB security events.
    
    Response actions based on severity:
    - MEDIUM: Log and notify
    - HIGH: Lock screens, isolate device
    - CRITICAL: Full lockdown, snapshot system state
    """
    
    def __init__(
        self,
        incident_dir: Optional[Path] = None,
        enable_lockdown: bool = True
    ):
        self._incident_dir = incident_dir or Path("/var/log/wru/incidents")
        self._incident_dir.mkdir(parents=True, exist_ok=True)
        self._enable_lockdown = enable_lockdown
        
        # Track active incidents
        self._active_incidents: dict[str, Incident] = {}
        self._incident_counter = 0
    
    def _generate_incident_id(self) -> str:
        """Generate unique incident ID."""
        self._incident_counter += 1
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"WRU-{timestamp}-{self._incident_counter:04d}"
    
    async def create_incident(
        self,
        incident_type: str,
        device: Optional[DeviceInfo],
        threat_score: int,
        description: str
    ) -> Incident:
        """Create and respond to a new incident."""
        # Determine severity
        if threat_score >= 90:
            severity = "CRITICAL"
        elif threat_score >= 70:
            severity = "HIGH"
        elif threat_score >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        incident = Incident(
            id=self._generate_incident_id(),
            timestamp=datetime.now(timezone.utc).isoformat(),
            severity=severity,
            incident_type=incident_type,
            device_id=device.device_id if device else None,
            bus_id=device.bus_id if device else None,
            threat_score=threat_score,
            description=description
        )
        
        logger.critical(
            f"INCIDENT CREATED: {incident.id} - "
            f"{severity} - {incident_type} - Score: {threat_score}"
        )
        
        # Store incident
        self._active_incidents[incident.id] = incident
        
        # Execute response based on severity
        await self._execute_response(incident, device)
        
        # Save incident to file
        await self._save_incident(incident)
        
        return incident
    
    async def _execute_response(
        self,
        incident: Incident,
        device: Optional[DeviceInfo]
    ) -> None:
        """Execute automated response actions."""
        actions = []
        
        if incident.severity == "CRITICAL":
            # Full lockdown
            if self._enable_lockdown:
                await self._lock_all_screens()
                actions.append("locked_all_screens")
            
            await self._snapshot_system_state(incident)
            actions.append("snapshot_created")
            
            # Could add: network isolation, alert security team, etc.
            
        elif incident.severity == "HIGH":
            # Partial response
            if self._enable_lockdown:
                await self._lock_all_screens()
                actions.append("locked_all_screens")
        
        # Common actions for all severities
        await self._log_to_syslog(incident)
        actions.append("logged_to_syslog")
        
        incident.actions_taken = actions
    
    async def _lock_all_screens(self) -> None:
        """Lock all user screens."""
        methods = [
            ["loginctl", "lock-sessions"],
            ["gnome-screensaver-command", "-l"],
            ["xdg-screensaver", "lock"],
            ["qdbus", "org.freedesktop.ScreenSaver", "/ScreenSaver", "Lock"],
        ]
        
        for cmd in methods:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                await asyncio.wait_for(proc.wait(), timeout=2.0)
                if proc.returncode == 0:
                    logger.info(f"Screen locked using: {cmd[0]}")
                    return
            except Exception:
                continue
        
        logger.warning("Could not lock screen with any method")
    
    async def _snapshot_system_state(self, incident: Incident) -> None:
        """Capture system state for forensic analysis."""
        snapshot_dir = self._incident_dir / incident.id
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Capture USB device info
            proc = await asyncio.create_subprocess_exec(
                "lsusb", "-v",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            (snapshot_dir / "lsusb.txt").write_bytes(stdout)
            
            # Capture dmesg
            proc = await asyncio.create_subprocess_exec(
                "dmesg", "--time-format=iso",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            (snapshot_dir / "dmesg.txt").write_bytes(stdout)
            
            # Capture network state
            proc = await asyncio.create_subprocess_exec(
                "ss", "-tunapl",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            (snapshot_dir / "network.txt").write_bytes(stdout)
            
            # Capture process list
            proc = await asyncio.create_subprocess_exec(
                "ps", "auxf",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            (snapshot_dir / "processes.txt").write_bytes(stdout)
            
            logger.info(f"System snapshot saved to {snapshot_dir}")
            
        except Exception as e:
            logger.error(f"Failed to capture system state: {e}")
    
    async def _log_to_syslog(self, incident: Incident) -> None:
        """Log incident to syslog."""
        try:
            import syslog
            syslog.syslog(
                syslog.LOG_CRIT if incident.severity == "CRITICAL" else syslog.LOG_WARNING,
                f"WRU {incident.severity}: {incident.id} - {incident.incident_type} - "
                f"Device: {incident.device_id} - Score: {incident.threat_score}"
            )
        except Exception as e:
            logger.warning(f"Could not log to syslog: {e}")
    
    async def _save_incident(self, incident: Incident) -> None:
        """Save incident to file."""
        incident_file = self._incident_dir / f"{incident.id}.json"
        try:
            with open(incident_file, "w") as f:
                json.dump(incident.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save incident: {e}")
    
    async def update_incident(
        self,
        incident_id: str,
        status: Optional[str] = None,
        notes: Optional[str] = None
    ) -> Optional[Incident]:
        """Update an existing incident."""
        incident = self._active_incidents.get(incident_id)
        
        if not incident:
            # Try to load from file
            incident_file = self._incident_dir / f"{incident_id}.json"
            if incident_file.exists():
                with open(incident_file) as f:
                    data = json.load(f)
                    incident = Incident(**data)
            else:
                return None
        
        if status:
            incident.status = status
            incident.actions_taken.append(f"status_changed_to_{status}")
        
        if notes:
            incident.actions_taken.append(f"note: {notes}")
        
        await self._save_incident(incident)
        return incident
    
    def get_active_incidents(self) -> list[Incident]:
        """Get all active (non-resolved) incidents."""
        return [
            i for i in self._active_incidents.values()
            if i.status not in ("RESOLVED", "FALSE_POSITIVE")
        ]
    
    async def list_all_incidents(self) -> list[Incident]:
        """List all incidents from files."""
        incidents = []
        
        for incident_file in self._incident_dir.glob("WRU-*.json"):
            try:
                with open(incident_file) as f:
                    data = json.load(f)
                    incidents.append(Incident(**data))
            except Exception as e:
                logger.warning(f"Failed to load incident {incident_file}: {e}")
        
        return sorted(incidents, key=lambda i: i.timestamp, reverse=True)
