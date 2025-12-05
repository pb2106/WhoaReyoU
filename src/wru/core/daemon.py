"""
WRU Main Policy Daemon

The central orchestrator for the USB security system.
Coordinates all security layers and enforces policies.
"""

import asyncio
import signal
import logging
import json
from pathlib import Path
from typing import Optional
from dataclasses import dataclass
from enum import Enum, auto

from wru.core.authorization import DeviceAuthorization, DeviceInfo
from wru.core.event_handler import USBEventHandler, USBEvent, DeviceAction
from wru.threat.engine import ThreatEngine, ThreatDecision, ThreatAssessment
from wru.forensics.logger import ForensicLogger

logger = logging.getLogger(__name__)


class DaemonState(Enum):
    """Daemon operational states."""
    STOPPED = auto()
    STARTING = auto()
    RUNNING = auto()
    STOPPING = auto()


@dataclass
class DaemonConfig:
    """Configuration for the WRU daemon."""
    
    # Paths
    config_dir: Path = Path("/etc/wru")
    log_dir: Path = Path("/var/log/wru")
    run_dir: Path = Path("/run/wru")
    
    # Policy thresholds
    auto_allow_threshold: int = 19
    quarantine_threshold: int = 39
    analyze_threshold: int = 69
    # Score 70+ is auto-deny
    
    # Behavior
    enable_hid_monitoring: bool = True
    enable_network_isolation: bool = True
    enable_vm_analysis: bool = False  # Optional, requires QEMU
    enable_clamav: bool = True
    
    # Logging
    log_level: str = "INFO"
    json_logging: bool = True
    
    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "DaemonConfig":
        """Load configuration from file."""
        config = cls()
        
        if config_path is None:
            config_path = config.config_dir / "daemon.json"
            
        if config_path.exists():
            try:
                with open(config_path) as f:
                    data = json.load(f)
                    
                for key, value in data.items():
                    if hasattr(config, key):
                        if key.endswith("_dir"):
                            setattr(config, key, Path(value))
                        else:
                            setattr(config, key, value)
                            
                logger.info(f"Loaded configuration from {config_path}")
            except Exception as e:
                logger.warning(f"Failed to load config: {e}, using defaults")
                
        return config


class WRUDaemon:
    """
    Main WRU Policy Daemon.
    
    Orchestrates all security layers:
    - Layer 0: Hub authorization defaults
    - Layer 1: Immediate deauthorization + chmod
    - Layer 2: Threat intelligence scoring
    - Layer 3: Isolated analysis (namespace/VM)
    - Layer 4: Runtime monitoring (HID/network)
    - Layer 5: Policy decisions
    - Layer 6: Forensic logging
    """
    
    def __init__(self, config: Optional[DaemonConfig] = None):
        self.config = config or DaemonConfig()
        self.state = DaemonState.STOPPED
        
        # Core components
        self._authorization = DeviceAuthorization()
        self._event_handler = USBEventHandler(self._authorization)
        self._threat_engine = ThreatEngine()
        self._forensic_logger = ForensicLogger(self.config.log_dir)
        
        # Runtime monitors (lazy-loaded)
        self._hid_monitors: dict[str, object] = {}  # bus_id -> HIDMonitor
        self._network_isolators: dict[str, object] = {}  # interface -> NetworkIsolator
        
        # Asyncio components
        self._main_loop: Optional[asyncio.AbstractEventLoop] = None
        self._shutdown_event = asyncio.Event()
        
        # Device tracking
        self._pending_decisions: dict[str, ThreatAssessment] = {}  # bus_id -> assessment
        self._authorized_devices: set[str] = set()  # Set of authorized device IDs
    
    async def start(self) -> None:
        """Start the WRU daemon."""
        if self.state != DaemonState.STOPPED:
            logger.warning(f"Cannot start daemon in state: {self.state}")
            return
            
        self.state = DaemonState.STARTING
        logger.info("Starting WRU daemon...")
        
        try:
            # Get event loop reference
            self._main_loop = asyncio.get_running_loop()
            
            # Set up shutdown handlers
            self._setup_signal_handlers()
            
            # Layer 0: Set hub authorization defaults
            await self._configure_hub_defaults()
            
            # Initialize forensic logger
            await self._forensic_logger.start()
            
            # Load threat engine databases
            await self._threat_engine.load_databases(self.config.config_dir)
            
            # Register event callback
            self._event_handler.register_callback(self._on_usb_event)
            
            # Start event handler
            await self._event_handler.start()
            
            # Process any already-connected devices
            await self._process_existing_devices()
            
            self.state = DaemonState.RUNNING
            logger.info("WRU daemon started successfully")
            
            # Log startup event
            await self._forensic_logger.log_event(
                event_type="daemon_started",
                details={"config": str(self.config.config_dir)}
            )
            
        except Exception as e:
            self.state = DaemonState.STOPPED
            logger.error(f"Failed to start daemon: {e}", exc_info=True)
            raise
    
    async def stop(self) -> None:
        """Stop the WRU daemon."""
        if self.state == DaemonState.STOPPED:
            return
            
        self.state = DaemonState.STOPPING
        logger.info("Stopping WRU daemon...")
        
        try:
            # Stop event handler
            await self._event_handler.stop()
            
            # Stop all HID monitors
            for monitor in self._hid_monitors.values():
                if hasattr(monitor, 'stop'):
                    await monitor.stop()
            self._hid_monitors.clear()
            
            # Stop all network isolators
            for isolator in self._network_isolators.values():
                if hasattr(isolator, 'cleanup'):
                    await isolator.cleanup()
            self._network_isolators.clear()
            
            # Log shutdown event
            await self._forensic_logger.log_event(
                event_type="daemon_stopped",
                details={}
            )
            
            # Stop forensic logger
            await self._forensic_logger.stop()
            
            self.state = DaemonState.STOPPED
            logger.info("WRU daemon stopped")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}", exc_info=True)
            self.state = DaemonState.STOPPED
    
    async def run_forever(self) -> None:
        """Run the daemon until shutdown signal."""
        await self.start()
        
        try:
            # Wait for shutdown signal
            await self._shutdown_event.wait()
        finally:
            await self.stop()
    
    def _setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""
        if self._main_loop is None:
            return
            
        for sig in (signal.SIGTERM, signal.SIGINT):
            self._main_loop.add_signal_handler(
                sig,
                lambda: asyncio.create_task(self._handle_shutdown())
            )
    
    async def _handle_shutdown(self) -> None:
        """Handle shutdown signal."""
        logger.info("Received shutdown signal")
        self._shutdown_event.set()
    
    async def _configure_hub_defaults(self) -> None:
        """Configure USB hubs to deny devices by default (Layer 0)."""
        count = self._authorization.set_hub_defaults()
        logger.info(f"Configured {count} USB hubs with authorized_default=0")
    
    async def _process_existing_devices(self) -> None:
        """Process devices that were connected before daemon started."""
        devices = self._authorization.get_all_devices()
        logger.info(f"Processing {len(devices)} existing USB devices")
        
        for device in devices:
            # Create synthetic event for existing device
            await self._evaluate_device(device)
    
    async def _on_usb_event(
        self,
        event: USBEvent,
        device_info: Optional[DeviceInfo]
    ) -> None:
        """
        Handle USB events from the event handler.
        
        This is the main policy enforcement point.
        """
        if event.action == DeviceAction.ADD:
            if device_info:
                await self._evaluate_device(device_info)
            else:
                logger.warning(f"No device info for {event.bus_id}")
                
        elif event.action == DeviceAction.REMOVE:
            await self._handle_device_removal(event.bus_id)
    
    async def _evaluate_device(self, device: DeviceInfo) -> None:
        """
        Evaluate a device and make policy decision.
        
        Implements Layers 2-5: Threat analysis and policy decision.
        """
        logger.info(
            f"Evaluating device: {device.bus_id} "
            f"({device.vendor_id}:{device.product_id}) "
            f"- {device.manufacturer or 'Unknown'} {device.product or 'Unknown'}"
        )
        
        # Layer 2: Threat intelligence scoring
        assessment = await self._threat_engine.analyze(device)
        
        logger.info(
            f"Threat assessment for {device.bus_id}: "
            f"score={assessment.score}, decision={assessment.decision.name}"
        )
        
        # Log the assessment
        await self._forensic_logger.log_device_event(
            event_type="device_evaluated",
            device=device,
            assessment=assessment
        )
        
        # Layer 5: Make policy decision
        await self._enforce_decision(device, assessment)
    
    async def _enforce_decision(
        self,
        device: DeviceInfo,
        assessment: ThreatAssessment
    ) -> None:
        """
        Enforce the threat assessment decision.
        
        Decision matrix:
        - ALLOW (score 0-19): Auto-authorize
        - QUARANTINE (score 20-39): Wait for user approval
        - ANALYZE (score 40-69): Deep analysis, then decide
        - DENY (score 70+): Block permanently
        """
        match assessment.decision:
            case ThreatDecision.ALLOW:
                await self._authorize_device(device, assessment)
                
            case ThreatDecision.QUARANTINE:
                await self._quarantine_device(device, assessment)
                
            case ThreatDecision.ANALYZE:
                await self._analyze_device(device, assessment)
                
            case ThreatDecision.DENY:
                await self._deny_device(device, assessment)
    
    async def _authorize_device(
        self,
        device: DeviceInfo,
        assessment: ThreatAssessment
    ) -> None:
        """Authorize a trusted device."""
        logger.info(f"Auto-authorizing trusted device: {device.bus_id}")
        
        if await self._authorization.authorize(device.bus_id):
            self._authorized_devices.add(device.device_id)
            
            # Start runtime monitoring if enabled
            if self.config.enable_hid_monitoring and device.has_hid:
                await self._start_hid_monitoring(device)
                
            if self.config.enable_network_isolation and device.has_network:
                await self._apply_network_monitoring(device)
            
            await self._forensic_logger.log_device_event(
                event_type="device_authorized",
                device=device,
                assessment=assessment
            )
    
    async def _quarantine_device(
        self,
        device: DeviceInfo,
        assessment: ThreatAssessment
    ) -> None:
        """Keep device quarantined, await user decision."""
        logger.warning(
            f"Device quarantined (score={assessment.score}): {device.bus_id} - "
            f"Reasons: {', '.join(assessment.reasons)}"
        )
        
        # Store pending decision
        self._pending_decisions[device.bus_id] = assessment
        
        await self._forensic_logger.log_device_event(
            event_type="device_quarantined",
            device=device,
            assessment=assessment
        )
        
        # TODO: Notify user via D-Bus or GUI
    
    async def _analyze_device(
        self,
        device: DeviceInfo,
        assessment: ThreatAssessment
    ) -> None:
        """Send device for deep analysis."""
        logger.warning(
            f"Device requires analysis (score={assessment.score}): {device.bus_id}"
        )
        
        # Store pending decision
        self._pending_decisions[device.bus_id] = assessment
        
        await self._forensic_logger.log_device_event(
            event_type="device_analyzing",
            device=device,
            assessment=assessment
        )
        
        # Layer 3: Isolated analysis
        if device.has_storage and self.config.enable_clamav:
            # Will be implemented in analysis module
            logger.info(f"Scheduling namespace analysis for {device.bus_id}")
            
        if self.config.enable_vm_analysis:
            logger.info(f"Scheduling VM analysis for {device.bus_id}")
    
    async def _deny_device(
        self,
        device: DeviceInfo,
        assessment: ThreatAssessment
    ) -> None:
        """Deny a dangerous device."""
        logger.error(
            f"DENYING dangerous device (score={assessment.score}): {device.bus_id} - "
            f"Reasons: {', '.join(assessment.reasons)}"
        )
        
        # Ensure device stays deauthorized
        await self._authorization.deauthorize(device.bus_id)
        
        await self._forensic_logger.log_device_event(
            event_type="device_denied",
            device=device,
            assessment=assessment
        )
        
        # High-severity incident response
        if assessment.score >= 90:
            await self._trigger_incident_response(device, assessment)
    
    async def _handle_device_removal(self, bus_id: str) -> None:
        """Handle device removal."""
        logger.info(f"Device removed: {bus_id}")
        
        # Clean up any monitoring
        if bus_id in self._hid_monitors:
            monitor = self._hid_monitors.pop(bus_id)
            if hasattr(monitor, 'stop'):
                await monitor.stop()
                
        # Clean up pending decisions
        self._pending_decisions.pop(bus_id, None)
        
        await self._forensic_logger.log_event(
            event_type="device_removed",
            details={"bus_id": bus_id}
        )
    
    async def _start_hid_monitoring(self, device: DeviceInfo) -> None:
        """Start HID keystroke monitoring for a device."""
        # Will be implemented when HIDMonitor is added
        logger.debug(f"HID monitoring requested for {device.bus_id}")
    
    async def _apply_network_monitoring(self, device: DeviceInfo) -> None:
        """Apply network isolation/monitoring for a device."""
        # Will be implemented when NetworkIsolator is added
        logger.debug(f"Network monitoring requested for {device.bus_id}")
    
    async def _trigger_incident_response(
        self,
        device: DeviceInfo,
        assessment: ThreatAssessment
    ) -> None:
        """Trigger high-severity incident response."""
        logger.critical(
            f"HIGH SEVERITY INCIDENT: {device.bus_id} (score={assessment.score})"
        )
        
        await self._forensic_logger.log_event(
            event_type="incident_triggered",
            details={
                "device_id": device.device_id,
                "bus_id": device.bus_id,
                "score": assessment.score,
                "reasons": assessment.reasons,
            }
        )
        
        # TODO: Lock screens, notify security team, etc.
    
    # Public API for CLI and external tools
    
    async def list_devices(self) -> list[dict]:
        """List all connected USB devices with their status."""
        devices = self._authorization.get_all_devices()
        result = []
        
        for device in devices:
            assessment = await self._threat_engine.analyze(device)
            result.append({
                "bus_id": device.bus_id,
                "vendor_id": device.vendor_id,
                "product_id": device.product_id,
                "manufacturer": device.manufacturer,
                "product": device.product,
                "serial": device.serial,
                "authorized": device.authorized,
                "threat_score": assessment.score,
                "threat_decision": assessment.decision.name,
            })
            
        return result
    
    async def authorize_device(self, bus_id: str) -> bool:
        """Manually authorize a device."""
        device = self._authorization.get_device_info(bus_id)
        if not device:
            logger.error(f"Device not found: {bus_id}")
            return False
            
        success = await self._authorization.authorize(bus_id)
        
        if success:
            self._pending_decisions.pop(bus_id, None)
            self._authorized_devices.add(device.device_id)
            
            await self._forensic_logger.log_event(
                event_type="manual_authorization",
                details={"bus_id": bus_id, "device_id": device.device_id}
            )
            
        return success
    
    async def deny_device(self, bus_id: str) -> bool:
        """Manually deny a device."""
        device = self._authorization.get_device_info(bus_id)
        if not device:
            logger.error(f"Device not found: {bus_id}")
            return False
            
        success = await self._authorization.deauthorize(bus_id)
        
        if success:
            self._pending_decisions.pop(bus_id, None)
            
            await self._forensic_logger.log_event(
                event_type="manual_denial",
                details={"bus_id": bus_id, "device_id": device.device_id}
            )
            
        return success


def main():
    """Entry point for the daemon."""
    import sys
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
        ]
    )
    
    logger.info("WRU Daemon starting...")
    
    try:
        config = DaemonConfig.load()
        daemon = WRUDaemon(config)
        asyncio.run(daemon.run_forever())
    except KeyboardInterrupt:
        logger.info("Daemon interrupted by user")
    except Exception as e:
        logger.error(f"Daemon failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
