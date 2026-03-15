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
from wru.forensics.incident import IncidentResponder
from wru.runtime.hid_monitor import HIDMonitorManager, HIDAlert
from wru.runtime.network_isolator import NetworkIsolatorManager
from wru.analysis.namespace import NamespaceAnalyzer
from wru.analysis.vm import VMAnalyzer
from wru.analysis.storage_preview import StoragePreview

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

    # Behaviour flags
    enable_hid_monitoring: bool = True
    enable_network_isolation: bool = True
    enable_vm_analysis: bool = True   # ON: detects BadUSB / HID injection
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
                        setattr(config, key, Path(value) if key.endswith("_dir") else value)
                logger.info(f"Loaded configuration from {config_path}")
            except Exception as e:
                logger.warning(f"Failed to load config: {e}, using defaults")

        return config


class WRUDaemon:
    """
    Main WRU Policy Daemon.

    Layers:
      0 – Hub authorization defaults (authorized_default=0)
      1 – Immediate deauthorization + chmod 000
      2 – Threat intelligence scoring (heuristics + CVE + patterns)
      3 – Isolated analysis (mount namespace / QEMU-VM)
      4 – Runtime monitoring (HID keystroke stats / network namespace)
      5 – Policy decisions (allow / quarantine / deny)
      6 – Forensic logging + incident response
    """

    def __init__(self, config: Optional[DaemonConfig] = None):
        self.config = config or DaemonConfig()
        self.state = DaemonState.STOPPED

        # ── Core components ──────────────────────────────────────────────
        self._authorization = DeviceAuthorization()
        self._event_handler = USBEventHandler(self._authorization)
        self._threat_engine = ThreatEngine()
        self._forensic_logger = ForensicLogger(self.config.log_dir)
        self._incident_responder = IncidentResponder(
            incident_dir=self.config.log_dir / "incidents"
        )

        # ── Runtime monitors ─────────────────────────────────────────────
        self._hid_manager = HIDMonitorManager()
        self._network_manager = NetworkIsolatorManager()

        # ── Analysis components ──────────────────────────────────────────
        self._namespace_analyzer = NamespaceAnalyzer()
        self._vm_analyzer = VMAnalyzer()

        # ── Asyncio ──────────────────────────────────────────────────────
        self._main_loop: Optional[asyncio.AbstractEventLoop] = None
        self._shutdown_event = asyncio.Event()

        # ── State tracking ───────────────────────────────────────────────
        self._pending_decisions: dict[str, ThreatAssessment] = {}
        self._authorized_devices: set[str] = set()
        self._hid_monitors: dict[str, object] = {}
        self._network_isolators: dict[str, object] = {}

        # ── Notification socket ──────────────────────────────────────────
        self._notification_server: Optional[asyncio.Server] = None
        self._notification_clients: list[asyncio.StreamWriter] = []

        # ── Policy lists ─────────────────────────────────────────────────
        self._allowlist: list[dict] = []
        self._blocklist: list[dict] = []

        # ── VM readiness ─────────────────────────────────────────────────
        # Set when the VM preflight task completes (success or failure).
        # _analyze_device waits on this so it never uses the VM before it
        # is confirmed ready, but startup is never blocked.
        self._vm_ready_event: asyncio.Event = asyncio.Event()

    # ─────────────────────────────── Lifecycle ───────────────────────────

    async def start(self) -> None:
        """Start the WRU daemon."""
        if self.state != DaemonState.STOPPED:
            logger.warning(f"Cannot start daemon in state: {self.state}")
            return

        self.state = DaemonState.STARTING
        logger.info("Starting WRU daemon...")

        try:
            self._main_loop = asyncio.get_running_loop()
            self._setup_signal_handlers()

            # Layer 0
            await self._configure_hub_defaults()

            await self._forensic_logger.start()
            await self._threat_engine.load_databases(self.config.config_dir)
            await self._load_policy()

            await self._start_notification_server()

            self._event_handler.register_callback(self._on_usb_event)
            await self._event_handler.start()
            await self._process_existing_devices()

            self.state = DaemonState.RUNNING
            logger.info("WRU daemon started successfully")
            await self._forensic_logger.log_event(
                event_type="daemon_started",
                details={"config": str(self.config.config_dir)}
            )

            # VM preflight runs in the background so startup is instant.
            # _vm_ready_event is set when it completes (success or failure).
            if self.config.enable_vm_analysis:
                asyncio.create_task(
                    self._vm_preflight_background(),
                    name="wru-vm-preflight",
                )

        except Exception as e:
            self.state = DaemonState.STOPPED
            logger.error(f"Failed to start daemon: {e}", exc_info=True)
            raise

    async def stop(self) -> None:
        """Stop the WRU daemon gracefully."""
        if self.state == DaemonState.STOPPED:
            return

        self.state = DaemonState.STOPPING
        logger.info("Stopping WRU daemon...")

        try:
            await self._event_handler.stop()
            await self._hid_manager.stop_all()
            await self._network_manager.cleanup_all()
            self._hid_monitors.clear()
            self._network_isolators.clear()

            if self._notification_server:
                self._notification_server.close()
                await self._notification_server.wait_closed()
            for writer in list(self._notification_clients):
                try:
                    writer.close()
                except Exception:
                    pass
            self._notification_clients.clear()

            await self._forensic_logger.log_event(event_type="daemon_stopped", details={})
            await self._forensic_logger.stop()
        except Exception as e:
            logger.error(f"Error during shutdown: {e}", exc_info=True)
        finally:
            self.state = DaemonState.STOPPED
            logger.info("WRU daemon stopped")

    async def run_forever(self) -> None:
        """Run the daemon until shutdown signal."""
        await self.start()
        try:
            await self._shutdown_event.wait()
        finally:
            await self.stop()

    # ─────────────────────────── Setup helpers ───────────────────────────

    def _setup_signal_handlers(self) -> None:
        if self._main_loop is None:
            return
        for sig in (signal.SIGTERM, signal.SIGINT):
            self._main_loop.add_signal_handler(
                sig, lambda: asyncio.create_task(self._handle_shutdown())
            )

    async def _handle_shutdown(self) -> None:
        logger.info("Received shutdown signal")
        self._shutdown_event.set()

    async def _configure_hub_defaults(self) -> None:
        count = self._authorization.set_hub_defaults()
        logger.info(f"Configured {count} USB hubs with authorized_default=0")

    async def _process_existing_devices(self) -> None:
        devices = self._authorization.get_all_devices()
        logger.info(f"Processing {len(devices)} existing USB devices")
        for device in devices:
            await self._evaluate_device(device)

    async def _vm_preflight_background(self) -> None:
        """
        Background task: ensure the VM image exists, then signal _vm_ready_event.
        Runs after the daemon is already RUNNING, so startup is never blocked.
        """
        try:
            await self._ensure_vm_image()
        finally:
            # Always signal — even on failure — so _analyze_device never
            # blocks forever waiting for a preflight that already gave up.
            self._vm_ready_event.set()

    async def _ensure_vm_image(self) -> None:
        """Blocking preflight: create VM image if missing. Disables VM analysis on failure."""
        if await self._vm_analyzer.check_available():
            logger.info("VM analysis image ready")
            return

        logger.info(
            "VM analysis image not found at expected path – creating now "
            "(downloads Alpine Linux ~55 MB, may take a few minutes)"
        )
        try:
            from wru.analysis.vm import create_vm_image
            success = await create_vm_image()
            if success:
                logger.info("VM image created successfully – VM analysis enabled")
            else:
                logger.warning(
                    "VM image creation failed (no internet / missing tools?) – "
                    "VM analysis disabled for this session"
                )
                self.config.enable_vm_analysis = False
        except Exception as e:
            logger.warning(f"VM image setup error: {e} – VM analysis disabled")
            self.config.enable_vm_analysis = False

    async def _load_policy(self) -> None:
        """Load allow / block lists from policy.json."""
        policy_path = self.config.config_dir / "policy.json"
        if not policy_path.exists():
            logger.info("No policy.json found, starting with empty lists")
            return
        try:
            with open(policy_path) as f:
                policy = json.load(f)
            self._allowlist = policy.get("allowlist", [])
            self._blocklist = policy.get("blocklist", [])
            logger.info(
                f"Loaded policy: {len(self._allowlist)} allowlist, "
                f"{len(self._blocklist)} blocklist entries"
            )
        except Exception as e:
            logger.warning(f"Failed to load policy.json: {e}")

    # ─────────────────────── Notification socket ─────────────────────────

    async def _start_notification_server(self) -> None:
        """Start Unix-domain socket server for tray applet notifications."""
        socket_path = self.config.run_dir / "notify.sock"
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        if socket_path.exists():
            socket_path.unlink()

        self._notification_server = await asyncio.start_unix_server(
            self._on_tray_client_connected,
            path=str(socket_path)
        )
        socket_path.chmod(0o666)
        logger.info(f"Notification server ready at {socket_path}")

    async def _on_tray_client_connected(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> None:
        """Accept a tray applet connection and keep it open."""
        self._notification_clients.append(writer)
        logger.debug("Tray applet connected")
        try:
            await reader.read(1)          # wait until client disconnects
        except Exception:
            pass
        finally:
            if writer in self._notification_clients:
                self._notification_clients.remove(writer)
            try:
                writer.close()
            except Exception:
                pass

    async def _broadcast_notification(
        self, title: str, message: str, urgency: str = "critical"
    ) -> None:
        """Push JSON notification to all connected tray applet clients."""
        payload = json.dumps({"title": title, "message": message, "urgency": urgency}) + "\n"
        dead: list[asyncio.StreamWriter] = []
        for writer in list(self._notification_clients):
            try:
                writer.write(payload.encode())
                await writer.drain()
            except Exception:
                dead.append(writer)
        for w in dead:
            if w in self._notification_clients:
                self._notification_clients.remove(w)

    async def _notify_user(
        self, message: str, title: str = "WRU Security Alert", urgency: str = "critical"
    ) -> None:
        """Notify via tray socket AND notify-send fallback."""
        await self._broadcast_notification(title, message, urgency)
        asyncio.create_task(self._notify_send_fallback(title, message, urgency))

    async def _notify_send_fallback(self, title: str, message: str, urgency: str) -> None:
        """
        Write notification to /run/wru/notifications.jsonl as a fallback.

        The tray applet reads from the socket (primary channel). This file
        acts as a secondary channel for tools that watch /run/wru/.
        It does NOT call sudo/runuser – both are blocked by ProtectSystem=full.
        """
        try:
            notif_file = self.config.run_dir / "notifications.jsonl"
            import time
            entry = json.dumps({
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "title": title,
                "message": message,
                "urgency": urgency,
            }) + "\n"
            with open(notif_file, "a") as f:
                f.write(entry)
            # Keep file small (last 100 notifications)
            await self._trim_notification_file(notif_file)
        except Exception as e:
            logger.debug(f"Notification file write failed: {e}")

    async def _trim_notification_file(self, path: Path) -> None:
        """Keep only the last 100 lines of the notification file."""
        try:
            lines = path.read_text().splitlines()
            if len(lines) > 100:
                path.write_text("\n".join(lines[-100:]) + "\n")
        except Exception:
            pass

    # ─────────────────────────── Event handling ──────────────────────────

    async def _on_usb_event(
        self, event: USBEvent, device_info: Optional[DeviceInfo]
    ) -> None:
        if event.action == DeviceAction.ADD:
            if device_info:
                await self._evaluate_device(device_info)
            else:
                logger.warning(f"No device info for {event.bus_id}")
        elif event.action == DeviceAction.REMOVE:
            await self._handle_device_removal(event.bus_id)

    async def _evaluate_device(self, device: DeviceInfo) -> None:
        """Full evaluation pipeline for a newly connected device."""
        logger.info(
            f"Evaluating: {device.bus_id} "
            f"({device.vendor_id}:{device.product_id}) "
            f"– {device.manufacturer or '?'} {device.product or '?'}"
        )

        # Blocklist → instant deny
        if self._threat_engine.check_blocklist(device, self._blocklist):
            logger.warning(f"{device.bus_id} matched blocklist")
            assessment = ThreatAssessment(
                device_id=device.device_id, score=100,
                decision=ThreatDecision.DENY, reasons=["Device in blocklist"]
            )
            await self._enforce_decision(device, assessment)
            return

        # Allowlist → instant authorize
        if self._threat_engine.check_allowlist(device, self._allowlist):
            logger.info(f"{device.bus_id} matched allowlist, auto-authorizing")
            assessment = ThreatAssessment(
                device_id=device.device_id, score=0,
                decision=ThreatDecision.ALLOW, reasons=["Device in allowlist"]
            )
            await self._enforce_decision(device, assessment)
            return

        # Full threat analysis
        assessment = await self._threat_engine.analyze(device)
        logger.info(
            f"Threat score {device.bus_id}: {assessment.score} → {assessment.decision.name}"
        )
        await self._forensic_logger.log_device_event(
            event_type="device_evaluated", device=device, assessment=assessment
        )
        await self._enforce_decision(device, assessment)

    async def _enforce_decision(
        self, device: DeviceInfo, assessment: ThreatAssessment
    ) -> None:
        match assessment.decision:
            case ThreatDecision.ALLOW:
                await self._authorize_device(device, assessment)
            case ThreatDecision.QUARANTINE:
                await self._quarantine_device(device, assessment)
            case ThreatDecision.ANALYZE:
                await self._analyze_device(device, assessment)
            case ThreatDecision.DENY:
                await self._deny_device(device, assessment)

    # ─────────────────────────── Policy actions ──────────────────────────

    async def _authorize_device(
        self, device: DeviceInfo, assessment: ThreatAssessment
    ) -> None:
        logger.info(f"Authorizing trusted device: {device.bus_id}")
        if await self._authorization.authorize(device.bus_id):
            self._authorized_devices.add(device.device_id)
            if self.config.enable_hid_monitoring and device.has_hid:
                await self._start_hid_monitoring(device)
            if self.config.enable_network_isolation and device.has_network:
                await self._apply_network_monitoring(device)
            await self._forensic_logger.log_device_event(
                event_type="device_authorized", device=device, assessment=assessment
            )

    async def _quarantine_device(
        self, device: DeviceInfo, assessment: ThreatAssessment
    ) -> None:
        device_name = device.product or device.manufacturer or "USB device"
        logger.warning(
            f"Quarantined (score={assessment.score}): {device.bus_id} "
            f"– {', '.join(assessment.reasons)}"
        )
        self._pending_decisions[device.bus_id] = assessment
        await self._forensic_logger.log_device_event(
            event_type="device_quarantined", device=device, assessment=assessment
        )
        await self._notify_user(
            message=(
                f"Device: {device_name}\n"
                f"Bus: {device.bus_id}\n"
                f"Risk score: {assessment.score}/100\n"
                f"To approve: wru allow {device.bus_id}\n"
                f"To deny:    wru deny {device.bus_id}"
            ),
            title="🔒 USB Device Quarantined",
            urgency="normal",
        )

    async def _analyze_device(
        self, device: DeviceInfo, assessment: ThreatAssessment
    ) -> None:
        """Layer 3 deep analysis – runs async tasks."""
        logger.warning(f"Deep analysis (score={assessment.score}): {device.bus_id}")
        self._pending_decisions[device.bus_id] = assessment
        await self._forensic_logger.log_device_event(
            event_type="device_analyzing", device=device, assessment=assessment
        )
        await self._notify_user(
            message=(
                f"Device: {device.product or device.manufacturer or 'Unknown'}\n"
                f"Scanning for threats – this may take ~30 s."
            ),
            title="🔍 Analyzing USB Device",
            urgency="normal",
        )

        if device.has_storage and self.config.enable_clamav:
            asyncio.create_task(self._run_namespace_analysis(device, assessment))
        elif self.config.enable_vm_analysis:
            # Wait briefly for the background VM preflight to finish.
            # This covers devices plugged in during a fast boot.
            if not self._vm_ready_event.is_set():
                logger.info("Waiting for VM preflight to complete before analyzing device…")
                try:
                    await asyncio.wait_for(self._vm_ready_event.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    logger.warning(
                        f"VM preflight not ready after 5 s – skipping VM analysis for {device.bus_id}"
                    )
                    await self._deny_device(device, assessment)
                    return
            asyncio.create_task(self._run_vm_analysis(device, assessment))
        else:
            logger.warning(f"No analysis method available for {device.bus_id}, denying.")
            await self._deny_device(device, assessment)

    async def _deny_device(
        self, device: DeviceInfo, assessment: ThreatAssessment
    ) -> None:
        logger.error(
            f"DENYING device (score={assessment.score}): {device.bus_id} "
            f"– {', '.join(assessment.reasons)}"
        )
        await self._authorization.deauthorize(device.bus_id)
        await self._forensic_logger.log_device_event(
            event_type="device_denied", device=device, assessment=assessment
        )
        if assessment.score >= 90:
            await self._trigger_incident_response(device, assessment)

    # ─────────────────────── Layer 3: Analysis tasks ─────────────────────

    async def _run_namespace_analysis(
        self, device: DeviceInfo, assessment: ThreatAssessment
    ) -> None:
        """Run namespace-isolated ClamAV scan on storage device."""
        try:
            storage = StoragePreview()
            info = await storage.get_storage_info(device.bus_id)
            if not info or not info.device_node:
                logger.warning(f"No storage node for {device.bus_id}")
                if self.config.enable_vm_analysis:
                    await self._run_vm_analysis(device, assessment)
                return

            device_path = (
                info.partition_nodes[0] if info.partition_nodes else info.device_node
            )
            result = await self._namespace_analyzer.analyze(device_path)
            await self._forensic_logger.log_event(
                event_type="namespace_analysis_complete",
                details=result.to_dict(),
                severity="WARNING" if not result.is_safe else "INFO",
            )
            if not result.is_safe:
                threats_str = ", ".join(result.threats_found[:3])
                logger.error(f"Threats found on {device.bus_id}: {threats_str}")
                await self._deny_device(device, assessment)
                await self._notify_user(
                    message=(
                        f"Device: {device.product or 'USB drive'}\n"
                        f"Threats: {threats_str}"
                    ),
                    title="🚨 Malware Detected – Device Blocked",
                )
            else:
                logger.info(f"Namespace analysis clean for {device.bus_id}, authorizing")
                await self._authorize_device(device, assessment)
                await self._notify_user(
                    message=f"Device: {device.product or 'USB drive'} – all clear.",
                    title="✅ USB Device Approved",
                    urgency="low",
                )
        except Exception as e:
            logger.error(f"Namespace analysis failed for {device.bus_id}: {e}", exc_info=True)

    async def _run_vm_analysis(
        self, device: DeviceInfo, assessment: ThreatAssessment
    ) -> None:
        """Run QEMU VM behavioral analysis (BadUSB / HID injection detection)."""
        try:
            result = await self._vm_analyzer.analyze(
                vendor_id=device.vendor_id,
                product_id=device.product_id,
            )
            await self._forensic_logger.log_event(
                event_type="vm_analysis_complete",
                details=result.to_dict(),
                severity="WARNING" if result.anomalies else "INFO",
            )
            if result.hid_injection_detected or result.descriptor_mutation_detected:
                logger.error(f"VM analysis: attack on {device.bus_id}: {result.anomalies}")
                await self._deny_device(device, assessment)
                await self._notify_user(
                    message=(
                        f"Device: {device.product or 'Unknown'}\n"
                        f"Findings: {', '.join(result.anomalies[:3])}"
                    ),
                    title="🚨 BadUSB Attack Detected – Device Blocked",
                )
            elif result.success:
                logger.info(f"VM analysis clean for {device.bus_id}, authorizing")
                await self._authorize_device(device, assessment)
                await self._notify_user(
                    message=f"Device: {device.product or 'USB device'} – passed VM analysis.",
                    title="✅ USB Device Approved",
                    urgency="low",
                )
            else:
                # Inconclusive (e.g. QEMU error) – log quietly, don't spam per-device
                logger.debug(f"VM analysis inconclusive for {device.bus_id}: {result.error}")
        except Exception as e:
            logger.error(f"VM analysis failed for {device.bus_id}: {e}", exc_info=True)

    # ─────────────────────── Layer 4: Runtime monitors ───────────────────

    async def _start_hid_monitoring(self, device: DeviceInfo) -> None:
        """Start evdev-based HID monitoring for BadUSB keystroke injection."""
        event_paths = self._find_hid_event_devices(device.bus_id)
        if not event_paths:
            logger.debug(f"No HID event nodes found yet for {device.bus_id}")
            return

        async def _on_hid_alert(alert: HIDAlert) -> None:
            await self._handle_hid_alert(device, alert)

        for event_path in event_paths:
            monitor = await self._hid_manager.start_monitor(event_path, callback=_on_hid_alert)
            self._hid_monitors[device.bus_id] = monitor
            logger.info(f"HID monitor started: {event_path} → {device.bus_id}")

    def _find_hid_event_devices(self, bus_id: str) -> list[str]:
        """Discover /dev/input/eventX nodes for a USB device via sysfs."""
        found: list[str] = []
        sysfs = self._authorization.SYSFS_USB_BASE / bus_id
        try:
            for p in sysfs.rglob("event*"):
                dev_node = Path("/dev/input") / p.name
                if dev_node.exists():
                    found.append(str(dev_node))
        except Exception as e:
            logger.debug(f"sysfs HID search failed for {bus_id}: {e}")
        return found

    async def _handle_hid_alert(self, device: DeviceInfo, alert: HIDAlert) -> None:
        """Respond to BadUSB detection from the HID monitor."""
        logger.critical(
            f"BadUSB detected on {device.bus_id}: "
            f"rate={alert.keystroke_rate:.1f}/s, CV={alert.coefficient_of_variation:.3f}"
        )
        await self._authorization.deauthorize(device.bus_id)
        await self._incident_responder.create_incident(
            incident_type="badusb_hid_injection",
            device=device,
            threat_score=95,
            description=(
                f"Keystroke injection detected: rate={alert.keystroke_rate:.1f}/s, "
                f"CV={alert.coefficient_of_variation:.3f}"
            ),
        )
        await self._notify_user(
            message=(
                f"Device: {device.product or device.manufacturer or 'Unknown'}\n"
                f"Keystroke rate: {alert.keystroke_rate:.0f}/s\n"
                f"Device has been blocked."
            ),
            title="⚡ BadUSB Attack Blocked!",
        )

    async def _apply_network_monitoring(self, device: DeviceInfo) -> None:
        """Isolate USB network adapters in a dedicated network namespace."""
        interface = self._find_network_interface(device.bus_id)
        if not interface:
            logger.debug(f"No network interface for {device.bus_id}")
            return
        isolator = await self._network_manager.isolate_interface(interface)
        self._network_isolators[interface] = isolator
        logger.info(f"Network interface {interface} isolated for {device.bus_id}")

        # Quick traffic analysis (async, non-blocking)
        asyncio.create_task(self._analyse_network_traffic(device, interface, isolator))

    def _find_network_interface(self, bus_id: str) -> Optional[str]:
        """Find the kernel network interface created for a USB device."""
        sysfs = self._authorization.SYSFS_USB_BASE / bus_id
        try:
            for p in sysfs.rglob("net/*"):
                if p.is_dir():
                    return p.name
        except Exception as e:
            logger.debug(f"sysfs net search failed for {bus_id}: {e}")
        return None

    async def _analyse_network_traffic(
        self, device: DeviceInfo, interface: str, isolator: object
    ) -> None:
        """Capture initial traffic and flag suspicious activity."""
        try:
            if not hasattr(isolator, "analyze_traffic"):
                return
            analysis = await isolator.analyze_traffic()
            await self._forensic_logger.log_event(
                event_type="network_traffic_analysis",
                details=analysis.to_dict(),
                severity="WARNING" if analysis.is_suspicious else "INFO",
            )
            if analysis.is_suspicious:
                logger.warning(
                    f"Suspicious traffic from {interface}: {analysis.suspicious_reasons}"
                )
                await self._notify_user(
                    message=(
                        f"Interface: {interface}\n"
                        f"Reasons: {', '.join(analysis.suspicious_reasons[:2])}"
                    ),
                    title="⚠️ Suspicious USB Network Activity",
                )
        except Exception as e:
            logger.error(f"Network traffic analysis failed: {e}", exc_info=True)

    # ──────────────────────── Layer 6: Incidents ─────────────────────────

    async def _trigger_incident_response(
        self, device: DeviceInfo, assessment: ThreatAssessment
    ) -> None:
        """Create a formal incident record and execute automated response."""
        logger.critical(f"HIGH SEVERITY INCIDENT: {device.bus_id} (score={assessment.score})")

        incident = await self._incident_responder.create_incident(
            incident_type="high_threat_usb_device",
            device=device,
            threat_score=assessment.score,
            description=(
                f"Score {assessment.score}/100. "
                f"Reasons: {', '.join(assessment.reasons[:5])}"
            ),
        )
        await self._forensic_logger.log_event(
            event_type="incident_triggered",
            details={
                "incident_id": incident.id,
                "device_id": device.device_id,
                "bus_id": device.bus_id,
                "score": assessment.score,
                "reasons": assessment.reasons,
            },
        )
        await self._notify_user(
            message=(
                f"Incident: {incident.id}\n"
                f"Device: {device.product or 'Unknown'}\n"
                f"Score: {assessment.score}/100\n"
                f"Check: sudo wru incidents"
            ),
            title="🚨 CRITICAL USB Threat – Incident Created",
        )

    # ──────────────── Device removal / cleanup ────────────────────────────

    async def _handle_device_removal(self, bus_id: str) -> None:
        logger.info(f"Device removed: {bus_id}")
        if bus_id in self._hid_monitors:
            monitor = self._hid_monitors.pop(bus_id)
            await self._hid_manager.stop_monitor(
                next(
                    (k for k, v in self._hid_manager._monitors.items() if v is monitor),
                    ""
                )
            )
        self._pending_decisions.pop(bus_id, None)
        await self._forensic_logger.log_event(
            event_type="device_removed", details={"bus_id": bus_id}
        )

    # ──────────────────── Public API (CLI / external) ─────────────────────

    async def list_devices(self) -> list[dict]:
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
                details={"bus_id": bus_id, "device_id": device.device_id},
            )
            # Notify the tray applet that the device is now accessible so
            # the user knows to open the file manager / check Disks.
            block_nodes = self._authorization._find_all_block_nodes(bus_id)
            device_label = device.product or device.manufacturer or bus_id
            if block_nodes:
                node_str = "  ".join(str(n) for n in block_nodes)
                msg = (
                    f"Device: {device_label}\n"
                    f"Block node(s): {node_str}\n"
                    f"The device should now appear in your file manager."
                )
            else:
                msg = (
                    f"Device: {device_label}\n"
                    f"Authorization complete. If it is a storage device,\n"
                    f"open your file manager or run: udisksctl mount -b /dev/sdX"
                )
            await self._notify_user(
                message=msg,
                title="✅ USB Device Authorized – Ready to Mount",
                urgency="normal",
            )
        return success

    async def deny_device(self, bus_id: str) -> bool:
        device = self._authorization.get_device_info(bus_id)
        if not device:
            logger.error(f"Device not found: {bus_id}")
            return False
        success = await self._authorization.deauthorize(bus_id)
        if success:
            self._pending_decisions.pop(bus_id, None)
            await self._forensic_logger.log_event(
                event_type="manual_denial",
                details={"bus_id": bus_id, "device_id": device.device_id},
            )
        return success


def main():
    """Entry point for the daemon."""
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    logger.info("WRU Daemon starting...")
    try:
        config = DaemonConfig.load()
        daemon = WRUDaemon(config)
        asyncio.run(daemon.run_forever())
    except KeyboardInterrupt:
        logger.info("Daemon interrupted by user")
    except Exception as e:
        logger.error(f"Daemon crashed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
