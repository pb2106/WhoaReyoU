"""
WRU Tray Applet

System-tray icon that connects to the WRU daemon's Unix notification socket
and shows desktop alerts when USB devices are quarantined, blocked, or need
user action. Shows Approve / Deny buttons for quarantined devices.

Run from a graphical session:
    wru-tray          # via console entry-point
    python -m wru.tray.applet
"""

import asyncio
import json
import logging
import subprocess
import threading
import socket
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

SOCKET_PATH = Path("/run/wru/notify.sock")
RECONNECT_DELAY = 3.0  # seconds between reconnect attempts


# ─────────────────────────── Icon drawing ─────────────────────────────────────

def _make_icon_image(color: str = "#1565C0") -> "Image":
    """Draw a shield icon for the system tray."""
    try:
        from PIL import Image, ImageDraw

        size = 64
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        cx = size // 2
        shield = [
            (cx, 4),
            (size - 6, 14),
            (size - 6, 34),
            (cx, size - 4),
            (6, 34),
            (6, 14),
        ]
        draw.polygon(shield, fill=color, outline="#0D47A1")
        draw.text((cx - 9, 20), "W", fill="white")
        return img

    except ImportError:
        try:
            from PIL import Image
            return Image.new("RGBA", (1, 1), (21, 101, 192, 255))
        except ImportError:
            return None


# ─────────────────────── Desktop notification helper ──────────────────────────

def _notify_send(title: str, message: str, urgency: str = "critical") -> None:
    """
    Show a desktop notification via libnotify (notify-send).
    Falls back silently if not available.
    """
    urgency_map = {"low": "low", "normal": "normal", "critical": "critical"}
    u = urgency_map.get(urgency, "critical")
    try:
        subprocess.Popen(
            ["notify-send", "-u", u, "-a", "WRU Security", title, message],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        pass  # notify-send not installed


def _show_approve_deny_dialog(bus_id: str, device_name: str, score: int) -> None:
    """
    Show a Zenity dialog with Approve / Deny buttons for a quarantined device.
    Runs wru allow/deny based on user choice. Non-blocking (separate thread).
    """
    def _run():
        try:
            result = subprocess.run(
                [
                    "zenity", "--question",
                    "--title=WRU: USB Device Quarantined",
                    f"--text=Device plugged in:\n\n  {device_name}\n  Bus: {bus_id}   Risk score: {score}/100\n\nDo you want to ALLOW this device?",
                    "--ok-label=Allow",
                    "--cancel-label=Deny",
                    "--width=420",
                ],
                timeout=60,
            )
            if result.returncode == 0:
                # User clicked Allow
                subprocess.run(["pkexec", "wru", "allow", bus_id], check=False)
                # Give udisks2 a moment to react to the block udev change
                # events that 'wru allow' fires, then notify the user.
                import time
                time.sleep(3)
                _notify_send(
                    "✅ Device Allowed",
                    f"{device_name} ({bus_id}) authorized.\n"
                    f"Check your file manager — the drive should appear now.",
                    "low",
                )
            else:
                # User clicked Deny
                subprocess.run(["pkexec", "wru", "deny", bus_id], check=False)
                _notify_send("🔒 Device Denied", f"{device_name} ({bus_id}) blocked.", "normal")
        except FileNotFoundError:
            # zenity not installed – fall back to notify-send only
            _notify_send(
                "🔒 USB Device Quarantined",
                f"{device_name} ({bus_id})  score {score}/100\n"
                f"Run: sudo wru allow {bus_id}  OR  sudo wru deny {bus_id}",
                "critical",
            )
        except subprocess.TimeoutExpired:
            pass

    threading.Thread(target=_run, daemon=True, name=f"wru-dialog-{bus_id}").start()


# ─────────────────────────── Tray applet ──────────────────────────────────────

class WRUTrayApplet:
    """
    System tray applet for the WRU USB security daemon.

    Architecture:
      • A background thread runs a blocking asyncio loop that maintains a
        persistent connection to the daemon's Unix socket.
      • Incoming JSON notification lines are dispatched on the main thread.
      • For quarantine events a Zenity approve/deny dialog is spawned.
      • For all events a libnotify desktop notification is shown.
      • The pystray icon runs on the main thread (required by most DEs).
    """

    def __init__(self) -> None:
        self._running = False
        self._icon: Optional[object] = None     # pystray.Icon
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._status: str = "Connecting…"

    # ─────────────── Public entry point ───────────────

    def run(self) -> None:
        """Start the tray applet (blocking – call from main thread)."""
        try:
            import pystray
        except ImportError:
            print(
                "pystray is required for the tray applet.\n"
                "Install with: pip install pystray pillow"
            )
            return

        self._running = True

        # Start background asyncio thread for socket comms
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_async_loop, daemon=True, name="wru-tray-socket"
        )
        self._thread.start()

        # Build tray icon
        icon_img = _make_icon_image()
        menu = pystray.Menu(
            pystray.MenuItem("WRU – USB Security Active", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Show Status", self._action_status),
            pystray.MenuItem("View Logs", self._action_logs),
            pystray.MenuItem("List Devices", self._action_list),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self._action_quit),
        )
        self._icon = pystray.Icon(
            name="wru",
            icon=icon_img,
            title="WRU – USB Security",
            menu=menu,
        )
        self._icon.run()     # blocks until icon.stop() is called

    # ─────────────── Async socket loop (background thread) ────────────────

    def _run_async_loop(self) -> None:
        """Run asyncio event loop in background thread."""
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._socket_listener())

    async def _socket_listener(self) -> None:
        """Maintain persistent connection to daemon notification socket."""
        while self._running:
            try:
                if not SOCKET_PATH.exists():
                    logger.debug("Daemon socket not found, waiting…")
                    await asyncio.sleep(RECONNECT_DELAY)
                    continue

                reader, writer = await asyncio.open_unix_connection(str(SOCKET_PATH))
                logger.info("Connected to WRU daemon notification socket")
                self._update_icon_title("WRU – Connected")

                try:
                    while self._running:
                        line = await asyncio.wait_for(reader.readline(), timeout=60.0)
                        if not line:
                            break
                        await self._handle_notification(line.decode().strip())
                except asyncio.TimeoutError:
                    pass       # heartbeat – keep loop alive
                except Exception as e:
                    logger.warning(f"Socket read error: {e}")
                finally:
                    try:
                        writer.close()
                    except Exception:
                        pass

            except Exception as e:
                logger.debug(f"Socket connection failed: {e}")

            self._update_icon_title("WRU – Reconnecting…")
            await asyncio.sleep(RECONNECT_DELAY)

    async def _handle_notification(self, raw: str) -> None:
        """Parse and display a JSON notification line from the daemon."""
        if not raw:
            return
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            # Plain-text fallback
            _notify_send("WRU Alert", raw)
            return

        title   = payload.get("title", "WRU Security Alert")
        message = payload.get("message", "")
        urgency = payload.get("urgency", "critical")

        # Always show a desktop notification
        _notify_send(title, message, urgency)

        # For quarantine events, also show an approve/deny dialog
        if "Quarantined" in title or "Quarantine" in title:
            # Parse bus_id and score out of the message lines
            bus_id      = self._extract_field(message, "Bus:")
            score_str   = self._extract_field(message, "Risk score:")
            device_name = self._extract_field(message, "Device:")

            # Fall back: parse classic quarantine message format
            if not bus_id:
                for line in message.splitlines():
                    line = line.strip()
                    if line.startswith("To approve:"):
                        parts = line.split()
                        if len(parts) >= 4:
                            bus_id = parts[-1]
                    if line.startswith("Device:"):
                        device_name = line.removeprefix("Device:").strip()
                    if line.startswith("Risk score:"):
                        score_str = line.removeprefix("Risk score:").split("/")[0].strip()

            score = int(score_str) if score_str and score_str.isdigit() else 0
            if bus_id:
                _show_approve_deny_dialog(bus_id, device_name or "Unknown device", score)

    @staticmethod
    def _extract_field(text: str, prefix: str) -> str:
        """Extract value after a prefix from a multiline string."""
        for line in text.splitlines():
            line = line.strip()
            if line.startswith(prefix):
                return line[len(prefix):].strip()
        return ""

    # ─────────────── Thread-safe UI helpers ───────────────

    def _update_icon_title(self, title: str) -> None:
        if self._icon:
            try:
                self._icon.title = title
            except Exception:
                pass

    # ─────────────── Menu actions ───────────────

    def _action_status(self, icon: object, item: object) -> None:
        try:
            subprocess.Popen(
                ["bash", "-c", "wru status; read -p 'Press Enter to close'"],
                start_new_session=True
            )
        except Exception as e:
            logger.error(f"Status action failed: {e}")

    def _action_logs(self, icon: object, item: object) -> None:
        try:
            subprocess.Popen(
                ["bash", "-c", "wru logs -n 50; read -p 'Press Enter to close'"],
                start_new_session=True
            )
        except Exception as e:
            logger.error(f"Logs action failed: {e}")

    def _action_list(self, icon: object, item: object) -> None:
        try:
            subprocess.Popen(
                ["bash", "-c", "wru list; read -p 'Press Enter to close'"],
                start_new_session=True
            )
        except Exception as e:
            logger.error(f"List action failed: {e}")

    def _action_quit(self, icon: object, item: object) -> None:
        self._running = False
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        icon.stop()


# ─────────────────────────── Entry point ──────────────────────────────────────

def main() -> None:
    """Entry point for `wru-tray` console script."""
    logging.basicConfig(level=logging.WARNING)
    applet = WRUTrayApplet()
    applet.run()


if __name__ == "__main__":
    main()
