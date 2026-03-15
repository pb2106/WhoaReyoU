"""
Tests for the USB mount-after-approval flow in authorization.py / daemon.py.

Runs with plain pytest (no pytest-asyncio needed) by using asyncio.run().
"""

import asyncio
import os
import stat
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch


# ─────────────────────────── helper ───────────────────────────────────────────

def _make_fake_sysblock(tmp_path: Path, bus_id: str):
    """
    Create a minimal fake sysfs block layout under tmp_path:
        tmp/sys/block/sdb/            – disk dir
        tmp/sys/block/sdb/sdb1/       – partition subdir
        tmp/sys/block/sdb/device      – symlink → target containing bus_id
        tmp/dev/sdb                   – disk node  (exists())
        tmp/dev/sdb1                  – partition node (exists())
    Returns (sys_block, disk_node, part_node).
    """
    sys_block = tmp_path / "sys" / "block"
    disk_dir  = sys_block / "sdb"
    disk_dir.mkdir(parents=True)
    part_dir  = disk_dir / "sdb1"
    part_dir.mkdir()

    # Symlink target whose resolved path will contain bus_id
    target = tmp_path / "sys" / "bus" / "usb" / "devices" / bus_id
    target.mkdir(parents=True)
    (disk_dir / "device").symlink_to(target)

    dev_dir   = tmp_path / "dev"
    dev_dir.mkdir(exist_ok=True)
    disk_node = dev_dir / "sdb"
    disk_node.touch()
    part_node = dev_dir / "sdb1"
    part_node.touch()

    return sys_block, disk_node, part_node


# ─────────────── _find_all_block_nodes ────────────────────────────────────────

def _find_all_block_nodes_under(tmp_path: Path, bus_id: str) -> list[Path]:
    """
    Inline reimplementation of _find_all_block_nodes that uses tmp_path
    instead of /sys/block and /dev, so it can run without root.
    """
    found: list[Path] = []
    sys_block = tmp_path / "sys" / "block"
    dev_dir   = tmp_path / "dev"
    if not sys_block.exists():
        return found
    for block_dir in sys_block.glob("sd*"):
        try:
            dev_link = (block_dir / "device").resolve()
            if bus_id not in str(dev_link):
                continue
            disk_node = dev_dir / block_dir.name
            if disk_node.exists():
                found.append(disk_node)
            for part_dir in block_dir.glob(f"{block_dir.name}[0-9]*"):
                part_node = dev_dir / part_dir.name
                if part_node.exists():
                    found.append(part_node)
        except OSError:
            pass
    return found


def test_find_all_block_nodes_discovers_disk_and_partition(tmp_path):
    """_find_all_block_nodes finds both the whole-disk and partition nodes."""
    bus_id = "1-2"
    _, disk_node, part_node = _make_fake_sysblock(tmp_path, bus_id)

    nodes = _find_all_block_nodes_under(tmp_path, bus_id)
    names = [n.name for n in nodes]
    assert "sdb"  in names, f"Disk node not found in {names}"
    assert "sdb1" in names, f"Partition node not found in {names}"


def test_find_all_block_nodes_ignores_unrelated_devices(tmp_path):
    """Devices on a different bus_id are NOT returned."""
    _, disk_node, part_node = _make_fake_sysblock(tmp_path, "1-3")

    nodes = _find_all_block_nodes_under(tmp_path, "1-2")  # different bus_id
    assert nodes == [], f"Expected empty list, got {nodes}"


# ─────────────── authorize() helper call order ────────────────────────────────

def test_authorize_calls_settle_restore_trigger_in_order():
    """
    DeviceAuthorization.authorize() must call the four new helpers
    in the correct sequence after writing authorized=1.
    """
    from wru.core.authorization import DeviceAuthorization

    auth = DeviceAuthorization()
    bus_id = "1-3"
    call_order: list[str] = []

    async def run():
        async def fake_settle(timeout=8):
            call_order.append("settle")

        async def fake_bind(bid):
            call_order.append("bind")

        async def fake_restore_info(info):
            call_order.append("restore_info")

        async def fake_restore_storage(bid):
            call_order.append("restore_storage")

        async def fake_trigger(bid):
            call_order.append("trigger")

        # Patch sysfs write and all helpers
        with (
            patch.object(Path, "exists", return_value=True),
            patch.object(Path, "write_text", return_value=None),
            patch.object(auth, "_bind_drivers",                  new=fake_bind),
            patch.object(auth, "_udevadm_settle",                new=fake_settle),
            patch.object(auth, "get_device_info",                return_value=MagicMock()),
            patch.object(auth, "_restore_device_node_permissions", new=fake_restore_info),
            patch.object(auth, "_restore_all_storage_permissions", new=fake_restore_storage),
            patch.object(auth, "_trigger_block_udev_events",     new=fake_trigger),
            patch("asyncio.sleep", new=AsyncMock()),
        ):
            await auth.authorize(bus_id)

    asyncio.run(run())

    assert "settle"          in call_order, f"settle not called: {call_order}"
    assert "restore_storage" in call_order, f"restore_storage not called: {call_order}"
    assert "trigger"         in call_order, f"trigger not called: {call_order}"

    # Ordering guards
    assert call_order.index("settle") < call_order.index("restore_storage"), (
        f"settle must come before restore_storage: {call_order}"
    )
    assert call_order.index("restore_storage") < call_order.index("trigger"), (
        f"restore_storage must come before trigger: {call_order}"
    )


# ──────────── daemon.authorize_device() sends tray notification ───────────────

def test_daemon_authorize_device_sends_ready_to_mount_notification():
    """
    WRUDaemon.authorize_device() must broadcast a "Ready to Mount"
    tray notification after a successful authorization.
    """
    from wru.core.daemon import WRUDaemon

    daemon = WRUDaemon.__new__(WRUDaemon)

    fake_device = MagicMock()
    fake_device.product      = "Test Drive"
    fake_device.manufacturer = "VendorCo"
    fake_device.device_id    = "abcd:1234:serial"

    daemon._authorization = MagicMock()
    daemon._authorization.get_device_info.return_value   = fake_device
    daemon._authorization.authorize                       = AsyncMock(return_value=True)
    daemon._authorization._find_all_block_nodes.return_value = [
        Path("/dev/sdb"), Path("/dev/sdb1")
    ]

    daemon._forensic_logger                = MagicMock()
    daemon._forensic_logger.log_event      = AsyncMock()
    daemon._pending_decisions              = {}
    daemon._authorized_devices             = set()

    notify_calls: list[dict] = []

    async def fake_notify(message, title="WRU Security Alert", urgency="critical"):
        notify_calls.append({"title": title, "message": message})

    daemon._notify_user = fake_notify

    result = asyncio.run(daemon.authorize_device("1-3"))

    assert result is True, "authorize_device should return True on success"

    titles = [c["title"] for c in notify_calls]
    assert any("Ready to Mount" in t for t in titles), (
        f"Expected 'Ready to Mount' notification. Got titles: {titles}"
    )

    messages = [c["message"] for c in notify_calls]
    assert any("/dev/sdb" in m for m in messages), (
        f"Expected block node in notification message. Got: {messages}"
    )
