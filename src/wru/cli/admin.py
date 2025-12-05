"""
WRU Admin CLI

Command-line interface for managing the WRU USB security system.
"""

import asyncio
import sys
import json
import functools
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()


def async_command(f):
    """Decorator to run async commands."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))
    return wrapper


@click.group()
@click.version_option(version="1.0.0", prog_name="WRU")
def cli():
    """WRU (Who R U?) - Zero-Trust USB Security System
    
    A comprehensive USB security solution with defense-in-depth protection.
    """
    pass


@cli.command()
@async_command
async def status():
    """Show WRU daemon status."""
    # Check if daemon is running via systemd or as a process
    import subprocess
    
    # Check systemd first
    result = subprocess.run(
        ["systemctl", "is-active", "wru-daemon"],
        capture_output=True,
        text=True
    )
    is_systemd_active = result.stdout.strip() == "active"
    
    # Also check if any WRU daemon process is running
    is_process_running = False
    for pattern in ["wru.core.daemon", "wru_namespace_daemon", "wru-daemon"]:
        result = subprocess.run(
            ["pgrep", "-f", pattern],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            is_process_running = True
            break
    
    is_running = is_systemd_active or is_process_running
    
    # Determine status text
    if is_systemd_active:
        status_text = ("● Running (systemd)", "green bold")
    elif is_process_running:
        status_text = ("● Running (manual)", "green bold")
    else:
        status_text = ("○ Stopped", "red bold")
    
    status_panel = Panel(
        Text.assemble(
            ("WRU Daemon Status\n\n", "bold"),
            ("Status: ", ""),
            status_text,
            ("\n\nProtection Layers:\n", ""),
            ("  ✓ ", "green") if is_running else ("  ○ ", "dim"),
            ("Layer 0: Initramfs Hub Control\n"),
            ("  ✓ ", "green") if is_running else ("  ○ ", "dim"),
            ("Layer 1: Dual Barrier Enforcement\n"),
            ("  ✓ ", "green") if is_running else ("  ○ ", "dim"),
            ("Layer 2: Threat Intelligence\n"),
            ("  ✓ ", "green") if is_running else ("  ○ ", "dim"),
            ("Layer 3: Isolated Analysis\n"),
            ("  ✓ ", "green") if is_running else ("  ○ ", "dim"),
            ("Layer 4: Runtime Protection\n"),
            ("  ✓ ", "green") if is_running else ("  ○ ", "dim"),
            ("Layer 5: Policy Orchestration\n"),
            ("  ✓ ", "green") if is_running else ("  ○ ", "dim"),
            ("Layer 6: Forensic Logging\n"),
        ),
        title="[bold blue]WRU Status[/]",
        border_style="blue"
    )
    
    console.print(status_panel)


@cli.command()
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
@async_command
async def list(json_output: bool):
    """List connected USB devices with threat assessment."""
    from wru.core.authorization import DeviceAuthorization
    from wru.threat.engine import ThreatEngine
    
    auth = DeviceAuthorization()
    threat = ThreatEngine()
    
    # Load threat databases (may fail without root, which is OK)
    config_dir = Path("/etc/wru")
    try:
        if config_dir.exists():
            await threat.load_databases(config_dir)
    except PermissionError:
        # Running without root - use default threat scoring
        pass
    
    devices = auth.get_all_devices()
    
    if json_output:
        output = []
        for device in devices:
            assessment = await threat.analyze(device)
            output.append({
                "bus_id": device.bus_id,
                "vendor_id": device.vendor_id,
                "product_id": device.product_id,
                "manufacturer": device.manufacturer,
                "product": device.product,
                "serial": device.serial,
                "authorized": device.authorized,
                "threat_score": assessment.score,
                "decision": assessment.decision.name,
                "reasons": assessment.reasons,
            })
        click.echo(json.dumps(output, indent=2))
        return
    
    # Create rich table
    table = Table(title="Connected USB Devices")
    table.add_column("Bus ID", style="cyan")
    table.add_column("VID:PID", style="blue")
    table.add_column("Description", style="white")
    table.add_column("Auth", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("Decision", style="bold")
    
    for device in devices:
        assessment = await threat.analyze(device)
        
        # Format description
        desc = device.product or device.manufacturer or "Unknown"
        if device.manufacturer and device.product:
            desc = f"{device.manufacturer} {device.product}"
        
        # Format authorization
        auth_icon = "✓" if device.authorized else "✗"
        auth_color = "green" if device.authorized else "red"
        
        # Format decision with color
        decision_colors = {
            "ALLOW": "green",
            "QUARANTINE": "yellow",
            "ANALYZE": "orange3",
            "DENY": "red",
        }
        decision_color = decision_colors.get(assessment.decision.name, "white")
        
        # Format score with color
        if assessment.score < 20:
            score_color = "green"
        elif assessment.score < 40:
            score_color = "yellow"
        elif assessment.score < 70:
            score_color = "orange3"
        else:
            score_color = "red"
        
        table.add_row(
            device.bus_id,
            f"{device.vendor_id}:{device.product_id}",
            desc[:40],
            f"[{auth_color}]{auth_icon}[/]",
            f"[{score_color}]{assessment.score}[/]",
            f"[{decision_color}]{assessment.decision.name}[/]"
        )
    
    console.print(table)
    
    if not devices:
        console.print("[dim]No USB devices found[/]")


@cli.command()
@click.argument("bus_id")
@click.option("--permanent", "-p", is_flag=True, help="Add to permanent allowlist")
@async_command
async def allow(bus_id: str, permanent: bool):
    """Authorize a USB device.
    
    BUS_ID should be in format like '1-2' (bus-port) or '1-2.3' (bus-port.subport).
    Use 'wru list' to see available devices and their bus IDs.
    
    This command requires root privileges.
    """
    import os
    from wru.core.authorization import DeviceAuthorization
    
    auth = DeviceAuthorization()
    
    # Check if the device exists first
    device = auth.get_device_info(bus_id)
    if not device:
        console.print(f"[red]✗ Device {bus_id} not found[/]")
        console.print("\n[dim]Hints:[/]")
        console.print("[dim]  • Use 'wru list' to see connected devices[/]")
        console.print("[dim]  • Bus ID format is like '1-2' or '1-2.3', not just '1'[/]")
        sys.exit(1)
    
    if await auth.authorize(bus_id):
        console.print(f"[green]✓ Device {bus_id} authorized[/]")
        
        if permanent:
            console.print(
                f"[yellow]TODO: Add {device.device_id} to permanent allowlist[/]"
            )
    else:
        console.print(f"[red]✗ Failed to authorize device {bus_id}[/]")
        if os.geteuid() != 0:
            console.print(f"[yellow]⚠ Try running with sudo: sudo wru allow {bus_id}[/]")
        sys.exit(1)


@cli.command()
@click.argument("bus_id")
@async_command
async def deny(bus_id: str):
    """Deny/deauthorize a USB device."""
    from wru.core.authorization import DeviceAuthorization
    
    auth = DeviceAuthorization()
    
    if await auth.deauthorize(bus_id):
        console.print(f"[green]✓ Device {bus_id} deauthorized[/]")
    else:
        console.print(f"[red]✗ Failed to deauthorize device {bus_id}[/]")
        sys.exit(1)


@cli.command()
@click.argument("bus_id")
@click.option("--deep", "-d", is_flag=True, help="Perform deep analysis (slower)")
@async_command
async def analyze(bus_id: str, deep: bool):
    """Analyze a specific USB device."""
    from wru.core.authorization import DeviceAuthorization
    from wru.threat.engine import ThreatEngine
    
    auth = DeviceAuthorization()
    threat = ThreatEngine()
    
    device = auth.get_device_info(bus_id)
    
    if not device:
        console.print(f"[red]Device {bus_id} not found[/]")
        sys.exit(1)
    
    # Load databases (may fail without root, which is OK)
    config_dir = Path("/etc/wru")
    try:
        if config_dir.exists():
            await threat.load_databases(config_dir)
    except PermissionError:
        pass
    
    # Perform analysis
    with console.status("[bold blue]Analyzing device..."):
        assessment = await threat.analyze(device)
    
    # Display results
    console.print(Panel(
        Text.assemble(
            ("Device: ", "bold"),
            (f"{device.manufacturer or 'Unknown'} {device.product or 'Unknown'}\n", ""),
            ("Bus ID: ", "bold"),
            (f"{device.bus_id}\n", "cyan"),
            ("VID:PID: ", "bold"),
            (f"{device.vendor_id}:{device.product_id}\n", "blue"),
            ("Serial: ", "bold"),
            (f"{device.serial or 'None'}\n", "dim"),
            ("Interfaces: ", "bold"),
            (f"{', '.join(device.interfaces) or 'None'}\n", ""),
        ),
        title="[bold]Device Information[/]"
    ))
    
    # Threat assessment
    score_color = "green" if assessment.score < 20 else "yellow" if assessment.score < 40 else "orange3" if assessment.score < 70 else "red"
    
    console.print(Panel(
        Text.assemble(
            ("Threat Score: ", "bold"),
            (f"{assessment.score}/100\n", f"bold {score_color}"),
            ("Decision: ", "bold"),
            (f"{assessment.decision.name}\n\n", f"bold {score_color}"),
            ("Risk Factors:\n", "bold"),
            *[(f"  • {reason}\n", score_color) for reason in assessment.reasons] if assessment.reasons else [("  None detected\n", "green")],
        ),
        title="[bold]Threat Assessment[/]",
        border_style=score_color
    ))


@cli.command()
@click.option("--follow", "-f", is_flag=True, help="Follow log output")
@click.option("--lines", "-n", default=20, help="Number of lines to show")
@click.option("--severity", "-s", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]))
@async_command
async def logs(follow: bool, lines: int, severity: Optional[str]):
    """View WRU logs."""
    from wru.forensics.logger import ForensicLogger
    
    log_dir = Path("/var/log/wru")
    
    if not log_dir.exists():
        console.print("[yellow]No logs found. Is WRU running?[/]")
        return
    
    logger = ForensicLogger(log_dir)
    
    events = await logger.search_logs(severity=severity, limit=lines)
    
    for event in reversed(events[-lines:]):
        # Color based on severity
        sev_colors = {
            "DEBUG": "dim",
            "INFO": "blue",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "bold red",
        }
        sev = event.get("severity", "INFO")
        color = sev_colors.get(sev, "white")
        
        timestamp = event.get("timestamp", "")[:19]
        event_type = event.get("event_type", "unknown")
        
        console.print(
            f"[dim]{timestamp}[/] [{color}]{sev:8}[/] {event_type}",
            end=""
        )
        
        if event.get("device_id"):
            console.print(f" [cyan]({event['device_id']})[/]", end="")
        
        if event.get("threat_score"):
            console.print(f" score={event['threat_score']}", end="")
        
        console.print()


@cli.command()
@async_command
async def incidents():
    """List security incidents."""
    import os
    from wru.forensics.incident import IncidentResponder
    
    try:
        responder = IncidentResponder()
        incidents = await responder.list_all_incidents()
    except PermissionError:
        console.print("[red]✗ Permission denied accessing incident logs[/]")
        if os.geteuid() != 0:
            console.print("[yellow]⚠ Try running with sudo: sudo wru incidents[/]")
        sys.exit(1)
    
    if not incidents:
        console.print("[green]No incidents recorded[/]")
        return
    
    table = Table(title="Security Incidents")
    table.add_column("ID", style="cyan")
    table.add_column("Time", style="dim")
    table.add_column("Severity")
    table.add_column("Type")
    table.add_column("Device")
    table.add_column("Status")
    
    for incident in incidents[:20]:
        sev_colors = {
            "LOW": "green",
            "MEDIUM": "yellow",
            "HIGH": "orange3",
            "CRITICAL": "red bold",
        }
        sev_color = sev_colors.get(incident.severity, "white")
        
        status_colors = {
            "OPEN": "red",
            "INVESTIGATING": "yellow",
            "RESOLVED": "green",
            "FALSE_POSITIVE": "dim",
        }
        status_color = status_colors.get(incident.status, "white")
        
        table.add_row(
            incident.id,
            incident.timestamp[:16],
            f"[{sev_color}]{incident.severity}[/]",
            incident.incident_type,
            incident.device_id or "N/A",
            f"[{status_color}]{incident.status}[/]"
        )
    
    console.print(table)


@cli.command()
@async_command
async def audit():
    """Run security audit of USB configuration."""
    import subprocess
    
    console.print(Panel("[bold]WRU Security Audit[/]", style="blue"))
    
    checks = []
    
    # Check 1: Hub authorization defaults
    console.print("\n[bold]Checking USB hub authorization defaults...[/]")
    hubs_secure = True
    for hub in Path("/sys/bus/usb/devices").glob("usb*"):
        auth_default = hub / "authorized_default"
        if auth_default.exists():
            value = auth_default.read_text().strip()
            if value != "0":
                hubs_secure = False
                console.print(f"  [red]✗ {hub.name}: authorized_default={value}[/]")
    
    if hubs_secure:
        console.print("  [green]✓ All hubs have authorized_default=0[/]")
        checks.append(("Hub Defaults", True))
    else:
        console.print("  [yellow]⚠ Some hubs allow auto-authorization[/]")
        checks.append(("Hub Defaults", False))
    
    # Check 2: Automount disabled
    console.print("\n[bold]Checking automount status...[/]")
    result = subprocess.run(
        ["systemctl", "is-active", "udisks2"],
        capture_output=True,
        text=True
    )
    if result.stdout.strip() == "inactive":
        console.print("  [green]✓ udisks2 is disabled[/]")
        checks.append(("Automount", True))
    else:
        console.print("  [yellow]⚠ udisks2 is running (automount enabled)[/]")
        checks.append(("Automount", False))
    
    # Check 3: IOMMU enabled
    console.print("\n[bold]Checking IOMMU status...[/]")
    cmdline = Path("/proc/cmdline").read_text()
    if "intel_iommu=on" in cmdline or "amd_iommu=on" in cmdline:
        console.print("  [green]✓ IOMMU is enabled[/]")
        checks.append(("IOMMU", True))
    else:
        console.print("  [yellow]⚠ IOMMU may not be enabled[/]")
        checks.append(("IOMMU", False))
    
    # Summary
    console.print("\n" + "─" * 40)
    passed = sum(1 for _, ok in checks if ok)
    total = len(checks)
    
    if passed == total:
        console.print(f"[green bold]✓ All {total} checks passed[/]")
    else:
        console.print(f"[yellow]⚠ {passed}/{total} checks passed[/]")


def main():
    """Entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
