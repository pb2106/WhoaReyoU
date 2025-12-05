"""
Network Device Isolator

Automatically quarantines USB network adapters (Ethernet/WiFi)
in isolated network namespaces to prevent data exfiltration.
"""

import asyncio
import logging
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class NetworkAnalysis:
    """Results from network device analysis."""
    interface_name: str
    namespace_name: str
    mac_address: str = ""
    is_suspicious: bool = False
    suspicious_reasons: list[str] = field(default_factory=list)
    packets_captured: int = 0
    beaconing_detected: bool = False
    dns_queries: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "interface": self.interface_name,
            "namespace": self.namespace_name,
            "mac": self.mac_address,
            "suspicious": self.is_suspicious,
            "reasons": self.suspicious_reasons,
            "packets": self.packets_captured,
            "beaconing": self.beaconing_detected,
            "dns_queries": self.dns_queries,
        }


class NetworkIsolator:
    """
    Isolates USB network devices in network namespaces.
    
    When a USB network adapter is detected:
    1. Move interface to isolated namespace
    2. Apply restrictive firewall rules
    3. Capture and analyze initial traffic
    4. Block until explicitly approved
    """
    
    NAMESPACE_PREFIX = "wru-net-"
    CAPTURE_DURATION = 10.0  # seconds
    
    def __init__(self, interface_name: str):
        """
        Initialize isolator for a network interface.
        
        Args:
            interface_name: Network interface name (e.g., usb0, enp0s20f0u1)
        """
        self._interface = interface_name
        self._namespace = f"{self.NAMESPACE_PREFIX}{interface_name}"
        self._isolated = False
        self._original_namespace = None  # Track for cleanup
    
    async def isolate(self) -> bool:
        """
        Move interface to isolated namespace.
        
        Returns True if successful.
        """
        if self._isolated:
            return True
        
        try:
            # Create network namespace
            await self._run_ip_cmd(["netns", "add", self._namespace])
            
            # Move interface to namespace
            await self._run_ip_cmd([
                "link", "set", self._interface,
                "netns", self._namespace
            ])
            
            # Apply firewall rules inside namespace
            await self._apply_firewall_rules()
            
            self._isolated = True
            logger.info(f"Isolated network interface {self._interface} in namespace {self._namespace}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to isolate {self._interface}: {e}")
            await self.cleanup()
            return False
    
    async def _run_ip_cmd(self, args: list[str]) -> tuple[str, str]:
        """Run ip command and return stdout, stderr."""
        cmd = ["ip"] + args
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode != 0:
            raise RuntimeError(f"ip command failed: {stderr.decode()}")
        
        return stdout.decode(), stderr.decode()
    
    async def _run_in_namespace(self, cmd: list[str]) -> tuple[int, str, str]:
        """Run command inside the isolated namespace."""
        full_cmd = ["ip", "netns", "exec", self._namespace] + cmd
        
        proc = await asyncio.create_subprocess_exec(
            *full_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        return proc.returncode, stdout.decode(), stderr.decode()
    
    async def _apply_firewall_rules(self) -> None:
        """Apply restrictive iptables rules inside namespace."""
        rules = [
            # Default DROP all
            ["iptables", "-P", "INPUT", "DROP"],
            ["iptables", "-P", "OUTPUT", "DROP"],
            ["iptables", "-P", "FORWARD", "DROP"],
            
            # Allow loopback
            ["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
            ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
            
            # Log dropped packets (for analysis)
            ["iptables", "-A", "INPUT", "-j", "LOG", "--log-prefix", "WRU-DROP-IN: "],
            ["iptables", "-A", "OUTPUT", "-j", "LOG", "--log-prefix", "WRU-DROP-OUT: "],
        ]
        
        for rule in rules:
            try:
                await self._run_in_namespace(rule)
            except Exception as e:
                logger.warning(f"Failed to apply rule {rule}: {e}")
    
    async def analyze_traffic(self, duration: float = None) -> NetworkAnalysis:
        """
        Capture and analyze traffic from the isolated interface.
        
        Returns analysis results.
        """
        duration = duration or self.CAPTURE_DURATION
        
        analysis = NetworkAnalysis(
            interface_name=self._interface,
            namespace_name=self._namespace
        )
        
        if not self._isolated:
            logger.warning(f"Cannot analyze {self._interface}: not isolated")
            return analysis
        
        try:
            # Get MAC address
            rc, stdout, _ = await self._run_in_namespace([
                "cat", f"/sys/class/net/{self._interface}/address"
            ])
            if rc == 0:
                analysis.mac_address = stdout.strip()
            
            # Enable interface for capture
            await self._run_in_namespace([
                "ip", "link", "set", self._interface, "up"
            ])
            
            # Capture traffic with tcpdump
            capture_file = f"/tmp/wru-capture-{self._interface}.pcap"
            
            proc = await asyncio.create_subprocess_exec(
                "ip", "netns", "exec", self._namespace,
                "timeout", str(int(duration)),
                "tcpdump", "-i", self._interface,
                "-w", capture_file,
                "-c", "100",  # Max 100 packets
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await proc.wait()
            
            # Analyze capture
            await self._analyze_capture(capture_file, analysis)
            
            # Cleanup capture file
            try:
                Path(capture_file).unlink()
            except Exception:
                pass
            
        except Exception as e:
            logger.error(f"Traffic analysis failed: {e}")
            analysis.suspicious_reasons.append(f"Analysis error: {e}")
        
        return analysis
    
    async def _analyze_capture(
        self,
        capture_file: str,
        analysis: NetworkAnalysis
    ) -> None:
        """Analyze captured packets."""
        try:
            # Use tshark to analyze if available
            proc = await asyncio.create_subprocess_exec(
                "tshark", "-r", capture_file,
                "-T", "fields",
                "-e", "frame.number",
                "-e", "ip.dst",
                "-e", "dns.qry.name",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            
            lines = stdout.decode().splitlines()
            analysis.packets_captured = len(lines)
            
            # Extract DNS queries
            for line in lines:
                parts = line.split("\t")
                if len(parts) >= 3 and parts[2]:
                    analysis.dns_queries.append(parts[2])
            
            # Check for suspicious patterns
            if analysis.packets_captured > 50:
                analysis.is_suspicious = True
                analysis.suspicious_reasons.append(
                    f"High packet count: {analysis.packets_captured}"
                )
            
            # Check for beaconing (repeated connections to same target)
            if len(analysis.dns_queries) > 0:
                from collections import Counter
                dns_counts = Counter(analysis.dns_queries)
                for domain, count in dns_counts.most_common(1):
                    if count > 5:
                        analysis.beaconing_detected = True
                        analysis.is_suspicious = True
                        analysis.suspicious_reasons.append(
                            f"Beaconing to {domain}: {count} queries"
                        )
            
        except FileNotFoundError:
            # tshark not installed, use basic analysis
            logger.debug("tshark not available, using basic capture analysis")
    
    async def allow_traffic(
        self,
        destination: Optional[str] = None,
        port: Optional[int] = None
    ) -> None:
        """
        Allow specific traffic from the isolated interface.
        
        Args:
            destination: IP or network to allow (e.g., "192.168.1.0/24")
            port: Port to allow
        """
        if not self._isolated:
            return
        
        rule = ["iptables", "-I", "OUTPUT", "1"]
        
        if destination:
            rule.extend(["-d", destination])
        if port:
            rule.extend(["-p", "tcp", "--dport", str(port)])
        
        rule.extend(["-j", "ACCEPT"])
        
        await self._run_in_namespace(rule)
        logger.info(f"Allowed traffic: dest={destination}, port={port}")
    
    async def restore(self) -> bool:
        """
        Restore interface to default namespace.
        
        Returns True if successful.
        """
        if not self._isolated:
            return True
        
        try:
            # Move interface back to default namespace
            await self._run_in_namespace([
                "ip", "link", "set", self._interface,
                "netns", "1"  # PID 1 is always in default namespace
            ])
            
            # Delete namespace
            await self._run_ip_cmd(["netns", "delete", self._namespace])
            
            self._isolated = False
            logger.info(f"Restored {self._interface} to default namespace")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore {self._interface}: {e}")
            return False
    
    async def cleanup(self) -> None:
        """Clean up namespace and resources."""
        try:
            # Try to restore interface first
            if self._isolated:
                await self.restore()
        except Exception:
            pass
        
        try:
            # Force delete namespace
            await self._run_ip_cmd(["netns", "delete", self._namespace])
        except Exception:
            pass
        
        self._isolated = False


class NetworkIsolatorManager:
    """Manages network isolators for multiple interfaces."""
    
    def __init__(self):
        self._isolators: dict[str, NetworkIsolator] = {}
    
    async def isolate_interface(self, interface_name: str) -> NetworkIsolator:
        """Create and activate isolator for an interface."""
        if interface_name in self._isolators:
            return self._isolators[interface_name]
        
        isolator = NetworkIsolator(interface_name)
        await isolator.isolate()
        self._isolators[interface_name] = isolator
        
        return isolator
    
    async def restore_interface(self, interface_name: str) -> None:
        """Restore an interface to normal operation."""
        isolator = self._isolators.pop(interface_name, None)
        if isolator:
            await isolator.restore()
    
    async def cleanup_all(self) -> None:
        """Clean up all isolators."""
        for isolator in self._isolators.values():
            await isolator.cleanup()
        self._isolators.clear()
    
    def get_isolator(self, interface_name: str) -> Optional[NetworkIsolator]:
        """Get isolator for an interface."""
        return self._isolators.get(interface_name)
