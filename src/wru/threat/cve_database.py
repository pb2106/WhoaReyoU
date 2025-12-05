"""
CVE Database Module

Provides cross-reference against known USB device vulnerabilities.
"""

import json
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CVEEntry:
    """A CVE database entry."""
    cve_id: str
    vendor_id: str
    product_id: str
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    published_date: str
    affected_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


class CVEDatabase:
    """
    USB device CVE database.
    
    Stores known vulnerabilities indexed by vendor:product ID.
    """
    
    DEFAULT_DB_PATH = Path("/etc/wru/cve-database.json")
    
    def __init__(self, db_path: Optional[Path] = None):
        self._db_path = db_path or self.DEFAULT_DB_PATH
        self._entries: dict[str, list[CVEEntry]] = {}  # vendor:product -> CVEs
        self._loaded = False
    
    def load(self, path: Optional[Path] = None) -> bool:
        """Load CVE database from JSON file."""
        db_path = path or self._db_path
        
        if not db_path.exists():
            logger.warning(f"CVE database not found: {db_path}")
            self._entries = {}
            self._loaded = True
            return False
        
        try:
            with open(db_path) as f:
                data = json.load(f)
            
            self._entries.clear()
            
            for entry_data in data.get("cves", []):
                entry = CVEEntry(
                    cve_id=entry_data["cve_id"],
                    vendor_id=entry_data["vendor_id"],
                    product_id=entry_data["product_id"],
                    description=entry_data.get("description", ""),
                    severity=entry_data.get("severity", "MEDIUM"),
                    published_date=entry_data.get("published_date", ""),
                    affected_versions=entry_data.get("affected_versions", []),
                    references=entry_data.get("references", []),
                )
                
                key = f"{entry.vendor_id}:{entry.product_id}"
                if key not in self._entries:
                    self._entries[key] = []
                self._entries[key].append(entry)
            
            self._loaded = True
            logger.info(f"Loaded CVE database with {len(self._entries)} device entries")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load CVE database: {e}")
            self._entries = {}
            self._loaded = True
            return False
    
    def lookup(self, vendor_id: str, product_id: str) -> list[CVEEntry]:
        """Look up CVEs for a specific device."""
        if not self._loaded:
            self.load()
        
        key = f"{vendor_id.lower()}:{product_id.lower()}"
        return self._entries.get(key, [])
    
    def get_highest_severity(self, vendor_id: str, product_id: str) -> Optional[str]:
        """Get highest severity CVE for a device."""
        entries = self.lookup(vendor_id, product_id)
        
        if not entries:
            return None
        
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        
        for severity in severity_order:
            if any(e.severity == severity for e in entries):
                return severity
        
        return None
    
    def has_critical_cve(self, vendor_id: str, product_id: str) -> bool:
        """Check if device has any critical CVEs."""
        entries = self.lookup(vendor_id, product_id)
        return any(e.severity == "CRITICAL" for e in entries)
    
    def get_as_dict(self) -> dict:
        """Get database as dictionary for heuristic scoring."""
        result = {}
        for key, entries in self._entries.items():
            if entries:
                # Use first/most severe entry
                entry = max(entries, key=lambda e: 
                    ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(e.severity)
                    if e.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] else 0
                )
                result[key] = {
                    "cve_id": entry.cve_id,
                    "severity": entry.severity,
                    "description": entry.description,
                }
        return result
    
    @property
    def entry_count(self) -> int:
        """Number of unique device entries."""
        return len(self._entries)
    
    @property
    def cve_count(self) -> int:
        """Total number of CVE entries."""
        return sum(len(entries) for entries in self._entries.values())


# Default embedded CVE entries for known USB attacks
DEFAULT_CVES = [
    {
        "cve_id": "CVE-2020-BADUSB",
        "vendor_id": "16c0",
        "product_id": "0486",
        "description": "Teensy USB development board commonly used for BadUSB attacks",
        "severity": "HIGH",
        "published_date": "2014-08-07",
    },
    {
        "cve_id": "CVE-RUBBER-DUCKY",
        "vendor_id": "05ac",
        "product_id": "021e",
        "description": "USB Rubber Ducky - keystroke injection tool that masquerades as Apple keyboard",
        "severity": "CRITICAL",
        "published_date": "2010-01-01",
    },
    {
        "cve_id": "CVE-BASH-BUNNY",
        "vendor_id": "f000",
        "product_id": "ff00",
        "description": "Bash Bunny - Multi-function attack platform",
        "severity": "CRITICAL",
        "published_date": "2017-03-01",
    },
]


def create_default_database(path: Path) -> None:
    """Create a default CVE database file."""
    data = {"cves": DEFAULT_CVES}
    
    path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    
    logger.info(f"Created default CVE database at {path}")
