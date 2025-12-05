"""
WRU (Who R U?) - Zero-Trust USB Security System

A comprehensive, patent-safe USB security solution implementing
defense-in-depth with 6 protection layers.
"""

__version__ = "1.0.0"
__author__ = "WRU Security Team"

from wru.core.daemon import WRUDaemon
from wru.threat.engine import ThreatEngine
from wru.core.authorization import DeviceAuthorization

__all__ = [
    "WRUDaemon",
    "ThreatEngine",
    "DeviceAuthorization",
    "__version__",
]
