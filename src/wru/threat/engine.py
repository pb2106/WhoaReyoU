"""
Threat Scoring Engine

The main threat intelligence component that coordinates
heuristic analysis, pattern detection, and CVE matching.
"""

import logging
import json
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

import yaml

from wru.core.authorization import DeviceInfo
from wru.threat.heuristics import HeuristicScorer, HeuristicResult
from wru.threat.patterns import PatternAnalyzer
from wru.threat.cve_database import CVEDatabase

logger = logging.getLogger(__name__)


class ThreatDecision(Enum):
    """Policy decision based on threat score."""
    ALLOW = auto()      # Score 0-19: Safe to authorize
    QUARANTINE = auto() # Score 20-39: Needs user approval
    ANALYZE = auto()    # Score 40-69: Needs deep analysis
    DENY = auto()       # Score 70+: Block the device


@dataclass
class ThreatAssessment:
    """Complete threat assessment for a device."""
    device_id: str
    score: int
    decision: ThreatDecision
    reasons: list[str]
    heuristic_results: list[HeuristicResult] = field(default_factory=list)
    pattern_analysis: Optional[dict] = None
    cve_matches: list[dict] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for logging/serialization."""
        return {
            "device_id": self.device_id,
            "score": self.score,
            "decision": self.decision.name,
            "reasons": self.reasons,
            "heuristics": [
                {"indicator": h.indicator, "score": h.score, "reason": h.reason}
                for h in self.heuristic_results
            ],
            "patterns": self.pattern_analysis,
            "cves": self.cve_matches,
        }


@dataclass
class ThreatEngineConfig:
    """Configuration for the threat engine."""
    
    # Decision thresholds
    allow_threshold: int = 19
    quarantine_threshold: int = 39
    analyze_threshold: int = 69
    # Score 70+ is DENY
    
    # Heuristic weights (can override defaults)
    heuristic_weights: dict[str, int] = field(default_factory=dict)
    
    # Feature toggles
    enable_cve_matching: bool = True
    enable_pattern_analysis: bool = True
    
    @classmethod
    def load(cls, config_path: Path) -> "ThreatEngineConfig":
        """Load configuration from YAML file."""
        config = cls()
        
        if not config_path.exists():
            logger.warning(f"Threat config not found: {config_path}")
            return config
        
        try:
            with open(config_path) as f:
                data = yaml.safe_load(f)
            
            if "thresholds" in data:
                thresholds = data["thresholds"]
                config.allow_threshold = thresholds.get("allow", config.allow_threshold)
                config.quarantine_threshold = thresholds.get("quarantine", config.quarantine_threshold)
                config.analyze_threshold = thresholds.get("analyze", config.analyze_threshold)
            
            if "heuristics" in data:
                config.heuristic_weights = data["heuristics"]
            
            if "features" in data:
                features = data["features"]
                config.enable_cve_matching = features.get("cve_matching", True)
                config.enable_pattern_analysis = features.get("pattern_analysis", True)
            
            logger.info(f"Loaded threat engine config from {config_path}")
            
        except Exception as e:
            logger.error(f"Failed to load threat config: {e}")
        
        return config


class ThreatEngine:
    """
    Main threat intelligence engine.
    
    Coordinates:
    - Heuristic scoring (10 indicators)
    - Temporal pattern analysis
    - CVE database cross-reference
    - Policy decision making
    """
    
    def __init__(self, config: Optional[ThreatEngineConfig] = None):
        self.config = config or ThreatEngineConfig()
        
        self._heuristic_scorer = HeuristicScorer()
        self._pattern_analyzer = PatternAnalyzer()
        self._cve_database = CVEDatabase()
        
        self._loaded = False
    
    async def load_databases(self, config_dir: Path) -> None:
        """Load configuration and databases."""
        # Load threat rules config
        rules_path = config_dir / "threat-rules.yaml"
        try:
            if rules_path.exists():
                self.config = ThreatEngineConfig.load(rules_path)
                
                # Apply heuristic weight overrides
                if self.config.heuristic_weights:
                    self._heuristic_scorer.update_weights(self.config.heuristic_weights)
        except PermissionError:
            logger.warning(f"Permission denied accessing {rules_path}, using defaults")
        
        # Load CVE database
        if self.config.enable_cve_matching:
            cve_path = config_dir / "cve-database.json"
            try:
                if cve_path.exists():
                    self._cve_database.load(cve_path)
            except PermissionError:
                logger.warning(f"Permission denied accessing {cve_path}, CVE matching disabled")
        
        self._loaded = True
        logger.info("Threat engine databases loaded")
    
    async def analyze(self, device: DeviceInfo) -> ThreatAssessment:
        """
        Perform complete threat analysis on a device.
        
        Returns ThreatAssessment with score and decision.
        """
        total_score = 0
        reasons = []
        heuristic_results = []
        cve_matches = []
        pattern_analysis = None
        
        # Run heuristic scoring
        heuristics = self._heuristic_scorer.evaluate_all(device)
        for result in heuristics:
            total_score += result.score
            reasons.append(result.reason)
            heuristic_results.append(result)
        
        # Check CVE database
        if self.config.enable_cve_matching:
            cve_result = self._heuristic_scorer.check_cve_match(
                device,
                self._cve_database.get_as_dict()
            )
            if cve_result:
                total_score += cve_result.score
                reasons.append(cve_result.reason)
                heuristic_results.append(cve_result)
                
                # Add CVE details
                cves = self._cve_database.lookup(device.vendor_id, device.product_id)
                cve_matches = [
                    {
                        "cve_id": cve.cve_id,
                        "severity": cve.severity,
                        "description": cve.description,
                    }
                    for cve in cves
                ]
        
        # Run pattern analysis
        if self.config.enable_pattern_analysis:
            # Record the connect event
            self._pattern_analyzer.record_event(device, "connect")
            
            # Analyze patterns
            patterns = self._pattern_analyzer.analyze(device)
            
            if patterns.is_anomalous:
                total_score += patterns.anomaly_score
                for pattern in patterns.patterns_detected:
                    reasons.append(f"Anomalous pattern: {pattern}")
                
                pattern_analysis = {
                    "anomaly_score": patterns.anomaly_score,
                    "patterns": patterns.patterns_detected,
                    "details": patterns.details,
                }
        
        # Determine decision based on score
        decision = self._make_decision(total_score)
        
        # Cap score at 100
        total_score = min(total_score, 100)
        
        assessment = ThreatAssessment(
            device_id=device.device_id,
            score=total_score,
            decision=decision,
            reasons=reasons,
            heuristic_results=heuristic_results,
            pattern_analysis=pattern_analysis,
            cve_matches=cve_matches,
        )
        
        logger.debug(
            f"Threat assessment for {device.device_id}: "
            f"score={total_score}, decision={decision.name}"
        )
        
        return assessment
    
    def _make_decision(self, score: int) -> ThreatDecision:
        """Determine policy decision based on threat score."""
        if score <= self.config.allow_threshold:
            return ThreatDecision.ALLOW
        elif score <= self.config.quarantine_threshold:
            return ThreatDecision.QUARANTINE
        elif score <= self.config.analyze_threshold:
            return ThreatDecision.ANALYZE
        else:
            return ThreatDecision.DENY
    
    def check_allowlist(self, device: DeviceInfo, allowlist: list[dict]) -> bool:
        """
        Check if device matches allowlist entry.
        
        Allowlist entries can match on:
        - vendor_id
        - product_id
        - serial (supports wildcards with *)
        """
        for entry in allowlist:
            # Must match vendor_id if specified
            if "vendor_id" in entry:
                if entry["vendor_id"].lower() != device.vendor_id.lower():
                    continue
            
            # Must match product_id if specified
            if "product_id" in entry:
                if entry["product_id"].lower() != device.product_id.lower():
                    continue
            
            # Match serial if specified (supports wildcard)
            if "serial" in entry:
                pattern = entry["serial"]
                if "*" in pattern:
                    # Simple wildcard matching
                    import fnmatch
                    if not fnmatch.fnmatch(device.serial, pattern):
                        continue
                else:
                    if device.serial != pattern:
                        continue
            
            # All specified fields matched
            return True
        
        return False
    
    def check_blocklist(self, device: DeviceInfo, blocklist: list[dict]) -> bool:
        """Check if device matches blocklist entry."""
        # Same logic as allowlist
        return self.check_allowlist(device, blocklist)
    
    def clear_device_history(self, device_id: str) -> None:
        """Clear all tracking data for a device."""
        self._heuristic_scorer.clear_history(device_id)
        self._pattern_analyzer.clear_device(device_id)
    
    def update_config(self, config: ThreatEngineConfig) -> None:
        """Update engine configuration."""
        self.config = config
        if config.heuristic_weights:
            self._heuristic_scorer.update_weights(config.heuristic_weights)
        logger.info("Threat engine configuration updated")
