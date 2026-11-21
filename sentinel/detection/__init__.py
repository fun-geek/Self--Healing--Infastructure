"""Deterministic detection and threat analysis."""

from sentinel.detection.engine import DetectionEngine
from sentinel.detection.rules import RULE_METADATA, RULES

__all__ = ["DetectionEngine", "RULE_METADATA", "RULES"]
