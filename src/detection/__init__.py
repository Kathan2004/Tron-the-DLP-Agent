"""Tron detection engine: data identifiers, validators, keyword proximity, redaction."""

from src.detection.engine import DetectionEngine, Match, ScanOutcome, get_engine, normalize_text, SEVERITY_RANK
from src.detection.library import DETECTORS, LEGACY_ALIASES

__all__ = ["DetectionEngine", "Match", "ScanOutcome", "get_engine", "normalize_text",
           "SEVERITY_RANK", "DETECTORS", "LEGACY_ALIASES"]
