"""Detector registry: one module per detector, looked up by name."""
from apistf.detectors.bfla import BflaDetector
from apistf.detectors.bola import BolaDetector
from apistf.detectors.jwt import JwtDetector
from apistf.detectors.mass_assignment import ExcessiveDataDetector, MassAssignmentDetector
from apistf.detectors.rate_limit import RateLimitDetector

REGISTRY: dict[str, type] = {
    "bola": BolaDetector,
    "bfla": BflaDetector,
    "jwt": JwtDetector,
    "mass_assignment": MassAssignmentDetector,
    "excessive_data": ExcessiveDataDetector,
    "rate_limit": RateLimitDetector,
}

__all__ = ["REGISTRY"]
