"""Minimal JWT crafting helpers for tests/detectors (base64url only, no crypto)."""
from apistf.detectors.jwt import craft_jwt

__all__ = ["craft_jwt"]
