"""Symmetric Attack/Defense game service.

This package is deliberately isolated from the legacy exercise services.  Its
public API is exported from :mod:`services.attack_defense.main`.
"""

from .config import AttackDefenseSettings

__all__ = ["AttackDefenseSettings"]
