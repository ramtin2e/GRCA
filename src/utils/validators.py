"""Validators for input data quality checking."""

from __future__ import annotations
from typing import List
from src.models.control import Control
from src.utils.logger import get_logger

logger = get_logger(__name__)


def validate_controls(controls: List[Control]) -> List[str]:
    """Validate a list of controls and return warnings."""
    warnings = []
    seen_ids = set()

    for ctrl in controls:
        if ctrl.id in seen_ids:
            warnings.append(f"Duplicate control ID: {ctrl.id}")
        seen_ids.add(ctrl.id)

        if not ctrl.name or ctrl.name == ctrl.id:
            warnings.append(f"Control {ctrl.id} has no descriptive name")

        if not ctrl.framework or ctrl.framework == "UNKNOWN":
            warnings.append(f"Control {ctrl.id} has no framework assigned")

    if warnings:
        logger.warning(f"Validation found {len(warnings)} issues")
    return warnings
