"""
JSON parser — handles structured JSON GRC report ingestion.

Supports various JSON report structures commonly found in compliance
audit exports, including nested and flat formats.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional
import json

from src.parsers.base_parser import BaseParser
from src.utils.logger import get_logger

logger = get_logger(__name__)


class JSONParser(BaseParser):
    """
    Parser for JSON-formatted GRC compliance reports.

    Supports:
        - Flat list of control objects: [{"control_id": ..., "status": ...}, ...]
        - Nested structure with controls key: {"controls": [...], "metadata": {...}}
        - ISO 27001 audit format: {"audit_date": ..., "controls": [{...}]}
        - Deep-nested: auto-discovers the controls array
    """

    def __init__(
        self,
        column_aliases: Optional[Dict[str, List[str]]] = None,
        default_framework: str = "UNKNOWN",
        controls_key: Optional[str] = None,
    ):
        """
        Initialize JSON parser.

        Args:
            column_aliases: Custom field name aliases.
            default_framework: Fallback framework name.
            controls_key: Explicit key path to controls array (e.g., "data.controls").
                          If None, auto-detects the array of control objects.
        """
        super().__init__(column_aliases=column_aliases, default_framework=default_framework)
        self.controls_key = controls_key

    def _parse_raw(self, file_path: Path) -> List[Dict]:
        """
        Read JSON file and extract control records.

        Handles multiple common JSON structures:
        1. Top-level array: [{control}, {control}, ...]
        2. Object with controls key: {"controls": [{...}]}
        3. Nested structure: {"audit": {"controls": [{...}]}}
        """
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # If explicit key path was provided, use it
        if self.controls_key:
            records = self._traverse_key_path(data, self.controls_key)
            if records:
                logger.info(f"Found {len(records)} records at key '{self.controls_key}'")
                return records

        # Auto-detect structure
        records = self._auto_detect_controls(data)
        logger.info(f"Auto-detected {len(records)} control records")
        return records

    def _auto_detect_controls(self, data) -> List[Dict]:
        """
        Automatically find the controls array in the JSON structure.

        Strategy:
        1. If data is a list of dicts, use it directly
        2. If data is a dict, search for likely control array keys
        3. Recursively search nested dicts for arrays of objects
        """
        # Case 1: Top-level array
        if isinstance(data, list):
            if all(isinstance(item, dict) for item in data):
                return data
            return []

        # Case 2: Dict — search for known control keys
        if isinstance(data, dict):
            # Priority keys that commonly contain control arrays
            control_keys = [
                "controls", "control_list", "findings", "results",
                "assessments", "audit_results", "compliance_data",
                "data", "items", "records",
            ]

            for key in control_keys:
                if key in data and isinstance(data[key], list):
                    if data[key] and isinstance(data[key][0], dict):
                        logger.debug(f"Found controls at key: '{key}'")
                        return data[key]

            # Recursive search in nested dicts
            for key, value in data.items():
                if isinstance(value, dict):
                    result = self._auto_detect_controls(value)
                    if result:
                        logger.debug(f"Found controls nested under: '{key}'")
                        return result

        return []

    def _traverse_key_path(self, data, key_path: str) -> Optional[List[Dict]]:
        """
        Traverse a dotted key path (e.g., 'data.audit.controls') into nested data.
        """
        current = data
        for key in key_path.split("."):
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                logger.warning(f"Key path '{key_path}' not found in data")
                return None

        if isinstance(current, list):
            return current
        return None
