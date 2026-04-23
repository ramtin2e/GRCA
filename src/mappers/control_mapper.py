"""
Control Mapper — maps compliance controls to MITRE ATT&CK techniques.

Loads mapping JSON files that define which ATT&CK techniques each
control mitigates, and provides lookup methods for gap analysis.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from src.utils.logger import get_logger
from src.utils.paths import get_resource_path

logger = get_logger(__name__)

# Framework name → mapping file name
FRAMEWORK_MAPPING_FILES = {
    "NIST_CSF": "nist_csf2_to_attack.json",
    "nist-csf2": "nist_csf2_to_attack.json",
    "nist-csf1": "nist_csf1_to_attack.json",
    "ISO_27001": "iso27001_to_attack.json",
    "iso27001": "iso27001_to_attack.json",
    "SOC2": "soc2_to_attack.json",
    "soc2": "soc2_to_attack.json",
    "CIS_CONTROLS": "cis_controls_to_attack.json",
    "cis": "cis_controls_to_attack.json",
}


class ControlMapper:
    """
    Maps GRC controls to MITRE ATT&CK techniques.

    Loads framework-specific mapping files and provides methods
    to look up which techniques a control mitigates (or which
    techniques are exposed when a control is missing).
    """

    def __init__(self, mappings_dir: str | Path = "data/mappings"):
        self.mappings_dir = get_resource_path(str(mappings_dir))
        self._mappings: Dict[str, Dict] = {}
        self._technique_info: Dict[str, Dict] = {}
        self._load_all_mappings()

    def _load_all_mappings(self) -> None:
        """Load all available mapping files from the mappings directory."""
        if not self.mappings_dir.exists():
            logger.warning(f"Mappings directory not found: {self.mappings_dir}")
            return

        for file_path in self.mappings_dir.glob("*.json"):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                framework_key = file_path.stem  # e.g., "nist_csf2_to_attack"
                self._mappings[framework_key] = data

                # Build technique info cache
                for control_id, mapping in data.items():
                    if isinstance(mapping, dict):
                        for tech_id in mapping.get("mitigates_techniques", []):
                            if tech_id not in self._technique_info:
                                self._technique_info[tech_id] = {
                                    "name": "",
                                    "tactics": mapping.get("tactics", []),
                                }

                logger.debug(f"Loaded mapping: {file_path.name} ({len(data)} controls)")
            except Exception as e:
                logger.error(f"Failed to load mapping {file_path.name}: {e}")

        logger.info(f"Loaded {len(self._mappings)} mapping files")

    def _get_mapping_for_framework(self, framework: str) -> Optional[Dict]:
        """Get the mapping data for a framework."""
        # Try direct mapping file lookup
        mapping_file = FRAMEWORK_MAPPING_FILES.get(framework)
        if mapping_file:
            stem = mapping_file.replace(".json", "")
            if stem in self._mappings:
                return self._mappings[stem]

        # Fallback: search all mappings for the control
        return None

    def map_control_to_techniques(self, control_id: str, framework: str = "") -> List[str]:
        """
        Get ATT&CK technique IDs mitigated by a control.

        Args:
            control_id: Control identifier (e.g., "PR.AA-01").
            framework: Framework name for targeted lookup.

        Returns:
            List of technique IDs (e.g., ["T1078", "T1110"]).
        """
        # Try framework-specific mapping first
        mapping = self._get_mapping_for_framework(framework)
        if mapping and control_id in mapping:
            return mapping[control_id].get("mitigates_techniques", [])

        # Search all mappings
        for mapping_data in self._mappings.values():
            if control_id in mapping_data:
                entry = mapping_data[control_id]
                if isinstance(entry, dict):
                    return entry.get("mitigates_techniques", [])

        return []

    def get_technique_info(self, technique_id: str) -> Dict:
        """
        Get info about a technique.

        Returns:
            Dict with "name" and "tactics" keys.
        """
        return self._technique_info.get(technique_id, {"name": technique_id, "tactics": []})

    def get_techniques_by_tactic(self) -> Dict[str, List[str]]:
        """
        Get all known techniques grouped by tactic.

        Returns:
            Dict of tactic → list of technique IDs.
        """
        by_tactic: Dict[str, List[str]] = {}

        for tech_id, info in self._technique_info.items():
            for tactic in info.get("tactics", []):
                if tactic not in by_tactic:
                    by_tactic[tactic] = []
                if tech_id not in by_tactic[tactic]:
                    by_tactic[tactic].append(tech_id)

        return by_tactic

    def get_all_mapped_controls(self, framework: str = "") -> List[str]:
        """Get all control IDs that have ATT&CK mappings."""
        controls = set()

        if framework:
            mapping = self._get_mapping_for_framework(framework)
            if mapping:
                controls.update(mapping.keys())
        else:
            for mapping_data in self._mappings.values():
                controls.update(mapping_data.keys())

        return sorted(controls)
