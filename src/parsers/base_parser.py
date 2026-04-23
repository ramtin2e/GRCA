"""
Base parser — abstract interface for all GRC report parsers.

Each parser subclass handles one file format (CSV, JSON, PDF, XLSX)
and normalizes the data into a uniform List[Control] output.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional

from src.models.control import Control, ControlStatus
from src.utils.logger import get_logger

logger = get_logger(__name__)


# Standard column name aliases — parsers try these in order
DEFAULT_COLUMN_ALIASES: Dict[str, List[str]] = {
    "control_id": [
        "Control_ID", "control_id", "ID", "ControlID",
        "control_identifier", "Ctrl_ID", "ctrl_id",
    ],
    "control_name": [
        "Control_Name", "control_name", "Name", "name", "ControlName",
        "title", "Title", "Control",
    ],
    "description": [
        "Description", "description", "Details", "details",
        "Control_Description", "control_description",
    ],
    "status": [
        "Status", "status", "Implementation_Status", "impl_status",
        "state", "State", "Compliance_Status",
    ],
    "framework": [
        "Framework", "framework", "Standard", "standard",
        "Regulation", "regulation",
    ],
    "category": [
        "Category", "category", "Function", "function",
        "Domain", "domain", "Control_Family", "family",
    ],
    "severity": [
        "Severity", "severity", "Priority", "priority",
        "Risk_Level", "risk_level", "Criticality",
    ],
    "notes": [
        "Notes", "notes", "Comments", "comments",
        "Findings", "findings", "Evidence", "evidence",
    ],
}

# Status string normalization
STATUS_ALIASES: Dict[str, ControlStatus] = {
    "implemented": ControlStatus.IMPLEMENTED,
    "complete": ControlStatus.IMPLEMENTED,
    "compliant": ControlStatus.IMPLEMENTED,
    "yes": ControlStatus.IMPLEMENTED,
    "pass": ControlStatus.IMPLEMENTED,
    "met": ControlStatus.IMPLEMENTED,
    "partial": ControlStatus.PARTIAL,
    "partially implemented": ControlStatus.PARTIAL,
    "in progress": ControlStatus.PARTIAL,
    "partial compliance": ControlStatus.PARTIAL,
    "missing": ControlStatus.MISSING,
    "not implemented": ControlStatus.MISSING,
    "non-compliant": ControlStatus.MISSING,
    "no": ControlStatus.MISSING,
    "fail": ControlStatus.MISSING,
    "not met": ControlStatus.MISSING,
    "gap": ControlStatus.MISSING,
    "not applicable": ControlStatus.NOT_APPLICABLE,
    "n/a": ControlStatus.NOT_APPLICABLE,
    "na": ControlStatus.NOT_APPLICABLE,
}


class BaseParser(ABC):
    """
    Abstract base class for GRC report parsers.

    Subclasses implement _parse_raw() to extract records from their
    specific format. The base class handles normalization, validation,
    and status string resolution.
    """

    def __init__(
        self,
        column_aliases: Optional[Dict[str, List[str]]] = None,
        default_framework: str = "UNKNOWN",
    ):
        """
        Initialize parser with column mapping configuration.

        Args:
            column_aliases: Custom column name aliases. Merged with defaults.
            default_framework: Framework name to use when not present in data.
        """
        self.column_aliases = {**DEFAULT_COLUMN_ALIASES}
        if column_aliases:
            self.column_aliases.update(column_aliases)
        self.default_framework = default_framework

    def parse(self, file_path: str | Path) -> List[Control]:
        """
        Parse a GRC report file and return normalized Control objects.

        Args:
            file_path: Path to the report file.

        Returns:
            List of Control objects extracted from the report.

        Raises:
            FileNotFoundError: If the file doesn't exist.
            ValueError: If the file contains no valid controls.
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"Report file not found: {file_path}")

        logger.info(f"Parsing report: {file_path.name}")
        raw_records = self._parse_raw(file_path)

        if not raw_records:
            raise ValueError(f"No records found in {file_path.name}")

        controls = []
        for i, record in enumerate(raw_records):
            try:
                control = self._normalize_record(record)
                if control:
                    controls.append(control)
            except Exception as e:
                logger.warning(f"Skipping record {i + 1}: {e}")

        logger.info(f"Successfully parsed {len(controls)} controls from {file_path.name}")
        return controls

    @abstractmethod
    def _parse_raw(self, file_path: Path) -> List[Dict]:
        """
        Extract raw records from the file.

        Subclasses implement this to handle their specific format.

        Args:
            file_path: Path to the file to parse.

        Returns:
            List of dictionaries, each representing one control record.
        """
        ...

    def _normalize_record(self, record: Dict) -> Optional[Control]:
        """
        Normalize a raw record dictionary into a Control object.

        Resolves column aliases, normalizes status strings, and
        fills in defaults for missing fields.
        """
        # Resolve field values using column aliases
        control_id = self._resolve_field(record, "control_id")
        if not control_id:
            return None  # ID is mandatory

        status_str = self._resolve_field(record, "status") or "Missing"
        status = self._normalize_status(status_str)

        return Control(
            id=control_id,
            name=self._resolve_field(record, "control_name") or control_id,
            description=self._resolve_field(record, "description") or "",
            framework=self._resolve_field(record, "framework") or self.default_framework,
            category=self._resolve_field(record, "category") or "",
            status=status,
            severity=self._resolve_field(record, "severity"),
            notes=self._resolve_field(record, "notes"),
        )

    def _resolve_field(self, record: Dict, field_name: str) -> Optional[str]:
        """
        Look up a field value trying all known aliases.

        Args:
            record: Raw record dictionary.
            field_name: Canonical field name to resolve.

        Returns:
            The field value if found, None otherwise.
        """
        aliases = self.column_aliases.get(field_name, [field_name])
        for alias in aliases:
            if alias in record and record[alias] is not None:
                value = str(record[alias]).strip()
                if value and value.lower() != "nan":
                    return value
        return None

    @staticmethod
    def _normalize_status(status_str: str) -> ControlStatus:
        """
        Normalize a status string to a ControlStatus enum.

        Handles various formats: "Implemented", "implemented",
        "PARTIAL", "In Progress", "N/A", etc.
        """
        normalized = status_str.strip().lower()
        if normalized in STATUS_ALIASES:
            return STATUS_ALIASES[normalized]

        # Fuzzy match — check if any alias is contained in the string
        for alias, status in STATUS_ALIASES.items():
            if alias in normalized:
                return status

        logger.warning(f"Unknown status '{status_str}', defaulting to MISSING")
        return ControlStatus.MISSING
