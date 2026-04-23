"""
Parser factory — auto-selects the correct parser based on file extension.

Provides a single entry point for report ingestion regardless of format.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from src.parsers.base_parser import BaseParser
from src.parsers.csv_parser import CSVParser
from src.parsers.json_parser import JSONParser
from src.parsers.pdf_parser import PDFParser
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Extension → Parser class mapping
PARSER_MAP: Dict[str, type] = {
    ".csv": CSVParser,
    ".tsv": CSVParser,
    ".xlsx": CSVParser,
    ".xls": CSVParser,
    ".json": JSONParser,
    ".pdf": PDFParser,
}


def get_parser(
    file_path: str | Path,
    default_framework: str = "UNKNOWN",
    **kwargs,
) -> BaseParser:
    """
    Get the appropriate parser for a given file.

    Auto-detects the format from the file extension and returns
    an initialized parser instance.

    Args:
        file_path: Path to the GRC report file.
        default_framework: Framework name to use when not in the data.
        **kwargs: Additional arguments passed to the parser constructor.

    Returns:
        An initialized parser ready to call .parse().

    Raises:
        ValueError: If the file extension is not supported.
        FileNotFoundError: If the file doesn't exist.
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    suffix = file_path.suffix.lower()

    if suffix not in PARSER_MAP:
        supported = ", ".join(sorted(PARSER_MAP.keys()))
        raise ValueError(
            f"Unsupported file format: '{suffix}'. "
            f"Supported formats: {supported}"
        )

    parser_class = PARSER_MAP[suffix]
    logger.info(f"Selected {parser_class.__name__} for {file_path.name}")

    return parser_class(default_framework=default_framework, **kwargs)


def parse_file(
    file_path: str | Path,
    default_framework: str = "UNKNOWN",
    **kwargs,
) -> List:
    """
    Convenience function: parse a file in one call.

    Args:
        file_path: Path to the GRC report file.
        default_framework: Framework name to use when not in the data.
        **kwargs: Additional arguments passed to the parser.

    Returns:
        List of Control objects.
    """
    parser = get_parser(file_path, default_framework=default_framework, **kwargs)
    return parser.parse(file_path)


def get_supported_formats() -> List[str]:
    """Return list of supported file extensions."""
    return sorted(PARSER_MAP.keys())
