"""
PDF parser — extracts control data from structured PDF compliance reports.

Uses pdfplumber for table extraction. Handles structured PDFs with
consistent table formatting. Unstructured/narrative PDFs are out of
scope for Phase 1 (planned LLM-based extraction in Phase 2).
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from src.parsers.base_parser import BaseParser
from src.utils.logger import get_logger

logger = get_logger(__name__)


class PDFParser(BaseParser):
    """
    Parser for PDF-formatted GRC compliance reports.

    Extracts tabular data from structured PDFs using pdfplumber.
    Works best with audit reports that contain consistent table layouts.

    Limitations:
        - Requires tables with headers in the first row
        - May struggle with merged cells or complex layouts
        - Narrative-only PDFs require Phase 2 LLM extraction
    """

    def __init__(
        self,
        column_aliases: Optional[Dict[str, List[str]]] = None,
        default_framework: str = "UNKNOWN",
        table_strategy: str = "text",
        min_table_rows: int = 2,
    ):
        """
        Initialize PDF parser.

        Args:
            column_aliases: Custom column name aliases.
            default_framework: Fallback framework name.
            table_strategy: pdfplumber extraction strategy ('text' or 'lines').
            min_table_rows: Minimum rows for a valid table (filters noise).
        """
        super().__init__(column_aliases=column_aliases, default_framework=default_framework)
        self.table_strategy = table_strategy
        self.min_table_rows = min_table_rows

    def _parse_raw(self, file_path: Path) -> List[Dict]:
        """
        Extract table data from all pages of a PDF.

        Scans every page for tables, combines them, and returns
        records as dictionaries using the first row as headers.
        """
        try:
            import pdfplumber
        except ImportError:
            raise ImportError(
                "pdfplumber is required for PDF parsing. "
                "Install it with: pip install pdfplumber"
            )

        all_records: List[Dict] = []
        headers = None

        with pdfplumber.open(file_path) as pdf:
            logger.info(f"Opened PDF: {file_path.name} ({len(pdf.pages)} pages)")

            for page_num, page in enumerate(pdf.pages, 1):
                tables = page.extract_tables(
                    table_settings={"text_strategy": self.table_strategy}
                )

                if not tables:
                    continue

                for table in tables:
                    if len(table) < self.min_table_rows:
                        continue

                    # First table row is headers (unless we already have them)
                    if headers is None:
                        headers = [
                            self._clean_header(h) for h in table[0] if h
                        ]
                        data_rows = table[1:]
                    else:
                        # Check if this table has the same headers
                        potential_headers = [
                            self._clean_header(h) for h in table[0] if h
                        ]
                        if potential_headers == headers:
                            data_rows = table[1:]
                        else:
                            data_rows = table

                    for row in data_rows:
                        if len(row) >= len(headers):
                            record = {
                                headers[i]: self._clean_cell(row[i])
                                for i in range(len(headers))
                            }
                            if any(v for v in record.values()):
                                all_records.append(record)

                logger.debug(
                    f"Page {page_num}: extracted {len(tables)} tables"
                )

        logger.info(f"Extracted {len(all_records)} records from PDF")
        return all_records

    @staticmethod
    def _clean_header(header: Optional[str]) -> str:
        """Clean and normalize a table header string."""
        if not header:
            return "unknown"
        # Remove newlines, extra whitespace, and special characters
        cleaned = header.replace("\n", " ").strip()
        cleaned = " ".join(cleaned.split())  # Collapse whitespace
        return cleaned

    @staticmethod
    def _clean_cell(cell: Optional[str]) -> Optional[str]:
        """Clean a table cell value."""
        if cell is None:
            return None
        cleaned = cell.replace("\n", " ").strip()
        cleaned = " ".join(cleaned.split())
        return cleaned if cleaned else None
