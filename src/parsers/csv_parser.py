"""
CSV and Excel parser — handles .csv and .xlsx GRC report ingestion.

Uses pandas for flexible parsing with configurable column mapping,
automatic header detection, and encoding handling.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

from src.parsers.base_parser import BaseParser
from src.utils.logger import get_logger

logger = get_logger(__name__)


class CSVParser(BaseParser):
    """
    Parser for CSV and Excel (.xlsx) GRC compliance reports.

    Supports:
        - Standard CSV files (comma, tab, semicolon delimited)
        - Excel workbooks (.xlsx) — reads first sheet by default
        - Automatic encoding detection
        - Configurable column name mapping
    """

    def __init__(
        self,
        column_aliases: Optional[Dict[str, List[str]]] = None,
        default_framework: str = "UNKNOWN",
        sheet_name: int | str = 0,
        encoding: str = "utf-8",
    ):
        """
        Initialize CSV/Excel parser.

        Args:
            column_aliases: Custom column name aliases.
            default_framework: Fallback framework name.
            sheet_name: Excel sheet to read (index or name). Ignored for CSV.
            encoding: File encoding for CSV files.
        """
        super().__init__(column_aliases=column_aliases, default_framework=default_framework)
        self.sheet_name = sheet_name
        self.encoding = encoding

    def _parse_raw(self, file_path: Path) -> List[Dict]:
        """
        Read CSV or Excel file into a list of record dictionaries.

        Args:
            file_path: Path to the CSV or XLSX file.

        Returns:
            List of dicts, one per row.
        """
        suffix = file_path.suffix.lower()

        try:
            if suffix == ".xlsx":
                df = pd.read_excel(
                    file_path,
                    sheet_name=self.sheet_name,
                    engine="openpyxl",
                    keep_default_na=False,
                )
                logger.info(f"Read Excel file: {file_path.name} (sheet: {self.sheet_name})")
            elif suffix in (".csv", ".tsv"):
                # Try to detect delimiter
                df = self._read_csv_smart(file_path)
                logger.info(f"Read CSV file: {file_path.name}")
            else:
                raise ValueError(f"Unsupported file format: {suffix}")

        except UnicodeDecodeError:
            # Retry with latin-1 encoding
            logger.warning(f"UTF-8 decode failed, retrying with latin-1: {file_path.name}")
            df = pd.read_csv(file_path, encoding="latin-1", keep_default_na=False)

        # Drop completely empty rows
        df = df.dropna(how="all")

        logger.info(f"Found {len(df)} rows and {len(df.columns)} columns")
        logger.debug(f"Columns: {list(df.columns)}")

        return df.to_dict(orient="records")

    def _read_csv_smart(self, file_path: Path) -> pd.DataFrame:
        """
        Read a CSV file with automatic delimiter detection.

        Tries comma first, then falls back to tab and semicolon.
        """
        # Read first few bytes to detect delimiter
        with open(file_path, "r", encoding=self.encoding) as f:
            sample = f.read(2048)

        # Count potential delimiters in the sample
        delimiters = {
            ",": sample.count(","),
            "\t": sample.count("\t"),
            ";": sample.count(";"),
            "|": sample.count("|"),
        }

        # Use the most common delimiter
        best_delimiter = max(delimiters, key=delimiters.get)
        if delimiters[best_delimiter] == 0:
            best_delimiter = ","  # Default fallback

        logger.debug(f"Detected delimiter: {repr(best_delimiter)}")

        return pd.read_csv(
            file_path,
            delimiter=best_delimiter,
            encoding=self.encoding,
            keep_default_na=False,
        )
