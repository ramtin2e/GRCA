"""Tests for report parsers (CSV, JSON)."""

import sys
import json
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parsers.csv_parser import CSVParser
from src.parsers.json_parser import JSONParser
from src.parsers.parser_factory import get_parser, get_supported_formats
from src.models.control import ControlStatus


class TestCSVParser:
    """Tests for CSV/Excel parser."""

    def test_parse_sample_nist(self):
        """Parse the sample NIST CSF 2.0 assessment."""
        parser = CSVParser(default_framework="NIST_CSF")
        sample = Path("data/sample_reports/sample_nist_csf2_assessment.csv")
        if not sample.exists():
            pytest.skip("Sample data not found")

        controls = parser.parse(sample)

        assert len(controls) > 0
        assert all(c.framework == "NIST_CSF" for c in controls)

        # Check we have a mix of statuses
        statuses = set(c.status for c in controls)
        assert ControlStatus.IMPLEMENTED in statuses
        assert ControlStatus.MISSING in statuses

    def test_parse_csv_with_aliases(self):
        """Parse CSV with non-standard column names."""
        csv_content = "ID,Title,State,Standard\nCTRL-1,Test Control,Implemented,NIST\n"

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, dir="."
        ) as f:
            f.write(csv_content)
            f.flush()
            temp_path = f.name

        try:
            parser = CSVParser(default_framework="TEST")
            controls = parser.parse(temp_path)

            assert len(controls) == 1
            assert controls[0].id == "CTRL-1"
            assert controls[0].status == ControlStatus.IMPLEMENTED
        finally:
            Path(temp_path).unlink()

    def test_status_normalization(self):
        """Verify various status strings are normalized correctly."""
        csv_content = (
            "Control_ID,Control_Name,Status,Framework\n"
            "C1,Test1,Implemented,TEST\n"
            "C2,Test2,Partial,TEST\n"
            "C3,Test3,Missing,TEST\n"
            "C4,Test4,N/A,TEST\n"
            "C5,Test5,In Progress,TEST\n"
            "C6,Test6,compliant,TEST\n"
            "C7,Test7,non-compliant,TEST\n"
        )

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, dir="."
        ) as f:
            f.write(csv_content)
            f.flush()
            temp_path = f.name

        try:
            parser = CSVParser()
            controls = parser.parse(temp_path)

            status_map = {c.id: c.status for c in controls}
            assert status_map["C1"] == ControlStatus.IMPLEMENTED
            assert status_map["C2"] == ControlStatus.PARTIAL
            assert status_map["C3"] == ControlStatus.MISSING
            assert status_map["C4"] == ControlStatus.NOT_APPLICABLE
            assert status_map["C5"] == ControlStatus.PARTIAL
            assert status_map["C6"] == ControlStatus.IMPLEMENTED
            assert status_map["C7"] == ControlStatus.MISSING
        finally:
            Path(temp_path).unlink()


class TestJSONParser:
    """Tests for JSON parser."""

    def test_parse_sample_iso(self):
        """Parse the sample ISO 27001 audit."""
        parser = JSONParser(default_framework="ISO_27001")
        sample = Path("data/sample_reports/sample_iso27001_audit.json")
        if not sample.exists():
            pytest.skip("Sample data not found")

        controls = parser.parse(sample)
        assert len(controls) > 0

    def test_parse_flat_array(self):
        """Parse a flat JSON array of controls."""
        data = [
            {"control_id": "C1", "Control_Name": "Test", "Status": "Implemented", "Framework": "TEST"},
            {"control_id": "C2", "Control_Name": "Test2", "Status": "Missing", "Framework": "TEST"},
        ]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, dir="."
        ) as f:
            json.dump(data, f)
            f.flush()
            temp_path = f.name

        try:
            parser = JSONParser()
            controls = parser.parse(temp_path)
            assert len(controls) == 2
        finally:
            Path(temp_path).unlink()

    def test_parse_nested_structure(self):
        """Parse nested JSON with controls under a key."""
        data = {
            "audit_date": "2026-01-01",
            "controls": [
                {"control_id": "A.1", "name": "Test", "status": "Implemented"},
            ],
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, dir="."
        ) as f:
            json.dump(data, f)
            f.flush()
            temp_path = f.name

        try:
            parser = JSONParser(default_framework="ISO")
            controls = parser.parse(temp_path)
            assert len(controls) == 1
            assert controls[0].id == "A.1"
        finally:
            Path(temp_path).unlink()


class TestParserFactory:
    """Tests for parser factory."""

    def test_supported_formats(self):
        """Check all expected formats are supported."""
        formats = get_supported_formats()
        assert ".csv" in formats
        assert ".json" in formats
        assert ".xlsx" in formats
        assert ".pdf" in formats

    def test_csv_selection(self):
        """Factory selects CSVParser for .csv files."""
        sample = Path("data/sample_reports/sample_nist_csf2_assessment.csv")
        if not sample.exists():
            pytest.skip("Sample data not found")
        parser = get_parser(sample)
        assert parser.__class__.__name__ == "CSVParser"

    def test_json_selection(self):
        """Factory selects JSONParser for .json files."""
        sample = Path("data/sample_reports/sample_iso27001_audit.json")
        if not sample.exists():
            pytest.skip("Sample data not found")
        parser = get_parser(sample)
        assert parser.__class__.__name__ == "JSONParser"

    def test_unsupported_format(self):
        """Factory raises error for unsupported formats."""
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False, dir=".") as f:
            temp_path = f.name

        try:
            with pytest.raises(ValueError, match="Unsupported"):
                get_parser(temp_path)
        finally:
            Path(temp_path).unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
