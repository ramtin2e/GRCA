"""Tests for gap analyzer."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.models.control import Control, ControlStatus, ComplianceTier
from src.models.compliance_profile import ComplianceProfile, FrameworkConfig
from src.analyzers.gap_analyzer import GapAnalyzer


def make_control(id, status, framework="NIST_CSF", severity="High"):
    """Helper to create a test control."""
    return Control(
        id=id,
        name=f"Test Control {id}",
        description="Test",
        framework=framework,
        category="Test",
        status=ControlStatus(status),
        severity=severity,
    )


class TestGapAnalyzer:
    """Tests for the core gap analysis engine."""

    def setup_method(self):
        """Set up test fixtures."""
        self.controls = [
            make_control("C1", "Implemented"),
            make_control("C2", "Partial", severity="Critical"),
            make_control("C3", "Missing", severity="Critical"),
            make_control("C4", "Implemented"),
            make_control("C5", "Missing", severity="Medium"),
            make_control("C6", "Partial", severity="High"),
        ]

    def test_default_profile_analysis(self):
        """Analyze with default (all REQUIRED) profile."""
        analyzer = GapAnalyzer()
        result = analyzer.analyze(self.controls)

        assert result.total_controls_analyzed == 6
        assert result.total_gaps == 4  # C2, C3, C5, C6
        assert result.critical_findings_count >= 0

    def test_findings_sorted_by_score(self):
        """Findings should be sorted by weighted score descending."""
        analyzer = GapAnalyzer()
        result = analyzer.analyze(self.controls)

        scores = [f.weighted_score for f in result.findings]
        assert scores == sorted(scores, reverse=True)

    def test_tier_summaries_correct(self):
        """Tier summary counts should match control statuses."""
        analyzer = GapAnalyzer()
        result = analyzer.analyze(self.controls)

        # All controls are REQUIRED by default
        req_summary = result.tier_summaries.get("REQUIRED")
        assert req_summary is not None
        assert req_summary.total_controls == 6
        assert req_summary.implemented == 2
        assert req_summary.partial == 2
        assert req_summary.missing == 2

    def test_tiered_profile_scoring(self):
        """Controls in different tiers should get different scores."""
        profile = ComplianceProfile(
            profile_name="Test Tiered",
            frameworks={
                "NIST_CSF": FrameworkConfig(
                    tier=ComplianceTier.REQUIRED,
                    overrides={
                        "C5": ComplianceTier.NICE_TO_HAVE,
                    },
                ),
            },
        )

        analyzer = GapAnalyzer(profile=profile)
        result = analyzer.analyze(self.controls)

        # Find C3 (REQUIRED + Missing + Critical) and C5 (NICE_TO_HAVE + Missing + Medium)
        c3 = next(f for f in result.findings if f.control_id == "C3")
        c5 = next(f for f in result.findings if f.control_id == "C5")

        # C3 should score much higher than C5
        assert c3.weighted_score > c5.weighted_score
        assert c3.tier == ComplianceTier.REQUIRED
        assert c5.tier == ComplianceTier.NICE_TO_HAVE

    def test_compliance_score_calculation(self):
        """Overall compliance score should reflect implementation status."""
        analyzer = GapAnalyzer()
        result = analyzer.analyze(self.controls)

        # Score should be between 0 and 100
        assert 0 <= result.overall_compliance_score <= 100
        # With 2 implemented, 2 partial, 2 missing out of 6, score should be moderate
        assert result.overall_compliance_score < 100

    def test_no_gaps_means_100_compliance(self):
        """All implemented controls should yield 100% compliance."""
        all_good = [
            make_control("C1", "Implemented"),
            make_control("C2", "Implemented"),
        ]
        analyzer = GapAnalyzer()
        result = analyzer.analyze(all_good)

        assert result.total_gaps == 0
        assert result.overall_compliance_score == 100.0

    def test_framework_summaries(self):
        """Framework summaries should group controls correctly."""
        mixed = [
            make_control("N1", "Implemented", framework="NIST_CSF"),
            make_control("N2", "Missing", framework="NIST_CSF"),
            make_control("I1", "Partial", framework="ISO_27001"),
        ]

        analyzer = GapAnalyzer()
        result = analyzer.analyze(mixed)

        assert "NIST_CSF" in result.framework_summaries
        assert "ISO_27001" in result.framework_summaries
        assert result.framework_summaries["NIST_CSF"].total_controls == 2
        assert result.framework_summaries["ISO_27001"].total_controls == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
