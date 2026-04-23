"""Tests for tier scorer and compliance profile."""

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.models.control import ComplianceTier
from src.models.compliance_profile import ComplianceProfile, FrameworkConfig
from src.models.gap import GapFinding
from src.models.control import ControlStatus
from src.analyzers.tier_scorer import TierScorer


class TestComplianceProfile:
    """Tests for compliance profile loading and tier resolution."""

    def test_load_default_profile(self):
        """Load the default profile YAML."""
        profile_path = Path("config/profiles/default_profile.yaml")
        if not profile_path.exists():
            pytest.skip("Default profile not found")

        profile = ComplianceProfile.from_yaml(profile_path)
        assert profile.profile_name == "Full Compliance Baseline"
        assert "NIST_CSF" in profile.frameworks

    def test_load_startup_profile(self):
        """Load the startup profile and verify tiers."""
        profile_path = Path("config/profiles/startup_profile.yaml")
        if not profile_path.exists():
            pytest.skip("Startup profile not found")

        profile = ComplianceProfile.from_yaml(profile_path)
        assert profile.frameworks["SOC2"].tier == ComplianceTier.REQUIRED
        assert profile.frameworks["NIST_CSF"].tier == ComplianceTier.DESIRED
        assert profile.frameworks["ISO_27001"].tier == ComplianceTier.NICE_TO_HAVE

    def test_per_control_overrides(self):
        """Per-control overrides should take priority."""
        profile_path = Path("config/profiles/startup_profile.yaml")
        if not profile_path.exists():
            pytest.skip("Startup profile not found")

        profile = ComplianceProfile.from_yaml(profile_path)

        # GV.OC-01 is overridden to NICE_TO_HAVE in NIST_CSF
        tier = profile.get_tier("NIST_CSF", "GV.OC-01")
        assert tier == ComplianceTier.NICE_TO_HAVE

        # A regular NIST control should be DESIRED (framework default)
        tier = profile.get_tier("NIST_CSF", "PR.AA-01")
        assert tier == ComplianceTier.DESIRED

    def test_unknown_framework_defaults_required(self):
        """Unknown frameworks should default to REQUIRED."""
        profile = ComplianceProfile.default()
        tier = profile.get_tier("UNKNOWN_FW", "CTRL-1")
        assert tier == ComplianceTier.REQUIRED

    def test_missing_profile_raises_error(self):
        """Loading a nonexistent profile should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            ComplianceProfile.from_yaml("nonexistent.yaml")


class TestGapFinding:
    """Tests for gap finding scoring."""

    def test_critical_required_missing(self):
        """Critical + REQUIRED + Missing = maximum score."""
        finding = GapFinding(
            control_id="C1",
            control_name="Test",
            framework="TEST",
            status=ControlStatus.MISSING,
            tier=ComplianceTier.REQUIRED,
            severity="Critical",
        )

        assert finding.weighted_score == 30.0  # 10 × 1.0 × 3.0
        assert finding.remediation_priority == "P1 - Critical"

    def test_medium_nice_partial(self):
        """Medium + NICE_TO_HAVE + Partial = low score."""
        finding = GapFinding(
            control_id="C2",
            control_name="Test",
            framework="TEST",
            status=ControlStatus.PARTIAL,
            tier=ComplianceTier.NICE_TO_HAVE,
            severity="Medium",
        )

        assert finding.weighted_score == 2.5  # 5 × 0.5 × 1.0
        assert finding.remediation_priority == "P4 - Low"

    def test_high_desired_missing(self):
        """High + DESIRED + Missing = moderate-high score."""
        finding = GapFinding(
            control_id="C3",
            control_name="Test",
            framework="TEST",
            status=ControlStatus.MISSING,
            tier=ComplianceTier.DESIRED,
            severity="High",
        )

        assert finding.weighted_score == 15.0  # 7.5 × 1.0 × 2.0
        assert finding.remediation_priority == "P2 - High"


class TestTierScorer:
    """Tests for tier scorer."""

    def test_remediation_roadmap_grouping(self):
        """Findings should be grouped by priority."""
        findings = [
            GapFinding(
                control_id="C1", control_name="T1", framework="TEST",
                status=ControlStatus.MISSING, tier=ComplianceTier.REQUIRED,
                severity="Critical",
            ),
            GapFinding(
                control_id="C2", control_name="T2", framework="TEST",
                status=ControlStatus.PARTIAL, tier=ComplianceTier.NICE_TO_HAVE,
                severity="Low",
            ),
        ]

        scorer = TierScorer()
        roadmap = scorer.get_remediation_roadmap(findings)

        assert len(roadmap["P1 - Critical"]) == 1
        assert roadmap["P1 - Critical"][0].control_id == "C1"


class TestComplianceTier:
    """Tests for tier enum properties."""

    def test_tier_weights(self):
        """Verify tier weight values."""
        assert ComplianceTier.REQUIRED.weight == 3.0
        assert ComplianceTier.DESIRED.weight == 2.0
        assert ComplianceTier.NICE_TO_HAVE.weight == 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
