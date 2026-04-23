"""
Gap Analyzer — core engine that identifies compliance gaps.

Takes a list of parsed controls and a compliance profile, produces
a full GapAnalysisResult with tier/framework summaries and prioritized findings.
"""

from __future__ import annotations

from typing import Dict, List

from src.models.compliance_profile import ComplianceProfile
from src.models.control import ComplianceTier, Control, ControlStatus
from src.models.gap import GapFinding
from src.models.report import FrameworkSummary, GapAnalysisResult, TierSummary
from src.utils.logger import get_logger

logger = get_logger(__name__)


class GapAnalyzer:
    """
    Identifies compliance gaps and produces a prioritized analysis result.

    Pipeline:
    1. Apply compliance tier from profile to each control
    2. Identify gaps (MISSING/PARTIAL controls)
    3. Create GapFinding objects with weighted scores
    4. Aggregate into tier and framework summaries
    5. Sort findings by weighted score (highest priority first)
    """

    def __init__(self, profile: ComplianceProfile | None = None):
        self.profile = profile or ComplianceProfile.default()

    def analyze(self, controls: List[Control]) -> GapAnalysisResult:
        """
        Run gap analysis on a list of controls.

        Args:
            controls: Parsed controls from report ingestion.

        Returns:
            Complete GapAnalysisResult with findings and summaries.
        """
        logger.info(f"Starting gap analysis on {len(controls)} controls")
        logger.info(f"Using profile: {self.profile.profile_name}")

        # Step 1: Apply compliance tiers
        self._apply_tiers(controls)

        # Step 2: Identify gaps and create findings
        findings = self._identify_gaps(controls)

        # Step 3: Sort by weighted score (highest first)
        findings.sort(key=lambda f: f.weighted_score, reverse=True)

        # Step 4: Build summaries
        tier_summaries = self._build_tier_summaries(controls)
        framework_summaries = self._build_framework_summaries(controls)

        result = GapAnalysisResult(
            profile_name=self.profile.profile_name,
            total_controls_analyzed=len(controls),
            findings=findings,
            tier_summaries=tier_summaries,
            framework_summaries=framework_summaries,
        )

        logger.info(
            f"Analysis complete: {result.total_gaps} gaps found, "
            f"compliance score: {result.overall_compliance_score}%"
        )

        return result

    def _apply_tiers(self, controls: List[Control]) -> None:
        """Apply compliance tier from the profile to each control."""
        for control in controls:
            control.tier = self.profile.get_tier(control.framework, control.id)

    def _identify_gaps(self, controls: List[Control]) -> List[GapFinding]:
        """Create GapFinding objects for all non-compliant controls."""
        findings = []

        for control in controls:
            if not control.is_gap():
                continue

            finding = GapFinding(
                control_id=control.id,
                control_name=control.name,
                framework=control.framework,
                category=control.category,
                status=control.status,
                tier=control.tier,
                severity=control.severity,
                notes=control.notes,
            )
            findings.append(finding)

        logger.info(f"Identified {len(findings)} gap findings")
        return findings

    def _build_tier_summaries(self, controls: List[Control]) -> Dict[str, TierSummary]:
        """Aggregate control counts by compliance tier."""
        summaries: Dict[str, TierSummary] = {}

        for tier in ComplianceTier:
            tier_controls = [c for c in controls if c.tier == tier]
            if not tier_controls:
                continue

            summaries[tier.value] = TierSummary(
                tier=tier,
                total_controls=len(tier_controls),
                implemented=sum(1 for c in tier_controls if c.status == ControlStatus.IMPLEMENTED),
                partial=sum(1 for c in tier_controls if c.status == ControlStatus.PARTIAL),
                missing=sum(1 for c in tier_controls if c.status == ControlStatus.MISSING),
                not_applicable=sum(1 for c in tier_controls if c.status == ControlStatus.NOT_APPLICABLE),
            )

        return summaries

    def _build_framework_summaries(self, controls: List[Control]) -> Dict[str, FrameworkSummary]:
        """Aggregate control counts by framework."""
        summaries: Dict[str, FrameworkSummary] = {}
        frameworks = set(c.framework for c in controls)

        for fw in frameworks:
            fw_controls = [c for c in controls if c.framework == fw]
            tier = fw_controls[0].tier if fw_controls else ComplianceTier.REQUIRED

            summaries[fw] = FrameworkSummary(
                framework=fw,
                tier=tier,
                total_controls=len(fw_controls),
                implemented=sum(1 for c in fw_controls if c.status == ControlStatus.IMPLEMENTED),
                partial=sum(1 for c in fw_controls if c.status == ControlStatus.PARTIAL),
                missing=sum(1 for c in fw_controls if c.status == ControlStatus.MISSING),
            )

        return summaries
