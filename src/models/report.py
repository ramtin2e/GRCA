"""
Gap Analysis Result model — aggregates all findings into a structured report.

This is the top-level output of the gap analysis pipeline, containing
tier-level summaries, framework breakdowns, prioritized gap lists,
and ATT&CK exposure data.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, computed_field

from src.models.control import ComplianceTier
from src.models.gap import GapFinding
from src.models.threat import ThreatExposure


class TierSummary(BaseModel):
    """Summary statistics for a single compliance tier."""

    tier: ComplianceTier
    total_controls: int = 0
    implemented: int = 0
    partial: int = 0
    missing: int = 0
    not_applicable: int = 0

    @computed_field
    @property
    def compliance_percentage(self) -> float:
        """Percentage of controls fully implemented in this tier."""
        applicable = self.total_controls - self.not_applicable
        if applicable == 0:
            return 100.0
        return round((self.implemented / applicable) * 100, 1)

    @computed_field
    @property
    def gap_count(self) -> int:
        """Total number of gaps (missing + partial) in this tier."""
        return self.missing + self.partial


class FrameworkSummary(BaseModel):
    """Summary statistics for a single compliance framework."""

    framework: str
    tier: ComplianceTier
    total_controls: int = 0
    implemented: int = 0
    partial: int = 0
    missing: int = 0

    @computed_field
    @property
    def compliance_percentage(self) -> float:
        """Percentage of controls implemented."""
        if self.total_controls == 0:
            return 100.0
        return round((self.implemented / self.total_controls) * 100, 1)


class GapAnalysisResult(BaseModel):
    """
    Complete output of the gap analysis pipeline.

    Contains everything needed to generate reports, ATT&CK Navigator
    layers, and remediation roadmaps.
    """

    # Metadata
    analysis_timestamp: datetime = Field(default_factory=datetime.now)
    profile_name: str = Field(default="", description="Compliance profile used")
    total_controls_analyzed: int = 0

    # Gap findings — sorted by weighted_score descending
    findings: List[GapFinding] = Field(
        default_factory=list, description="All identified gaps, priority-sorted"
    )

    # Tier-level summaries
    tier_summaries: Dict[str, TierSummary] = Field(
        default_factory=dict, description="Compliance stats per tier"
    )

    # Framework-level summaries
    framework_summaries: Dict[str, FrameworkSummary] = Field(
        default_factory=dict, description="Compliance stats per framework"
    )

    # ATT&CK exposure (populated by coverage analyzer)
    threat_exposures: List[ThreatExposure] = Field(
        default_factory=list, description="ATT&CK techniques exposed by gaps"
    )
    attack_coverage: Optional[Dict[str, float]] = Field(
        default=None, description="Coverage percentage per ATT&CK tactic"
    )

    @computed_field
    @property
    def total_gaps(self) -> int:
        """Total number of gap findings."""
        return len(self.findings)

    @computed_field
    @property
    def overall_compliance_score(self) -> float:
        """
        Weighted compliance score (0–100).

        Accounts for tier weights — REQUIRED gaps drag the score
        down more than NICE_TO_HAVE gaps.
        """
        if self.total_controls_analyzed == 0:
            return 100.0

        max_possible = 0.0
        achieved = 0.0

        for tier_name, summary in self.tier_summaries.items():
            tier = ComplianceTier(tier_name)
            applicable = summary.total_controls - summary.not_applicable
            max_possible += applicable * tier.weight
            achieved += summary.implemented * tier.weight
            # Partial controls get half credit
            achieved += summary.partial * tier.weight * 0.5

        if max_possible == 0:
            return 100.0

        return round((achieved / max_possible) * 100, 1)

    @computed_field
    @property
    def critical_findings_count(self) -> int:
        """Number of P1-Critical findings."""
        return sum(1 for f in self.findings if f.remediation_priority == "P1 - Critical")

    @computed_field
    @property
    def high_findings_count(self) -> int:
        """Number of P2-High findings."""
        return sum(1 for f in self.findings if f.remediation_priority == "P2 - High")

    def get_findings_by_tier(self, tier: ComplianceTier) -> List[GapFinding]:
        """Get all findings for a specific compliance tier."""
        return [f for f in self.findings if f.tier == tier]

    def get_findings_by_framework(self, framework: str) -> List[GapFinding]:
        """Get all findings for a specific framework."""
        return [f for f in self.findings if f.framework == framework]

    def get_top_findings(self, n: int = 10) -> List[GapFinding]:
        """Get the top N highest-priority findings."""
        return self.findings[:n]
