"""
Gap Finding model — represents a single compliance gap identified during analysis.

A gap finding combines control metadata with tier-weighted scoring and
links to the ATT&CK techniques exposed by the missing/partial control.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, computed_field

from src.models.control import ComplianceTier, ControlStatus


class GapFinding(BaseModel):
    """
    A single compliance gap identified during policy gap analysis.

    Created when a control is MISSING or PARTIAL. Carries the weighted
    score that determines remediation priority.
    """

    control_id: str = Field(..., description="Control identifier")
    control_name: str = Field(..., description="Human-readable control name")
    framework: str = Field(..., description="Source compliance framework")
    category: str = Field(default="", description="Control category/function")
    status: ControlStatus = Field(..., description="Current implementation status")
    tier: ComplianceTier = Field(..., description="Compliance tier from profile")
    severity: Optional[str] = Field(
        default="Medium", description="Control severity rating"
    )
    notes: Optional[str] = Field(default=None, description="Auditor notes")

    # ATT&CK mapping (populated by coverage analyzer)
    exposed_techniques: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs exposed by this gap",
    )

    # Remediation (populated by remediation engine)
    recommendations: Dict[str, Any] = Field(
        default_factory=dict,
        description="Remediation recommendations for this gap",
    )

    @computed_field
    @property
    def severity_score(self) -> float:
        """
        Base severity score (0-10).

        Derived from the severity string.
        """
        scores = {
            "Critical": 10.0,
            "High": 7.5,
            "Medium": 5.0,
            "Low": 2.5,
            "Informational": 1.0,
        }
        return scores.get(self.severity or "Medium", 5.0)

    @computed_field
    @property
    def gap_factor(self) -> float:
        """Status-based gap factor (0.0–1.0)."""
        return self.status.gap_factor

    @computed_field
    @property
    def weighted_score(self) -> float:
        """
        Final weighted gap score.

        Formula: severity_score × gap_factor × tier_weight

        Examples:
            Critical + Missing + REQUIRED  = 10 × 1.0 × 3.0 = 30.0
            Medium + Partial + NICE_TO_HAVE = 5 × 0.5 × 1.0 = 2.5
        """
        return round(self.severity_score * self.gap_factor * self.tier.weight, 2)

    @computed_field
    @property
    def remediation_priority(self) -> str:
        """
        Human-readable priority based on weighted score.

        Thresholds:
            ≥ 20.0  → P1 - Critical
            ≥ 10.0  → P2 - High
            ≥ 5.0   → P3 - Medium
            < 5.0   → P4 - Low
        """
        if self.weighted_score >= 20.0:
            return "P1 - Critical"
        elif self.weighted_score >= 10.0:
            return "P2 - High"
        elif self.weighted_score >= 5.0:
            return "P3 - Medium"
        else:
            return "P4 - Low"
