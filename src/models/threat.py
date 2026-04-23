"""
Threat models — ATT&CK technique and threat exposure representations.

These models connect compliance gaps to real-world attack surface
via MITRE ATT&CK technique mappings.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field, computed_field


class AttackTechnique(BaseModel):
    """
    A single MITRE ATT&CK technique.

    Represents one technique from the Enterprise ATT&CK matrix,
    loaded from STIX data or mapping files.
    """

    technique_id: str = Field(..., description="ATT&CK technique ID (e.g., 'T1078')")
    name: str = Field(..., description="Technique name (e.g., 'Valid Accounts')")
    description: str = Field(default="", description="Technique description")
    tactics: List[str] = Field(
        default_factory=list,
        description="Kill chain phases (e.g., ['Initial Access', 'Persistence'])",
    )
    platforms: List[str] = Field(
        default_factory=list,
        description="Applicable platforms (e.g., ['Windows', 'Linux'])",
    )
    url: Optional[str] = Field(
        default=None, description="ATT&CK page URL for this technique"
    )

    @property
    def is_subtechnique(self) -> bool:
        """Check if this is a sub-technique (e.g., T1078.001)."""
        return "." in self.technique_id

    @property
    def parent_technique_id(self) -> Optional[str]:
        """Get parent technique ID if this is a sub-technique."""
        if self.is_subtechnique:
            return self.technique_id.split(".")[0]
        return None

    @property
    def is_critical(self) -> bool:
        """Check if technique maps to high-impact tactics."""
        critical_tactics = {"initial-access", "impact", "exfiltration"}
        return any(
            tactic.lower().replace(" ", "-") in critical_tactics
            for tactic in self.tactics
        )


class ThreatExposure(BaseModel):
    """
    Links a MITRE ATT&CK technique to the compliance gaps that expose it.

    When a control gap leaves a technique unmitigated, this model captures
    the relationship and aggregates the risk score from all contributing gaps.
    """

    technique_id: str = Field(..., description="ATT&CK technique ID")
    technique_name: str = Field(default="", description="Technique name")
    tactics: List[str] = Field(
        default_factory=list, description="Associated tactics"
    )
    exposed_by_gaps: List[str] = Field(
        default_factory=list,
        description="Control IDs whose gaps expose this technique",
    )
    gap_scores: List[float] = Field(
        default_factory=list,
        description="Weighted scores from each contributing gap",
    )

    @computed_field
    @property
    def aggregate_risk_score(self) -> float:
        """
        Combined risk score from all gaps exposing this technique.

        Uses max score (worst-case) rather than sum, because a technique
        only needs to be exploited once.
        """
        return round(max(self.gap_scores), 2) if self.gap_scores else 0.0

    @computed_field
    @property
    def exposure_count(self) -> int:
        """Number of distinct control gaps exposing this technique."""
        return len(self.exposed_by_gaps)

    @computed_field
    @property
    def risk_level(self) -> str:
        """Categorize the risk level based on aggregate score."""
        if self.aggregate_risk_score >= 20.0:
            return "Critical"
        elif self.aggregate_risk_score >= 10.0:
            return "High"
        elif self.aggregate_risk_score >= 5.0:
            return "Medium"
        else:
            return "Low"
