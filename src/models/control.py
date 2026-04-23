"""
Control data model — represents a single GRC compliance control.

Each control has a status (Implemented/Partial/Missing), belongs to a
compliance framework, and carries a tier assignment from the active
compliance profile that determines its scoring weight.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ComplianceTier(str, Enum):
    """
    Determines how critical a control is to the organization's compliance posture.

    Scoring weights:
        REQUIRED    → 3×  (regulatory/contractual mandate)
        DESIRED     → 2×  (strategic security goal)
        NICE_TO_HAVE → 1× (best-practice aspirational)
    """

    REQUIRED = "REQUIRED"
    DESIRED = "DESIRED"
    NICE_TO_HAVE = "NICE_TO_HAVE"

    @property
    def weight(self) -> float:
        """Return the scoring multiplier for this tier."""
        weights = {
            ComplianceTier.REQUIRED: 3.0,
            ComplianceTier.DESIRED: 2.0,
            ComplianceTier.NICE_TO_HAVE: 1.0,
        }
        return weights[self]


class ControlStatus(str, Enum):
    """Implementation status of a control."""

    IMPLEMENTED = "Implemented"
    PARTIAL = "Partial"
    MISSING = "Missing"
    NOT_APPLICABLE = "Not_Applicable"

    @property
    def gap_factor(self) -> float:
        """
        Return gap severity factor (0.0 = fully covered, 1.0 = fully exposed).

        Partial controls get 0.5 — they reduce risk but don't eliminate it.
        """
        factors = {
            ControlStatus.IMPLEMENTED: 0.0,
            ControlStatus.PARTIAL: 0.5,
            ControlStatus.MISSING: 1.0,
            ControlStatus.NOT_APPLICABLE: 0.0,
        }
        return factors[self]


class Control(BaseModel):
    """
    Represents a single GRC compliance control from an ingested report.

    Examples:
        - NIST CSF 2.0: PR.AA-01 (Identity Management)
        - ISO 27001: A.8.8 (Management of technical vulnerabilities)
        - SOC 2: CC6.1 (Logical and Physical Access Controls)
    """

    id: str = Field(..., description="Control identifier (e.g., 'PR.AA-01')")
    name: str = Field(..., description="Human-readable control name")
    description: str = Field(default="", description="Detailed control description")
    framework: str = Field(
        ..., description="Compliance framework (e.g., 'NIST_CSF', 'ISO_27001')"
    )
    category: str = Field(
        default="", description="Control category/function (e.g., 'Protect', 'Detect')"
    )
    status: ControlStatus = Field(
        ..., description="Implementation status"
    )
    severity: Optional[str] = Field(
        default=None,
        description="Severity if not implemented: Critical, High, Medium, Low",
    )
    tier: ComplianceTier = Field(
        default=ComplianceTier.REQUIRED,
        description="Compliance tier from active profile",
    )
    notes: Optional[str] = Field(
        default=None, description="Auditor notes or evidence references"
    )

    def is_implemented(self) -> bool:
        """Check if this control is fully implemented."""
        return self.status == ControlStatus.IMPLEMENTED

    def is_gap(self) -> bool:
        """Check if this control represents a compliance gap."""
        return self.status in (ControlStatus.MISSING, ControlStatus.PARTIAL)

    def gap_weight(self) -> float:
        """
        Calculate weighted gap score.

        Combines the status gap factor with the tier weight to produce
        a single score representing how critical this gap is.

        Returns:
            Weighted score (0.0 for implemented, up to 3.0 for REQUIRED+MISSING)
        """
        return self.status.gap_factor * self.tier.weight

    model_config = {"str_strip_whitespace": True}
