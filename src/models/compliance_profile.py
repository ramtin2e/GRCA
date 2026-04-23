"""
Compliance Profile model — defines the desired compliance posture.

A profile assigns each framework a compliance tier (REQUIRED/DESIRED/NICE_TO_HAVE)
and supports per-control overrides. This drives the gap analysis scoring engine.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional

import yaml
from pydantic import BaseModel, Field

from src.models.control import ComplianceTier


class FrameworkConfig(BaseModel):
    """Configuration for a single compliance framework within a profile."""

    version: str = Field(default="", description="Framework version (e.g., '2.0')")
    tier: ComplianceTier = Field(
        default=ComplianceTier.REQUIRED,
        description="Default tier for all controls in this framework",
    )
    overrides: Dict[str, ComplianceTier] = Field(
        default_factory=dict,
        description="Per-control tier overrides (control_id → tier)",
    )

    def get_tier_for_control(self, control_id: str) -> ComplianceTier:
        """
        Get the effective tier for a specific control.

        Checks for per-control overrides first, then falls back to the
        framework-level default tier.

        Args:
            control_id: The control identifier to look up.

        Returns:
            The ComplianceTier for this control.
        """
        if control_id in self.overrides:
            return self.overrides[control_id]
        return self.tier


class ComplianceProfile(BaseModel):
    """
    Defines the organization's desired compliance posture.

    A profile assigns each framework a default compliance tier and supports
    per-control overrides. Multiple profiles can be maintained for different
    contexts (e.g., "production" vs. "staging" environments, or
    "pre-IPO" vs. "early-stage" compliance postures).

    Example YAML:
        profile_name: "Enterprise Standard"
        frameworks:
          NIST_CSF:
            version: "2.0"
            tier: REQUIRED
            overrides:
              GV.OC-01: NICE_TO_HAVE
          ISO_27001:
            tier: DESIRED
    """

    profile_name: str = Field(..., description="Human-readable profile name")
    description: str = Field(default="", description="Profile description")
    frameworks: Dict[str, FrameworkConfig] = Field(
        default_factory=dict,
        description="Framework name → configuration mapping",
    )

    def get_tier(self, framework: str, control_id: str) -> ComplianceTier:
        """
        Get the effective compliance tier for a control.

        Lookup order:
        1. Per-control override in the framework config
        2. Framework-level default tier
        3. Falls back to REQUIRED if framework is not in the profile

        Args:
            framework: Framework name (e.g., 'NIST_CSF').
            control_id: Control identifier (e.g., 'PR.AA-01').

        Returns:
            The effective ComplianceTier.
        """
        if framework in self.frameworks:
            return self.frameworks[framework].get_tier_for_control(control_id)
        # Unknown framework defaults to REQUIRED — fail safe
        return ComplianceTier.REQUIRED

    def has_framework(self, framework: str) -> bool:
        """Check if a framework is defined in this profile."""
        return framework in self.frameworks

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ComplianceProfile":
        """
        Load a compliance profile from a YAML file.

        Args:
            path: Path to the YAML profile file.

        Returns:
            A ComplianceProfile instance.

        Raises:
            FileNotFoundError: If the profile file doesn't exist.
            yaml.YAMLError: If the YAML is malformed.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Compliance profile not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        # Parse framework configs, converting tier strings to enums
        frameworks = {}
        for fw_name, fw_data in data.get("frameworks", {}).items():
            if isinstance(fw_data, dict):
                # Convert override tier strings to enums
                overrides = {}
                for ctrl_id, tier_str in fw_data.get("overrides", {}).items():
                    if isinstance(tier_str, str):
                        overrides[ctrl_id] = ComplianceTier(tier_str)

                frameworks[fw_name] = FrameworkConfig(
                    version=fw_data.get("version", ""),
                    tier=ComplianceTier(fw_data.get("tier", "REQUIRED")),
                    overrides=overrides,
                )

        return cls(
            profile_name=data.get("profile_name", "Unnamed Profile"),
            description=data.get("description", ""),
            frameworks=frameworks,
        )

    @classmethod
    def default(cls) -> "ComplianceProfile":
        """
        Create a default profile where everything is REQUIRED.

        Useful as a fallback when no profile is specified.
        """
        return cls(
            profile_name="Default (All Required)",
            description="All controls treated as REQUIRED.",
            frameworks={},  # Empty = everything falls back to REQUIRED
        )
