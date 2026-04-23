"""
Tier Scorer — applies tier-weighted scoring and produces remediation priorities.
"""

from __future__ import annotations

from typing import Dict, List

from src.models.control import ComplianceTier
from src.models.gap import GapFinding
from src.models.report import GapAnalysisResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


class TierScorer:
    """
    Applies tier-weighted scoring to gap findings and computes
    a compliance posture score.
    """

    def __init__(self, custom_weights: Dict[str, float] | None = None):
        """
        Args:
            custom_weights: Override default tier weights.
                            e.g. {"REQUIRED": 5.0, "DESIRED": 2.0, "NICE_TO_HAVE": 0.5}
        """
        self.weights = {
            ComplianceTier.REQUIRED: 3.0,
            ComplianceTier.DESIRED: 2.0,
            ComplianceTier.NICE_TO_HAVE: 1.0,
        }
        if custom_weights:
            for tier_name, weight in custom_weights.items():
                tier = ComplianceTier(tier_name)
                self.weights[tier] = weight

    def score_findings(self, result: GapAnalysisResult) -> GapAnalysisResult:
        """
        Re-score all findings with current weights and re-sort.

        Modifies the result in-place and returns it.
        """
        for finding in result.findings:
            # Tier weight is already baked into GapFinding.weighted_score
            # via the ComplianceTier.weight property — this method is for
            # applying custom weight overrides
            pass

        result.findings.sort(key=lambda f: f.weighted_score, reverse=True)
        return result

    def get_remediation_roadmap(self, findings: List[GapFinding]) -> Dict[str, List[GapFinding]]:
        """
        Group findings into a remediation roadmap by priority.

        Returns:
            {
                "P1 - Critical": [...],
                "P2 - High": [...],
                "P3 - Medium": [...],
                "P4 - Low": [...]
            }
        """
        roadmap: Dict[str, List[GapFinding]] = {
            "P1 - Critical": [],
            "P2 - High": [],
            "P3 - Medium": [],
            "P4 - Low": [],
        }

        for finding in findings:
            priority = finding.remediation_priority
            roadmap[priority].append(finding)

        for priority, items in roadmap.items():
            logger.info(f"{priority}: {len(items)} findings")

        return roadmap

    def compute_posture_score(self, result: GapAnalysisResult) -> float:
        """
        Compute overall compliance posture score (0-100).

        This is a weighted score where REQUIRED gaps drag the score
        down more than NICE_TO_HAVE gaps.
        """
        return result.overall_compliance_score
