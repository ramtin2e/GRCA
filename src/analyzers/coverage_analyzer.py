"""
Coverage Analyzer — maps gaps to ATT&CK techniques and computes coverage stats.
"""

from __future__ import annotations

from typing import Dict, List

from src.mappers.control_mapper import ControlMapper
from src.models.gap import GapFinding
from src.models.report import GapAnalysisResult
from src.models.threat import ThreatExposure
from src.utils.logger import get_logger

logger = get_logger(__name__)


class CoverageAnalyzer:
    """
    Maps compliance gaps to MITRE ATT&CK techniques and calculates
    technique coverage per tactic.
    """

    def __init__(self, mapper: ControlMapper):
        self.mapper = mapper

    def analyze_coverage(self, result: GapAnalysisResult) -> GapAnalysisResult:
        """
        Enrich a GapAnalysisResult with ATT&CK exposure data.

        1. Maps each gap finding to exposed ATT&CK techniques
        2. Aggregates technique exposure scores
        3. Computes coverage percentage per tactic

        Modifies result in-place and returns it.
        """
        logger.info("Analyzing ATT&CK coverage...")

        # Map each gap to techniques
        technique_gaps: Dict[str, ThreatExposure] = {}

        for finding in result.findings:
            techniques = self.mapper.map_control_to_techniques(finding.control_id, finding.framework)
            finding.exposed_techniques = techniques

            for tech_id in techniques:
                if tech_id not in technique_gaps:
                    tech_info = self.mapper.get_technique_info(tech_id)
                    technique_gaps[tech_id] = ThreatExposure(
                        technique_id=tech_id,
                        technique_name=tech_info.get("name", ""),
                        tactics=tech_info.get("tactics", []),
                        exposed_by_gaps=[],
                        gap_scores=[],
                    )

                technique_gaps[tech_id].exposed_by_gaps.append(finding.control_id)
                technique_gaps[tech_id].gap_scores.append(finding.weighted_score)

        # Sort exposures by risk
        exposures = sorted(
            technique_gaps.values(),
            key=lambda e: e.aggregate_risk_score,
            reverse=True,
        )

        result.threat_exposures = exposures
        result.attack_coverage = self._compute_tactic_coverage(exposures)

        logger.info(
            f"Found {len(exposures)} exposed ATT&CK techniques "
            f"across {len(result.attack_coverage or {})} tactics"
        )

        return result

    def _compute_tactic_coverage(self, exposures: List[ThreatExposure]) -> Dict[str, float]:
        """
        Compute what percentage of techniques per tactic are exposed.

        Returns dict of tactic → exposure percentage.
        """
        tactic_exposed: Dict[str, int] = {}
        tactic_total: Dict[str, int] = {}

        # Count exposed techniques per tactic
        for exposure in exposures:
            for tactic in exposure.tactics:
                tactic_exposed[tactic] = tactic_exposed.get(tactic, 0) + 1

        # Get total techniques per tactic from mapper
        all_techniques_by_tactic = self.mapper.get_techniques_by_tactic()
        for tactic, techniques in all_techniques_by_tactic.items():
            tactic_total[tactic] = len(techniques)

        # Calculate coverage (what % is exposed / at risk)
        coverage = {}
        for tactic in set(list(tactic_exposed.keys()) + list(tactic_total.keys())):
            exposed = tactic_exposed.get(tactic, 0)
            total = tactic_total.get(tactic, 1)
            # Invert: coverage = what's NOT exposed
            coverage[tactic] = round(((total - exposed) / total) * 100, 1) if total > 0 else 100.0

        return coverage
