"""
Executive Summary Generator — produces audit-style narrative from analysis results.

Generates professional executive summary text that mirrors real GRC audit
deliverables, demonstrating domain knowledge in compliance reporting.
"""

from __future__ import annotations

from typing import Dict, List, Any

from src.utils.logger import get_logger

logger = get_logger(__name__)

# NIST CSF function descriptions
FUNCTION_DESCRIPTIONS = {
    "Govern": "establishes cybersecurity governance and risk management oversight",
    "Identify": "enables asset discovery and risk assessment capabilities",
    "Protect": "implements safeguards for critical infrastructure services",
    "Detect": "defines capabilities to identify cybersecurity events",
    "Respond": "establishes incident response and mitigation procedures",
    "Recover": "ensures timely restoration of impaired services and capabilities",
}

# Framework display names
FRAMEWORK_NAMES = {
    "NIST_CSF": "NIST Cybersecurity Framework 2.0",
    "ISO_27001": "ISO/IEC 27001:2022 Annex A",
    "SOC2": "SOC 2 Type II",
    "CIS_CONTROLS": "CIS Controls v8",
}


def generate_executive_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate an executive summary from gap analysis results.

    Returns a dict with:
        - overall_assessment: High-level posture statement
        - key_findings: List of critical finding summaries
        - risk_exposure: ATT&CK threat exposure narrative
        - recommendations_summary: Prioritized action items
        - maturity_assessment: CMMI-style maturity evaluation
    """
    score = result.get("overall_compliance_score", 0)
    total = result.get("total_controls_analyzed", 0)
    gaps = result.get("total_gaps", 0)
    findings = result.get("findings", [])
    tiers = result.get("tier_summaries", {})
    exposures = result.get("threat_exposures", [])
    frameworks = result.get("framework_summaries", {})
    roadmap = result.get("roadmap", {})
    profile = result.get("profile_name", "Default")

    # Determine posture rating
    if score >= 80:
        posture = "Strong"
        posture_desc = "demonstrates a mature security posture with comprehensive control implementation"
    elif score >= 60:
        posture = "Moderate"
        posture_desc = "maintains a developing security posture with notable gaps requiring attention"
    elif score >= 40:
        posture = "Weak"
        posture_desc = "exhibits significant compliance deficiencies that present material risk"
    else:
        posture = "Critical"
        posture_desc = "faces critical compliance gaps that require immediate executive attention and resource allocation"

    # Framework name
    fw_keys = list(frameworks.keys()) if frameworks else []
    fw_name = FRAMEWORK_NAMES.get(fw_keys[0], fw_keys[0]) if fw_keys else "the selected compliance framework"

    # Overall assessment
    implemented = total - gaps
    overall = (
        f"Based on the assessment of {total} controls against {fw_name}, "
        f"the organization {posture_desc}. The current compliance score of "
        f"{score:.1f}% reflects {implemented} fully implemented controls with "
        f"{gaps} controls identified as partially implemented or missing."
    )

    # Key findings
    key_findings = []
    p1_count = roadmap.get("P1 - Critical", 0)
    p2_count = roadmap.get("P2 - High", 0)

    if p1_count > 0:
        p1_findings = [f for f in findings if f.get("remediation_priority", "").startswith("P1")]
        missing_p1 = [f for f in p1_findings if f.get("status") == "Missing"]
        if missing_p1:
            ctrl_list = ", ".join(f["control_id"] for f in missing_p1[:3])
            key_findings.append(
                f"{len(missing_p1)} critical controls are completely unimplemented ({ctrl_list}), "
                f"representing the highest risk to the organization's security posture."
            )
        partial_p1 = [f for f in p1_findings if f.get("status") == "Partial"]
        if partial_p1:
            key_findings.append(
                f"{len(partial_p1)} high-severity controls have partial implementation, "
                f"indicating incomplete deployment that may provide a false sense of security."
            )

    # Function/category analysis
    categories = {}
    for f in findings:
        cat = f.get("category", "Unknown")
        if cat not in categories:
            categories[cat] = {"count": 0, "missing": 0}
        categories[cat]["count"] += 1
        if f.get("status") == "Missing":
            categories[cat]["missing"] += 1

    weakest = sorted(categories.items(), key=lambda x: x[1]["count"], reverse=True)
    if weakest:
        worst_cat, worst_data = weakest[0]
        cat_desc = FUNCTION_DESCRIPTIONS.get(worst_cat, f"covers {worst_cat} controls")
        key_findings.append(
            f"The {worst_cat} function, which {cat_desc}, has the highest concentration "
            f"of gaps with {worst_data['count']} findings ({worst_data['missing']} missing controls)."
        )

    # Risk exposure narrative
    risk_exposure = ""
    if exposures:
        technique_count = len(exposures)
        critical_techs = [e for e in exposures if e.get("risk_level") == "Critical"]
        high_techs = [e for e in exposures if e.get("risk_level") == "High"]

        risk_exposure = (
            f"The identified compliance gaps expose the organization to {technique_count} "
            f"MITRE ATT&CK techniques"
        )
        if critical_techs or high_techs:
            risk_exposure += (
                f", including {len(critical_techs)} critical-risk and {len(high_techs)} high-risk "
                f"techniques that adversaries actively exploit in real-world campaigns"
            )
        risk_exposure += (
            ". These exposures span multiple attack lifecycle phases, indicating that "
            "a determined threat actor could potentially chain these gaps to achieve "
            "initial access, establish persistence, and exfiltrate sensitive data."
        )

    # Recommendations summary
    rec_summary = []
    if p1_count:
        rec_summary.append(
            f"Immediately remediate {p1_count} P1-Critical findings to address "
            f"the most severe compliance gaps and reduce attack surface exposure."
        )
    if p2_count:
        rec_summary.append(
            f"Prioritize {p2_count} P2-High findings for remediation within the "
            f"next 30-60 days to achieve meaningful posture improvement."
        )

    # Estimate what score would be after P1 fixes
    p1_score_impact = sum(f.get("weighted_score", 0) for f in findings if f.get("remediation_priority", "").startswith("P1"))
    if p1_score_impact > 0 and total > 0:
        rec_summary.append(
            f"Resolving all P1-Critical findings would improve the compliance score "
            f"by an estimated {min(p1_score_impact / total * 3, 100 - score):.0f} percentage points."
        )

    rec_summary.append(
        "Establish a quarterly compliance review cadence to track remediation "
        "progress and identify emerging gaps as the threat landscape evolves."
    )

    # Maturity assessment (1-5 CMMI-style)
    if score >= 85:
        maturity_level, maturity_label = 5, "Optimizing"
        maturity_desc = "Continuous improvement processes are in place with proactive risk management."
    elif score >= 70:
        maturity_level, maturity_label = 4, "Managed"
        maturity_desc = "Controls are measured and monitored, with consistent enforcement across the organization."
    elif score >= 55:
        maturity_level, maturity_label = 3, "Defined"
        maturity_desc = "Standardized processes exist but enforcement and monitoring are inconsistent."
    elif score >= 35:
        maturity_level, maturity_label = 2, "Developing"
        maturity_desc = "Basic controls are in place but implementation is ad-hoc and reactive."
    else:
        maturity_level, maturity_label = 1, "Initial"
        maturity_desc = "Security controls are largely absent or informal with no standardized processes."

    maturity = {
        "level": maturity_level,
        "label": maturity_label,
        "description": maturity_desc,
        "domains": {},
    }

    # Per-domain maturity
    for cat, data in categories.items():
        cat_total = data["count"]
        cat_missing = data["missing"]
        cat_score = max(0, 100 - (cat_total * 100 / max(total, 1) * 1.5))
        if cat_score >= 80:
            maturity["domains"][cat] = {"level": 4, "label": "Managed"}
        elif cat_score >= 60:
            maturity["domains"][cat] = {"level": 3, "label": "Defined"}
        elif cat_score >= 40:
            maturity["domains"][cat] = {"level": 2, "label": "Developing"}
        else:
            maturity["domains"][cat] = {"level": 1, "label": "Initial"}

    summary = {
        "posture_rating": posture,
        "overall_assessment": overall,
        "key_findings": key_findings,
        "risk_exposure": risk_exposure,
        "recommendations_summary": rec_summary,
        "maturity": maturity,
    }

    logger.info(f"Generated executive summary: posture={posture}, maturity=L{maturity_level}")
    return summary
