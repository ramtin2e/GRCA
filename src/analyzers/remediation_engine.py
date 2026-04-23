"""
Remediation Engine — generates actionable fix suggestions for compliance gaps.

Maps each control gap to specific, prioritized remediation recommendations
based on the control's framework, category, and severity.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from src.models.gap import GapFinding
from src.utils.logger import get_logger

logger = get_logger(__name__)


# Remediation templates keyed by control category/function
# These demonstrate deep GRC domain knowledge
CATEGORY_RECOMMENDATIONS: Dict[str, List[str]] = {
    "Protect": [
        "Conduct a controls assessment to identify specific implementation gaps",
        "Develop a remediation plan with milestones and resource allocation",
        "Implement compensating controls while primary controls are being deployed",
    ],
    "Detect": [
        "Deploy continuous monitoring tools appropriate for the environment",
        "Establish baseline metrics and anomaly detection thresholds",
        "Integrate detection capabilities with incident response workflows",
    ],
    "Respond": [
        "Develop and document incident response procedures and playbooks",
        "Conduct tabletop exercises to validate response capabilities",
        "Establish communication channels and escalation procedures",
    ],
    "Recover": [
        "Validate backup and recovery procedures through regular testing",
        "Document recovery time and recovery point objectives (RTO/RPO)",
        "Establish post-incident review processes for continuous improvement",
    ],
    "Identify": [
        "Conduct a comprehensive asset inventory and risk assessment",
        "Establish a risk register with ownership assignments",
        "Implement continuous risk monitoring processes",
    ],
    "Govern": [
        "Establish governance framework with clear roles and responsibilities",
        "Develop and approve security policies at executive level",
        "Implement regular governance review and reporting cadence",
    ],
}

# Specific remediation recommendations per control ID
CONTROL_RECOMMENDATIONS: Dict[str, Dict] = {
    # NIST CSF 2.0
    "PR.AA-01": {
        "title": "Implement Enterprise Identity Management",
        "recommendations": [
            "Deploy multi-factor authentication (MFA) across all user accounts, prioritizing privileged and remote access",
            "Implement a centralized Identity Provider (IdP) with SSO for all business applications",
            "Establish automated credential lifecycle management (provisioning, rotation, revocation)",
            "Deploy privileged access management (PAM) for admin and service accounts",
        ],
        "quick_wins": ["Enable MFA for all admin accounts within 30 days", "Audit and remove stale accounts"],
        "estimated_effort": "Medium",
        "estimated_timeline": "2-4 months",
    },
    "PR.AA-04": {
        "title": "Secure Identity Assertions and Token Handling",
        "recommendations": [
            "Implement SAML assertion validation with signature verification on all service providers",
            "Deploy token binding and short-lived token policies to prevent replay attacks",
            "Establish certificate pinning for critical identity federation endpoints",
            "Conduct a federated identity security assessment across all integrated applications",
        ],
        "quick_wins": ["Enable SAML signature validation on all SP endpoints"],
        "estimated_effort": "Medium",
        "estimated_timeline": "1-3 months",
    },
    "PR.AA-05": {
        "title": "Implement Role-Based Access Control (RBAC)",
        "recommendations": [
            "Design and implement a formal RBAC model aligned with job functions and least privilege",
            "Conduct quarterly access reviews with manager attestation for all critical systems",
            "Implement just-in-time (JIT) access provisioning for privileged operations",
            "Deploy automated access certification campaigns with documented approval workflows",
        ],
        "quick_wins": ["Audit current admin accounts and remove unnecessary privileges"],
        "estimated_effort": "High",
        "estimated_timeline": "3-6 months",
    },
    "PR.DS-01": {
        "title": "Encrypt Data at Rest",
        "recommendations": [
            "Enable AES-256 encryption on all databases, file shares, and backup storage",
            "Implement key management using a hardware security module (HSM) or cloud KMS",
            "Classify data assets and apply encryption policies based on sensitivity level",
            "Conduct a data discovery scan to identify unencrypted sensitive data stores",
        ],
        "quick_wins": ["Enable transparent data encryption (TDE) on all production databases"],
        "estimated_effort": "Medium",
        "estimated_timeline": "2-4 months",
    },
    "PR.DS-10": {
        "title": "Protect Data in Use",
        "recommendations": [
            "Deploy Data Loss Prevention (DLP) agents on endpoints to monitor sensitive data access",
            "Implement memory protection and process isolation for applications handling sensitive data",
            "Evaluate confidential computing options for high-sensitivity workloads",
            "Establish data handling procedures and training for personnel with access to sensitive data",
        ],
        "quick_wins": ["Deploy endpoint DLP policies for PII and financial data patterns"],
        "estimated_effort": "High",
        "estimated_timeline": "3-6 months",
    },
    "PR.PS-01": {
        "title": "Establish Configuration Management Program",
        "recommendations": [
            "Define and enforce security baselines using CIS Benchmarks or DISA STIGs",
            "Deploy configuration management tools (Ansible, Chef, or Group Policy) for automated enforcement",
            "Implement continuous configuration drift detection and automated remediation",
            "Establish a change management process with security review gates",
        ],
        "quick_wins": ["Deploy automated baseline compliance scanning on critical servers"],
        "estimated_effort": "Medium",
        "estimated_timeline": "2-3 months",
    },
    "PR.PS-02": {
        "title": "Implement Automated Patch Management",
        "recommendations": [
            "Deploy an enterprise patch management solution with automated deployment capabilities",
            "Establish risk-based patching SLAs: Critical (72h), High (7d), Medium (30d), Low (90d)",
            "Implement a vulnerability-to-patch correlation workflow with your scanning tools",
            "Create a patching exception process with documented compensating controls",
        ],
        "quick_wins": ["Identify and patch all critical CVEs older than 30 days immediately"],
        "estimated_effort": "Medium",
        "estimated_timeline": "1-3 months",
    },
    "PR.PS-06": {
        "title": "Integrate Security into SDLC",
        "recommendations": [
            "Implement SAST, DAST, and SCA scanning in CI/CD pipelines with quality gates",
            "Conduct threat modeling during design phase for all new features and services",
            "Establish secure coding training program for all developers (annual)",
            "Implement pre-commit hooks for secrets detection and dependency vulnerability checks",
        ],
        "quick_wins": ["Add SCA scanning to CI/CD to catch vulnerable dependencies"],
        "estimated_effort": "Medium",
        "estimated_timeline": "2-4 months",
    },
    "DE.CM-03": {
        "title": "Deploy Comprehensive Endpoint Monitoring",
        "recommendations": [
            "Extend EDR coverage to 100% of managed endpoints including servers and containers",
            "Implement behavioral analytics and machine learning-based anomaly detection",
            "Establish automated alert triage with SOAR integration for common threat patterns",
            "Deploy file integrity monitoring (FIM) on critical system files and configurations",
        ],
        "quick_wins": ["Deploy EDR agents on remaining unprotected endpoints within 30 days"],
        "estimated_effort": "Medium",
        "estimated_timeline": "1-2 months",
    },
    "DE.CM-06": {
        "title": "Establish Third-Party Risk Monitoring",
        "recommendations": [
            "Implement a vendor security assessment program with tiered review based on data access",
            "Deploy continuous third-party risk monitoring using security ratings services",
            "Establish contractual security requirements and right-to-audit clauses",
            "Conduct annual third-party penetration testing for critical vendor integrations",
        ],
        "quick_wins": ["Inventory all third-party integrations with data access classifications"],
        "estimated_effort": "Medium",
        "estimated_timeline": "2-4 months",
    },
    "DE.CM-09": {
        "title": "Monitor Security Tool Integrity",
        "recommendations": [
            "Implement tamper detection for all security tools (EDR, SIEM, firewall agents)",
            "Deploy heartbeat monitoring to detect disabled or unresponsive security agents",
            "Establish alerting for security tool configuration changes or policy modifications",
            "Conduct periodic integrity validation of security tool deployments",
        ],
        "quick_wins": ["Configure alerts for EDR agent health status changes"],
        "estimated_effort": "Low",
        "estimated_timeline": "2-4 weeks",
    },
    "DE.AE-06": {
        "title": "Automate Alert Distribution and Escalation",
        "recommendations": [
            "Implement automated alert routing and escalation workflows based on severity",
            "Deploy SOAR playbooks for common alert types to reduce response time",
            "Establish on-call rotation with automated notification via PagerDuty or equivalent",
            "Create runbooks for the top 20 most frequent alert types",
        ],
        "quick_wins": ["Configure automated Slack/Teams notifications for P1 alerts"],
        "estimated_effort": "Low",
        "estimated_timeline": "2-4 weeks",
    },
    "RS.MA-01": {
        "title": "Operationalize Incident Response Plan",
        "recommendations": [
            "Conduct quarterly tabletop exercises simulating realistic breach scenarios",
            "Establish retainer agreements with incident response and forensics providers",
            "Implement automated incident classification and triage workflows",
            "Deploy an incident management platform for coordinated response activities",
            "Develop communication templates for stakeholder, legal, and regulatory notifications",
        ],
        "quick_wins": ["Schedule first tabletop exercise within 30 days"],
        "estimated_effort": "Medium",
        "estimated_timeline": "1-3 months",
    },
    "RS.AN-03": {
        "title": "Build Forensic Analysis Capability",
        "recommendations": [
            "Cross-train SOC analysts on forensic investigation procedures and tools",
            "Deploy forensic imaging and analysis tools (Velociraptor, KAPE, or equivalent)",
            "Establish evidence handling and chain-of-custody procedures",
            "Create forensic investigation playbooks for common incident types",
        ],
        "quick_wins": ["Document current forensic capability gaps and training needs"],
        "estimated_effort": "Medium",
        "estimated_timeline": "2-4 months",
    },
    "RS.MI-01": {
        "title": "Deploy Automated Containment Capabilities",
        "recommendations": [
            "Implement network-based automated isolation via EDR and firewall integration",
            "Deploy microsegmentation to limit blast radius during active incidents",
            "Create pre-approved containment actions that can be executed without management approval",
            "Establish automated DNS sinkholing for known malicious domains",
        ],
        "quick_wins": ["Configure EDR network isolation capability for all endpoints"],
        "estimated_effort": "Medium",
        "estimated_timeline": "1-3 months",
    },
    "RS.MI-02": {
        "title": "Develop Eradication Playbooks",
        "recommendations": [
            "Create step-by-step eradication procedures for top threat scenarios (ransomware, BEC, insider)",
            "Implement automated persistence mechanism detection and removal tooling",
            "Establish re-imaging and clean rebuild procedures for compromised systems",
            "Deploy IOC sweep capabilities across the environment during eradication phase",
        ],
        "quick_wins": ["Document eradication procedures for the top 3 threat scenarios"],
        "estimated_effort": "Low",
        "estimated_timeline": "2-4 weeks",
    },
    "RC.RP-01": {
        "title": "Validate Recovery Capabilities",
        "recommendations": [
            "Conduct quarterly disaster recovery testing with documented results",
            "Implement immutable backup storage to prevent ransomware encryption of backups",
            "Validate RTO/RPO objectives through timed recovery exercises",
            "Establish alternate processing site readiness with regular failover testing",
        ],
        "quick_wins": ["Perform a test restore of critical system backups this week"],
        "estimated_effort": "Medium",
        "estimated_timeline": "1-3 months",
    },
    "GV.RM-01": {
        "title": "Formalize Risk Management Framework",
        "recommendations": [
            "Develop a risk appetite statement and obtain board-level approval",
            "Implement a risk register with quantitative scoring methodology",
            "Establish quarterly risk review cadence with executive reporting",
            "Align risk management framework with NIST RMF or ISO 31000",
        ],
        "quick_wins": ["Draft risk appetite statement for executive review"],
        "estimated_effort": "Medium",
        "estimated_timeline": "1-2 months",
    },
    "GV.SC-01": {
        "title": "Establish Supply Chain Risk Management",
        "recommendations": [
            "Implement tiered vendor security assessment based on data access and criticality",
            "Deploy software bill of materials (SBOM) management for critical applications",
            "Establish vendor security incident notification requirements in contracts",
            "Monitor critical vendor security posture using external ratings services",
        ],
        "quick_wins": ["Create a critical vendor inventory with risk tier assignments"],
        "estimated_effort": "Medium",
        "estimated_timeline": "2-4 months",
    },
    "ID.RA-01": {
        "title": "Deploy Vulnerability Management Program",
        "recommendations": [
            "Deploy authenticated vulnerability scanning across all network segments (weekly)",
            "Implement risk-based vulnerability prioritization using EPSS and asset criticality",
            "Establish SLA-driven remediation workflows with tracking and accountability",
            "Integrate vulnerability data with asset management and ticketing systems",
        ],
        "quick_wins": ["Deploy vulnerability scanning tool and run first full-scope scan"],
        "estimated_effort": "Medium",
        "estimated_timeline": "1-3 months",
    },
    # ISO 27001
    "A.8.1": {
        "title": "Secure Endpoint Device Management",
        "recommendations": [
            "Enroll all BYOD devices in MDM with conditional access policies",
            "Implement remote wipe capability for all devices with corporate data access",
            "Deploy device compliance checks (encryption, patch level, antivirus) as access prerequisites",
        ],
        "quick_wins": ["Enable conditional access requiring device compliance for email"],
        "estimated_effort": "Medium",
        "estimated_timeline": "1-2 months",
    },
    "A.8.3": {
        "title": "Enforce Information Access Restriction",
        "recommendations": [
            "Migrate legacy systems to modern access control frameworks",
            "Implement quarterly access review campaigns with automated workflows",
            "Deploy attribute-based access control (ABAC) for fine-grained data access",
        ],
        "quick_wins": ["Conduct emergency access review on legacy CRM system"],
        "estimated_effort": "High",
        "estimated_timeline": "3-6 months",
    },
    "A.8.5": {
        "title": "Strengthen Authentication Controls",
        "recommendations": [
            "Deploy MFA on all internal applications, not just cloud services",
            "Implement minimum 14-character password policy with complexity requirements",
            "Deploy passwordless authentication (FIDO2/WebAuthn) for high-security applications",
        ],
        "quick_wins": ["Enable MFA for internal applications using existing IdP"],
        "estimated_effort": "Medium",
        "estimated_timeline": "1-3 months",
    },
    "A.8.8": {
        "title": "Establish Vulnerability Management Program",
        "recommendations": [
            "Deploy automated vulnerability scanning across all network segments",
            "Implement risk-based patch prioritization using CVSS, EPSS, and asset criticality",
            "Establish patch management SLAs with escalation procedures",
            "Integrate vulnerability findings into change management and deployment workflows",
        ],
        "quick_wins": ["Deploy vulnerability scanner and run initial full-scope assessment"],
        "estimated_effort": "Medium",
        "estimated_timeline": "1-3 months",
    },
    "A.8.9": {
        "title": "Automate Configuration Management",
        "recommendations": [
            "Implement Infrastructure as Code (IaC) with security baselines",
            "Deploy configuration drift detection with automated remediation",
            "Establish golden image management for server and workstation deployments",
        ],
        "quick_wins": ["Enable drift detection on critical server configurations"],
        "estimated_effort": "Medium",
        "estimated_timeline": "2-3 months",
    },
    "A.8.12": {
        "title": "Deploy Data Leakage Prevention",
        "recommendations": [
            "Implement endpoint DLP for USB, email, and cloud upload channels",
            "Deploy network DLP at egress points monitoring for sensitive data patterns",
            "Disable unauthorized USB storage device usage via group policy",
            "Implement CASB for shadow IT discovery and data exfiltration prevention",
        ],
        "quick_wins": ["Disable USB mass storage via group policy on all workstations"],
        "estimated_effort": "High",
        "estimated_timeline": "3-6 months",
    },
    "A.8.24": {
        "title": "Strengthen Cryptographic Controls",
        "recommendations": [
            "Enable mutual TLS (mTLS) for all internal east-west service communication",
            "Conduct a cryptographic inventory and retire weak algorithms (SHA-1, TLS 1.0/1.1)",
            "Implement certificate lifecycle management with automated renewal",
        ],
        "quick_wins": ["Enable TLS encryption on internal database connections"],
        "estimated_effort": "Medium",
        "estimated_timeline": "2-4 months",
    },
    "A.8.25": {
        "title": "Mature Secure Development Lifecycle",
        "recommendations": [
            "Implement threat modeling during design phase (STRIDE methodology)",
            "Add DAST scanning and SCA to the CI/CD pipeline alongside existing SAST",
            "Conduct annual secure coding training for all development staff",
        ],
        "quick_wins": ["Add SCA dependency scanning to existing CI/CD pipeline"],
        "estimated_effort": "Medium",
        "estimated_timeline": "2-4 months",
    },
    "A.5.23": {
        "title": "Implement Cloud Security Framework",
        "recommendations": [
            "Deploy a Cloud Security Posture Management (CSPM) solution",
            "Develop cloud-specific security policies aligned with CSA Cloud Controls Matrix",
            "Implement cloud workload protection platform (CWPP) for runtime security",
            "Establish cloud security architecture review for all new deployments",
        ],
        "quick_wins": ["Enable cloud-native security monitoring (GuardDuty, Defender for Cloud)"],
        "estimated_effort": "High",
        "estimated_timeline": "3-6 months",
    },
    "A.5.30": {
        "title": "Validate Business Continuity Readiness",
        "recommendations": [
            "Conduct DR failover testing within 30 days and document results",
            "Implement immutable backups with air-gapped or offline copies",
            "Update RTO/RPO objectives based on current business requirements",
            "Establish automated DR orchestration for critical systems",
        ],
        "quick_wins": ["Schedule and execute DR test for tier-1 applications"],
        "estimated_effort": "Medium",
        "estimated_timeline": "1-3 months",
    },
}

# Fallback recommendations based on status
STATUS_RECOMMENDATIONS: Dict[str, List[str]] = {
    "Missing": [
        "Conduct a gap assessment to determine implementation requirements and resource needs",
        "Develop a project plan with budget, timeline, and responsible parties",
        "Evaluate and select appropriate technical solutions or process improvements",
        "Implement interim compensating controls to reduce risk exposure during remediation",
    ],
    "Partial": [
        "Assess current implementation coverage and identify specific deficiencies",
        "Develop a plan to extend coverage to all in-scope systems and processes",
        "Validate effectiveness of existing controls through testing",
        "Address identified gaps in documentation and procedural compliance",
    ],
}


class RemediationEngine:
    """
    Generates remediation recommendations for compliance gap findings.

    Uses a tiered lookup:
    1. Control-specific recommendations (most precise)
    2. Category-based recommendations
    3. Status-based fallback recommendations
    """

    def enrich_findings(self, findings: List[GapFinding]) -> List[GapFinding]:
        """
        Add remediation recommendations to each gap finding.

        Modifies findings in-place and returns them.
        """
        for finding in findings:
            recs = self.get_recommendations(finding)
            finding.recommendations = recs
        
        logger.info(f"Enriched {len(findings)} findings with remediation recommendations")
        return findings

    def get_recommendations(self, finding: GapFinding) -> Dict:
        """
        Get recommendations for a specific finding.

        Returns dict with:
            - title: Short remediation title
            - recommendations: List of specific actions
            - quick_wins: Immediate low-effort improvements
            - estimated_effort: Low/Medium/High
            - estimated_timeline: Human-readable timeline
        """
        # Tier 1: Control-specific
        if finding.control_id in CONTROL_RECOMMENDATIONS:
            return CONTROL_RECOMMENDATIONS[finding.control_id].copy()

        # Tier 2: Build from category + status
        recs = {
            "title": f"Remediate {finding.control_name}",
            "recommendations": [],
            "quick_wins": [],
            "estimated_effort": "Medium",
            "estimated_timeline": "1-3 months",
        }

        # Category-based recs
        if finding.category in CATEGORY_RECOMMENDATIONS:
            recs["recommendations"].extend(CATEGORY_RECOMMENDATIONS[finding.category])

        # Status-based recs
        status_recs = STATUS_RECOMMENDATIONS.get(finding.status.value, [])
        recs["recommendations"].extend(status_recs)

        # Deduplicate
        recs["recommendations"] = list(dict.fromkeys(recs["recommendations"]))[:5]

        if not recs["quick_wins"]:
            recs["quick_wins"] = ["Conduct initial assessment and document current state"]

        return recs
