#!/usr/bin/env python3
"""
GRC Threat Modeler — CLI Entry Point

Orchestrates the full pipeline:
  1. Parse report → List[Control]
  2. Analyze gaps → GapAnalysisResult
  3. Map to ATT&CK → ThreatExposure
  4. Output results → JSON / CLI Table
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from src.analyzers.gap_analyzer import GapAnalyzer
from src.analyzers.coverage_analyzer import CoverageAnalyzer
from src.analyzers.tier_scorer import TierScorer
from src.mappers.control_mapper import ControlMapper
from src.models.compliance_profile import ComplianceProfile
from src.parsers.parser_factory import get_parser
from src.utils.logger import configure_logging, get_logger
from src.utils.validators import validate_controls


def build_cli() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="grc-modeler",
        description=(
            "GRC Threat Modeler — Automated compliance gap analysis "
            "with MITRE ATT&CK threat mapping"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --input data/sample_reports/sample_nist_csf2_assessment.csv --framework nist-csf2\n"
            "  python main.py --input report.json --framework iso27001 --profile config/profiles/startup_profile.yaml\n"
            "  python main.py --input audit.csv --framework nist-csf2 --output-format json --output-dir ./outputs\n"
        ),
    )

    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Path to GRC report file (CSV, JSON, XLSX, PDF)",
    )
    parser.add_argument(
        "--framework", "-f",
        required=True,
        choices=["nist-csf2", "nist-csf1", "iso27001", "soc2", "cis"],
        help="Compliance framework of the input report",
    )
    parser.add_argument(
        "--profile", "-p",
        default=None,
        help="Path to compliance profile YAML (default: all controls REQUIRED)",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="./outputs",
        help="Directory for output files (default: ./outputs)",
    )
    parser.add_argument(
        "--output-format",
        choices=["json", "table", "both"],
        default="both",
        help="Output format (default: both)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )

    return parser


def print_table(result) -> None:
    """Print results as a rich CLI table."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text

        console = Console()

        # Header
        console.print()
        console.print(
            Panel(
                f"[bold cyan]GRC Gap Analysis Report[/]\n"
                f"Profile: {result.profile_name}\n"
                f"Controls Analyzed: {result.total_controls_analyzed}\n"
                f"Total Gaps: {result.total_gaps}\n"
                f"Compliance Score: [bold]"
                f"{'[green]' if result.overall_compliance_score >= 70 else '[red]'}"
                f"{result.overall_compliance_score}%[/]",
                title="Summary",
                border_style="cyan",
            )
        )

        # Tier summary table
        if result.tier_summaries:
            tier_table = Table(title="Compliance by Tier", border_style="blue")
            tier_table.add_column("Tier", style="bold")
            tier_table.add_column("Total", justify="right")
            tier_table.add_column("Implemented", justify="right", style="green")
            tier_table.add_column("Partial", justify="right", style="yellow")
            tier_table.add_column("Missing", justify="right", style="red")
            tier_table.add_column("Compliance %", justify="right")

            for tier_name, summary in result.tier_summaries.items():
                pct = summary.compliance_percentage
                pct_color = "green" if pct >= 70 else ("yellow" if pct >= 50 else "red")
                tier_table.add_row(
                    tier_name,
                    str(summary.total_controls),
                    str(summary.implemented),
                    str(summary.partial),
                    str(summary.missing),
                    f"[{pct_color}]{pct}%[/]",
                )

            console.print(tier_table)
            console.print()

        # Top findings table
        top_findings = result.get_top_findings(15)
        if top_findings:
            findings_table = Table(title="Priority Gap Findings", border_style="red")
            findings_table.add_column("#", justify="right", style="dim")
            findings_table.add_column("Control", style="bold")
            findings_table.add_column("Name", max_width=40)
            findings_table.add_column("Status", justify="center")
            findings_table.add_column("Tier", justify="center")
            findings_table.add_column("Severity")
            findings_table.add_column("Score", justify="right", style="bold")
            findings_table.add_column("Priority")

            for i, finding in enumerate(top_findings, 1):
                status_color = "red" if finding.status.value == "Missing" else "yellow"
                tier_color = {
                    "REQUIRED": "red",
                    "DESIRED": "yellow",
                    "NICE_TO_HAVE": "dim",
                }.get(finding.tier.value, "white")
                priority_color = {
                    "P1 - Critical": "bold red",
                    "P2 - High": "red",
                    "P3 - Medium": "yellow",
                    "P4 - Low": "dim",
                }.get(finding.remediation_priority, "white")

                findings_table.add_row(
                    str(i),
                    finding.control_id,
                    finding.control_name,
                    f"[{status_color}]{finding.status.value}[/]",
                    f"[{tier_color}]{finding.tier.value}[/]",
                    finding.severity or "Medium",
                    str(finding.weighted_score),
                    f"[{priority_color}]{finding.remediation_priority}[/]",
                )

            console.print(findings_table)
            console.print()

        # ATT&CK exposure summary
        if result.threat_exposures:
            attack_table = Table(title="Top ATT&CK Technique Exposures", border_style="magenta")
            attack_table.add_column("Technique", style="bold")
            attack_table.add_column("Name", max_width=35)
            attack_table.add_column("Tactics", max_width=30)
            attack_table.add_column("Risk", justify="right")
            attack_table.add_column("Exposed By", justify="right")

            for exposure in result.threat_exposures[:10]:
                risk_color = {
                    "Critical": "bold red",
                    "High": "red",
                    "Medium": "yellow",
                    "Low": "dim",
                }.get(exposure.risk_level, "white")

                attack_table.add_row(
                    exposure.technique_id,
                    exposure.technique_name,
                    ", ".join(exposure.tactics[:2]),
                    f"[{risk_color}]{exposure.risk_level}[/]",
                    str(exposure.exposure_count),
                )

            console.print(attack_table)

    except ImportError:
        # Fallback if rich is not installed
        print(f"\n=== GRC Gap Analysis Report ===")
        print(f"Profile: {result.profile_name}")
        print(f"Controls: {result.total_controls_analyzed}")
        print(f"Gaps: {result.total_gaps}")
        print(f"Score: {result.overall_compliance_score}%")
        print(f"\nTop Findings:")
        for i, f in enumerate(result.get_top_findings(10), 1):
            print(f"  {i}. [{f.remediation_priority}] {f.control_id} - {f.control_name} ({f.status.value}) Score: {f.weighted_score}")


def save_json(result, output_dir: Path) -> None:
    """Save results as JSON."""
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "gap_analysis_result.json"

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(result.model_dump(mode="json"), f, indent=2, default=str)

    print(f"\n[OK] JSON report saved: {output_file}")


# Framework name normalization
FRAMEWORK_NAMES = {
    "nist-csf2": "NIST_CSF",
    "nist-csf1": "NIST_CSF",
    "iso27001": "ISO_27001",
    "soc2": "SOC2",
    "cis": "CIS_CONTROLS",
}


def main():
    """Run the GRC Threat Modeler pipeline."""
    parser = build_cli()
    args = parser.parse_args()

    # Configure logging
    configure_logging(level=args.log_level)
    logger = get_logger("main")

    logger.info("GRC Threat Modeler v0.1.0")
    logger.info(f"Input: {args.input}")
    logger.info(f"Framework: {args.framework}")

    try:
        # Step 1: Load compliance profile
        if args.profile:
            profile = ComplianceProfile.from_yaml(args.profile)
            logger.info(f"Loaded profile: {profile.profile_name}")
        else:
            profile = ComplianceProfile.default()
            logger.info("Using default profile (all REQUIRED)")

        # Step 2: Parse report
        framework_name = FRAMEWORK_NAMES.get(args.framework, args.framework)
        report_parser = get_parser(args.input, default_framework=framework_name)
        controls = report_parser.parse(args.input)

        # Step 3: Validate
        warnings = validate_controls(controls)
        for w in warnings:
            logger.warning(f"Validation: {w}")

        # Step 4: Gap analysis
        analyzer = GapAnalyzer(profile=profile)
        result = analyzer.analyze(controls)

        # Step 5: ATT&CK coverage analysis
        mapper = ControlMapper(mappings_dir="data/mappings")
        coverage = CoverageAnalyzer(mapper=mapper)
        result = coverage.analyze_coverage(result)

        # Step 6: Tier scoring
        scorer = TierScorer()
        roadmap = scorer.get_remediation_roadmap(result.findings)

        # Step 7: Output
        output_dir = Path(args.output_dir)
        output_format = args.output_format

        if output_format in ("table", "both"):
            print_table(result)

        if output_format in ("json", "both"):
            save_json(result, output_dir)

        logger.info("Pipeline complete!")

    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
