"""
GRC Threat Modeler — Web Server

Flask application that provides a web UI for the GRC gap analysis pipeline.
Serves the dashboard and handles file uploads + analysis via REST API.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import traceback
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzers.gap_analyzer import GapAnalyzer
from src.analyzers.coverage_analyzer import CoverageAnalyzer
from src.analyzers.executive_summary import generate_executive_summary
from src.analyzers.remediation_engine import RemediationEngine
from src.analyzers.tier_scorer import TierScorer
from src.mappers.control_mapper import ControlMapper
from src.models.compliance_profile import ComplianceProfile
from src.parsers.parser_factory import get_parser, get_supported_formats
from src.utils.logger import configure_logging, get_logger
from src.utils.validators import validate_controls
from src.utils.paths import get_resource_path

configure_logging(level="INFO")
logger = get_logger("web.app")

# Detect if we are running in a bundled desktop app
IS_FROZEN = getattr(sys, 'frozen', False)

app = Flask(
    __name__,
    static_folder=str(get_resource_path("web/static")),
    template_folder=str(get_resource_path("web/static")), # We serve index.html from static
)

# Ensure uploads dir exists - for desktop, use a temp dir or local data dir
if IS_FROZEN:
    UPLOAD_DIR = Path(tempfile.gettempdir()) / "grca_uploads"
else:
    UPLOAD_DIR = Path(__file__).parent.parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# Project root for resolving config/data paths
PROJECT_ROOT = get_resource_path("")

# Framework label → internal key
FRAMEWORK_MAP = {
    "nist-csf2": "NIST_CSF",
    "nist-csf1": "NIST_CSF",
    "iso27001": "ISO_27001",
    "soc2": "SOC2",
    "cis": "CIS_CONTROLS",
}


@app.route("/")
def index():
    """Serve the main dashboard page."""
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/profiles", methods=["GET"])
def list_profiles():
    """List available compliance profiles."""
    profiles_dir = PROJECT_ROOT / "config" / "profiles"
    profiles = []

    if profiles_dir.exists():
        for p in sorted(profiles_dir.glob("*.yaml")):
            try:
                profile = ComplianceProfile.from_yaml(p)
                profiles.append({
                    "filename": p.name,
                    "name": profile.profile_name,
                    "description": profile.description,
                    "frameworks": {
                        k: v.tier.value for k, v in profile.frameworks.items()
                    },
                })
            except Exception as e:
                logger.warning(f"Failed to load profile {p.name}: {e}")

    return jsonify({"profiles": profiles})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Run the gap analysis pipeline on an uploaded report.

    Expects multipart form data:
        - file: The report file (CSV, JSON, XLSX, PDF)
        - framework: Framework identifier (nist-csf2, iso27001, etc.)
        - profile: Profile filename (optional, defaults to all-required)
    """
    # Validate file
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    framework = request.form.get("framework", "nist-csf2")
    profile_name = request.form.get("profile", "")

    # Save uploaded file
    suffix = Path(file.filename).suffix.lower()
    supported = get_supported_formats()
    if suffix not in supported:
        return jsonify({
            "error": f"Unsupported file format: {suffix}. Supported: {', '.join(supported)}"
        }), 400

    temp_path = UPLOAD_DIR / f"upload_{os.urandom(8).hex()}{suffix}"
    try:
        file.save(str(temp_path))
        logger.info(f"Saved upload: {temp_path.name}")

        # Load profile
        if profile_name:
            profile_path = PROJECT_ROOT / "config" / "profiles" / profile_name
            if profile_path.exists():
                profile = ComplianceProfile.from_yaml(profile_path)
            else:
                profile = ComplianceProfile.default()
        else:
            profile = ComplianceProfile.default()

        # Parse
        framework_name = FRAMEWORK_MAP.get(framework, framework)
        parser = get_parser(str(temp_path), default_framework=framework_name)
        controls = parser.parse(str(temp_path))

        # Validate
        warnings = validate_controls(controls)

        # Analyze
        analyzer = GapAnalyzer(profile=profile)
        result = analyzer.analyze(controls)

        # ATT&CK coverage
        mapper = ControlMapper(mappings_dir=str(PROJECT_ROOT / "data" / "mappings"))
        coverage = CoverageAnalyzer(mapper=mapper)
        result = coverage.analyze_coverage(result)

        # Remediation recommendations
        remediator = RemediationEngine()
        remediator.enrich_findings(result.findings)

        # Tier scoring
        scorer = TierScorer()
        roadmap = scorer.get_remediation_roadmap(result.findings)

        # Serialize result
        result_data = result.model_dump(mode="json")

        # Add roadmap summary
        result_data["roadmap"] = {
            k: len(v) for k, v in roadmap.items()
        }
        result_data["validation_warnings"] = warnings

        # Executive summary
        result_data["executive_summary"] = generate_executive_summary(result_data)

        return jsonify({"success": True, "result": result_data})

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        logger.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

    finally:
        # Cleanup
        if temp_path.exists():
            temp_path.unlink()


@app.route("/api/sample-reports", methods=["GET"])
def list_sample_reports():
    """List available sample reports for quick demo."""
    samples_dir = PROJECT_ROOT / "data" / "sample_reports"
    samples = []

    if samples_dir.exists():
        for f in sorted(samples_dir.iterdir()):
            if f.suffix in (".csv", ".json", ".xlsx"):
                # Guess framework from filename
                fw = "nist-csf2" if "nist" in f.name.lower() else "iso27001"
                samples.append({
                    "filename": f.name,
                    "framework": fw,
                    "size": f.stat().st_size,
                })

    return jsonify({"samples": samples})


@app.route("/api/analyze-sample", methods=["POST"])
def analyze_sample():
    """Run analysis on a built-in sample report."""
    data = request.get_json()
    if not data or "filename" not in data:
        return jsonify({"error": "No sample specified"}), 400

    sample_path = PROJECT_ROOT / "data" / "sample_reports" / data["filename"]
    if not sample_path.exists():
        return jsonify({"error": "Sample not found"}), 404

    framework = data.get("framework", "nist-csf2")
    profile_name = data.get("profile", "")

    try:
        # Load profile
        if profile_name:
            profile_path = PROJECT_ROOT / "config" / "profiles" / profile_name
            profile = ComplianceProfile.from_yaml(profile_path) if profile_path.exists() else ComplianceProfile.default()
        else:
            profile = ComplianceProfile.default()

        framework_name = FRAMEWORK_MAP.get(framework, framework)
        parser = get_parser(str(sample_path), default_framework=framework_name)
        controls = parser.parse(str(sample_path))

        warnings = validate_controls(controls)

        analyzer = GapAnalyzer(profile=profile)
        result = analyzer.analyze(controls)

        mapper = ControlMapper(mappings_dir=str(PROJECT_ROOT / "data" / "mappings"))
        coverage = CoverageAnalyzer(mapper=mapper)
        result = coverage.analyze_coverage(result)

        remediator = RemediationEngine()
        remediator.enrich_findings(result.findings)

        scorer = TierScorer()
        roadmap = scorer.get_remediation_roadmap(result.findings)

        result_data = result.model_dump(mode="json")
        result_data["roadmap"] = {k: len(v) for k, v in roadmap.items()}
        result_data["validation_warnings"] = warnings
        result_data["executive_summary"] = generate_executive_summary(result_data)

        return jsonify({"success": True, "result": result_data})

    except Exception as e:
        logger.error(f"Sample analysis failed: {e}")
        return jsonify({"error": str(e)}), 500


def main():
    """Launch the web server."""
    import argparse

    parser = argparse.ArgumentParser(description="GRC Threat Modeler Web UI")
    parser.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    parser.add_argument("--host", default="127.0.0.1", help="Host (default: 127.0.0.1)")
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    args = parser.parse_args()

    print(f"\n  GRC Threat Modeler v0.1.0")
    print(f"  Dashboard: http://{args.host}:{args.port}")
    print(f"  Press Ctrl+C to stop\n")

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
