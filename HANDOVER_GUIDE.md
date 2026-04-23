# GRC Threat Modeler: Technical Handover Document

This document provides a comprehensive overview of the **GRC Threat Modeler** project. It is designed to enable a seamless handover to a web development or full-stack agentic AI for further refinement, scaling, or feature implementation.

## 1. Project Overview
The **GRC Threat Modeler** is a professional-grade GRC (Governance, Risk, and Compliance) automation dashboard. It transforms raw compliance assessment reports (CSV, JSON, etc.) into actionable threat-informed intelligence by mapping compliance gaps to the **MITRE ATT&CK** framework and providing specific remediation recommendations.

### Key Value Propositions:
- **Automated Gap Analysis**: Compares assessment data against configurable "Compliance Profiles" (e.g., Startup, Enterprise).
- **Threat-Informed GRC**: Directly links missing security controls to specific adversary techniques.
- **Remediation Intelligence**: Generates a prioritized roadmap with estimated effort, timelines, and "Quick Wins."
- **Executive-Ready Reporting**: Auto-generates a narrative executive summary and maturity assessment.

---

## 2. Technology Stack
- **Backend**: Python 3.11+
    - **Framework**: Flask (REST API)
    - **Data Validation**: Pydantic v2
    - **Configuration**: PyYAML
- **Frontend**: Vanilla JavaScript (ES6+), HTML5, CSS3
    - **Design System**: Custom Glassmorphism (Dark/Light mode support)
    - **Visualizations**: Animated SVG rings, Donut charts, CSS Heatmaps
- **Architecture**: Modular "Analyzer Pipeline" pattern.

---

## 3. Project Structure
```text
GRCA/
├── config/                 # YAML Configuration
│   └── profiles/           # Compliance tier definitions (Required vs Desired)
├── data/
│   ├── mappings/           # NIST/ISO to MITRE ATT&CK mapping JSONs
│   └── sample_reports/     # Demonstration data (CSV/JSON)
├── src/                    # Core Logic (The "Brain")
│   ├── analyzers/          # The Intelligence Layer
│   │   ├── gap_analyzer.py # Core compliance logic
│   │   ├── coverage_analyzer.py # ATT&CK mapping logic
│   │   ├── remediation_engine.py # Fix recommendations data/logic
│   │   ├── executive_summary.py # Narrative generator
│   │   └── tier_scorer.py   # Priority/Score calculation
│   ├── models/             # Pydantic data schemas
│   └── parsers/            # Multi-format ingestion (CSV/JSON/XLSX)
├── web/                    # Presentation Layer
│   ├── app.py              # Flask server & API Endpoints
│   └── static/             # SPA Frontend (app.js, style.css, index.html)
└── tests/                  # Pytest suite (27+ tests)
```

---

## 4. The Analysis Pipeline (Data Flow)
When a user uploads a report or runs a sample, the following sequential pipeline executes:

1.  **Ingestion**: `parser_factory.py` selects the correct parser based on file extension.
2.  **Normalization**: `BaseParser` converts raw data into a standard list of `Control` models.
3.  **Gap Analysis**: `GapAnalyzer` compares controls against the selected `ComplianceProfile` (e.g., identifying "Missing" required controls).
4.  **Threat Mapping**: `CoverageAnalyzer` uses `ControlMapper` to find matching MITRE ATT&CK techniques for every identified gap.
5.  **Remediation Enrichment**: `RemediationEngine` attaches actionable steps, effort estimates, and "Quick Wins" to each finding.
6.  **Executive Summarization**: `executive_summary.py` analyzes the final results to write a narrative summary and calculate CMMI-style maturity.
7.  **Serialization**: The entire graph is serialized to JSON and sent to the frontend.

---

## 5. UI Features & Components
- **Dashboard Overview**: Summary cards with animated counters and a compliance percentage ring.
- **Executive Summary Card**: Auto-generated text section with a "Maturity Gauge" (Level 1-5).
- **Detail Grid**:
    - **Donut Chart**: Interactive breakdown of control statuses (Implemented, Partial, Missing).
    - **Tier Bars**: Visual coverage by Compliance Tier (Required, Desired, etc.).
    - **Remediation Roadmap**: High-level count of findings by Priority (P1-P4).
- **Findings Table**: Clickable rows that open a **Slide-in Detail Drawer**.
- **Detail Drawer**: Displays full control metadata, ATT&CK techniques, and the **Remediation Panel**.
- **ATT&CK Heatmap**: A compact grid of technique IDs color-coded by risk level.
- **Theme Engine**: Persistence-enabled Dark/Light mode toggle.

---

## 6. API Reference (Key Endpoints)
- `GET /api/profiles`: Returns list of available compliance profiles.
- `GET /api/sample-reports`: Returns list of demo files.
- `POST /api/analyze`: Multi-part upload handler.
- `POST /api/analyze-sample`: Runs analysis on an internal data file.

---

## 7. Instructions for the Next Agent

### Setup:
1. Ensure a virtual environment is active: `.\venv\Scripts\activate`
2. Run server: `python web/app.py --port 5000`
3. Access: `http://127.0.0.1:5000`

### Recommended Next Steps:
1.  **Persistence**: Implement a simple SQLite backend to save analysis history and show "Compliance over time" charts.
2.  **PDF Export**: Use a library like `jsPDF` or a backend solution (`WeasyPrint`) to generate high-fidelity audit reports.
3.  **Interactive Remediation**: Add a "Feedback" field in the Detail Drawer allowing users to provide "Suggested Changes" to the remediation results (the infrastructure for the `recommendations` field in the `GapFinding` model is already in place).
4.  **Auth/Multitenancy**: If scaling beyond a portfolio piece, implement user sessions to separate data.
5.  **Enhanced Visualization**: Replace the CSS bars with a proper Radar/Spider chart for function-area coverage (NIST Functions: Identify, Protect, Detect, etc.).

---
*Generated by Antigravity AI for Project Handover.*
