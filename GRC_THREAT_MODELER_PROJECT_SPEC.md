# GRC-to-Threat-Model Automation Project

## Project Overview
**Name:** GRC Threat Modeler  
**Purpose:** Automated tool that transforms GRC compliance reports into actionable threat models using MITRE ATT&CK framework  
**Portfolio Value:** Demonstrates understanding of compliance frameworks, threat intelligence, security automation, and practical risk analysis

---

## What This Tool Does

### Input
- GRC compliance reports (NIST CSF, ISO 27001, SOC 2, CIS Controls)
- Formats: CSV, JSON, Excel, PDF

### Processing
1. Parses compliance assessment data
2. Identifies control gaps and weaknesses
3. Maps missing/weak controls to MITRE ATT&CK techniques
4. Generates threat scenarios based on exposed attack surface
5. Produces risk scoring and prioritization

### Output
- MITRE ATT&CK Navigator heatmap (JSON layer file)
- Detailed threat model report (PDF/HTML)
- Attack scenario documentation
- Prioritized remediation roadmap
- Visual architecture diagrams showing vulnerable components

---

## Project Architecture

```
grc-threat-modeler/
├── README.md
├── requirements.txt
├── setup.py
├── .gitignore
├── config/
│   ├── config.yaml              # Application configuration
│   └── logging_config.yaml      # Logging settings
├── data/
│   ├── mappings/
│   │   ├── nist_csf_to_attack.json
│   │   ├── iso27001_to_attack.json
│   │   ├── cis_controls_to_attack.json
│   │   └── soc2_to_attack.json
│   ├── mitre_attack/
│   │   ├── enterprise-attack.json   # MITRE ATT&CK STIX data
│   │   └── techniques_matrix.json
│   └── sample_reports/
│       ├── sample_nist_assessment.csv
│       ├── sample_iso27001_audit.json
│       └── sample_soc2_gaps.xlsx
├── src/
│   ├── __init__.py
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── base_parser.py
│   │   ├── nist_parser.py
│   │   ├── iso_parser.py
│   │   ├── soc2_parser.py
│   │   └── cis_parser.py
│   ├── mappers/
│   │   ├── __init__.py
│   │   ├── control_mapper.py       # Maps controls to ATT&CK
│   │   ├── asset_mapper.py         # Identifies assets from controls
│   │   └── threat_mapper.py        # Generates threat scenarios
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── gap_analyzer.py         # Analyzes control gaps
│   │   ├── risk_scorer.py          # Calculates risk scores
│   │   └── coverage_analyzer.py    # ATT&CK coverage analysis
│   ├── generators/
│   │   ├── __init__.py
│   │   ├── attack_navigator.py     # Generate ATT&CK layer files
│   │   ├── report_generator.py     # PDF/HTML reports
│   │   ├── scenario_generator.py   # Threat scenarios
│   │   └── diagram_generator.py    # Architecture diagrams
│   ├── models/
│   │   ├── __init__.py
│   │   ├── control.py              # Control data model
│   │   ├── threat.py               # Threat data model
│   │   ├── asset.py                # Asset data model
│   │   └── report.py               # Report data model
│   └── utils/
│       ├── __init__.py
│       ├── logger.py
│       ├── file_handler.py
│       └── validators.py
├── templates/
│   ├── report_template.html
│   ├── scenario_template.md
│   └── navigator_template.json
├── outputs/                         # Generated reports go here
│   ├── reports/
│   ├── navigator_layers/
│   └── diagrams/
├── tests/
│   ├── __init__.py
│   ├── test_parsers.py
│   ├── test_mappers.py
│   ├── test_analyzers.py
│   └── test_generators.py
├── scripts/
│   ├── download_mitre_data.py      # Fetch latest ATT&CK data
│   └── generate_sample_data.py     # Create demo reports
├── docs/
│   ├── ARCHITECTURE.md
│   ├── MAPPING_METHODOLOGY.md
│   ├── API_REFERENCE.md
│   └── USAGE_EXAMPLES.md
└── main.py                          # CLI entry point
```

---

## Tech Stack

### Core
- **Python 3.9+**
- **pandas** - Data manipulation
- **openpyxl** - Excel file handling
- **PyPDF2** or **pdfplumber** - PDF parsing
- **pyyaml** - Configuration management

### MITRE ATT&CK Integration
- **stix2** - MITRE ATT&CK STIX data handling
- **attackcti** - ATT&CK CTI Python library
- **mitreattack-python** - Official MITRE library

### Report Generation
- **Jinja2** - HTML templating
- **WeasyPrint** or **ReportLab** - PDF generation
- **Graphviz** or **diagrams** - Architecture diagrams
- **Plotly** or **matplotlib** - Risk visualizations

### Optional Enhancements
- **OpenAI/Anthropic API** - Generate threat narratives with LLM
- **FastAPI** - Web API for the tool
- **Streamlit** - Interactive web UI

---

## Implementation Roadmap

### Phase 1: Foundation (Week 1)
**Goal:** Basic parsing and data models

#### Tasks:
1. **Project Setup**
   ```bash
   mkdir grc-threat-modeler && cd grc-threat-modeler
   python -m venv venv
   source venv/bin/activate
   pip install pandas openpyxl pyyaml stix2 jinja2
   ```

2. **Create Data Models** (`src/models/`)
   - `Control` class: id, name, description, status, framework, severity
   - `Threat` class: attack_technique, tactic, description, likelihood, impact
   - `Asset` class: name, type, criticality, protected_by_controls
   - `Report` class: aggregates all data for output

3. **Build Sample GRC Reports** (`data/sample_reports/`)
   - Create CSV with columns: Control_ID, Control_Name, Status (Implemented/Partial/Missing), Framework, Category
   - Example: NIST CSF assessment with 50 controls

4. **Implement Base Parser** (`src/parsers/base_parser.py`)
   ```python
   class BaseParser:
       def parse(self, file_path: str) -> List[Control]:
           """Parse GRC report and return Control objects"""
           pass
       
       def validate(self, data) -> bool:
           """Validate parsed data structure"""
           pass
   ```

5. **Download MITRE ATT&CK Data**
   - Script to fetch enterprise-attack.json from MITRE GitHub
   - Store in `data/mitre_attack/`

**Deliverable:** Can parse a sample NIST report into Control objects

---

### Phase 2: Control-to-ATT&CK Mapping (Week 2)
**Goal:** Map compliance controls to MITRE ATT&CK techniques

#### Tasks:
1. **Create Mapping Files** (`data/mappings/`)
   - Research and build JSON mappings:
   ```json
   {
     "NIST_CSF_PR.AC-1": {
       "control_name": "Identity Management",
       "mitigates_techniques": ["T1078", "T1110", "T1552"],
       "protects_assets": ["user_accounts", "authentication_systems"],
       "tactics": ["Initial Access", "Credential Access"]
     }
   }
   ```
   - Start with 20-30 high-value controls

2. **Build Control Mapper** (`src/mappers/control_mapper.py`)
   ```python
   class ControlMapper:
       def map_control_to_attack(self, control: Control) -> List[str]:
           """Returns list of ATT&CK technique IDs this control mitigates"""
           pass
       
       def identify_gaps(self, controls: List[Control]) -> Dict:
           """Returns techniques NOT covered by implemented controls"""
           pass
   ```

3. **Implement Gap Analyzer** (`src/analyzers/gap_analyzer.py`)
   - Identify missing/partial controls
   - Map gaps to exposed ATT&CK techniques
   - Calculate coverage percentage per tactic

**Deliverable:** Given controls, outputs list of unmitigated ATT&CK techniques

---

### Phase 3: Threat Scenario Generation (Week 3)
**Goal:** Generate realistic attack scenarios based on gaps

#### Tasks:
1. **Build Threat Mapper** (`src/mappers/threat_mapper.py`)
   ```python
   class ThreatMapper:
       def generate_scenarios(self, gaps: List[str]) -> List[ThreatScenario]:
           """Create attack scenarios from technique combinations"""
           pass
       
       def build_attack_chain(self, techniques: List[str]) -> AttackChain:
           """Link techniques into logical attack progression"""
           pass
   ```

2. **Implement Risk Scorer** (`src/analyzers/risk_scorer.py`)
   - Likelihood scoring (based on threat actor prevalence, ease of exploit)
   - Impact scoring (based on asset criticality)
   - Combined risk score: likelihood × impact
   - Prioritization ranking

3. **Create Scenario Templates** (`templates/scenario_template.md`)
   ```markdown
   ## Threat Scenario: [Name]
   **ATT&CK Techniques:** T1078, T1110, T1552
   **Tactics:** Initial Access → Credential Access → Privilege Escalation
   
   ### Attack Narrative
   [Generated description of attack flow]
   
   ### Exploited Gaps
   - Missing Control: MFA on all accounts
   - Partial Control: Password complexity policy
   
   ### Risk Score: 8.5/10
   - Likelihood: High (common attack pattern)
   - Impact: Critical (admin access compromise)
   
   ### Recommendations
   1. Implement MFA across all user accounts
   2. Deploy credential monitoring solution
   ```

**Deliverable:** Generates 5-10 realistic threat scenarios with risk scores

---

### Phase 4: ATT&CK Navigator Integration (Week 4)
**Goal:** Visual heatmap of vulnerable techniques

#### Tasks:
1. **Build Navigator Generator** (`src/generators/attack_navigator.py`)
   ```python
   class AttackNavigatorGenerator:
       def create_layer(self, threats: List[Threat]) -> dict:
           """Generate ATT&CK Navigator layer JSON"""
           pass
       
       def apply_scoring(self, layer: dict, scores: Dict[str, float]) -> dict:
           """Color-code techniques by risk score"""
           pass
   ```

2. **Navigator Layer Format**
   ```json
   {
     "name": "GRC Gap Analysis - ACME Corp",
     "versions": {
       "attack": "14",
       "navigator": "4.9.1",
       "layer": "4.5"
     },
     "domain": "enterprise-attack",
     "techniques": [
       {
         "techniqueID": "T1078",
         "score": 85,
         "color": "#ff6666",
         "comment": "Valid Accounts: Missing MFA control",
         "enabled": true
       }
     ]
   }
   ```

3. **Color-Coding Logic**
   - Red (90-100): Critical gaps, easy to exploit
   - Orange (70-89): High risk gaps
   - Yellow (50-69): Medium risk
   - Green (<50): Low priority or partial mitigation

**Deliverable:** JSON file that loads into ATT&CK Navigator showing risk heatmap

---

### Phase 5: Report Generation (Week 5)
**Goal:** Professional PDF/HTML reports

#### Tasks:
1. **HTML Report Generator** (`src/generators/report_generator.py`)
   - Executive summary
   - Control coverage statistics
   - Top 10 critical gaps
   - Threat scenario details
   - ATT&CK heatmap embed
   - Remediation roadmap with cost/timeline estimates

2. **PDF Conversion**
   - Use WeasyPrint to convert HTML → PDF
   - Include charts and diagrams
   - Professional styling

3. **Diagram Generator** (`src/generators/diagram_generator.py`)
   - Attack chain flow diagrams
   - Asset relationship graphs
   - Coverage visualization (radar chart of tactics)

**Deliverable:** Complete threat model report ready for stakeholder presentation

---

### Phase 6: CLI & Automation (Week 6)
**Goal:** Easy-to-use command-line tool

#### Tasks:
1. **Build CLI** (`main.py`)
   ```python
   import argparse
   
   def main():
       parser = argparse.ArgumentParser(description='GRC Threat Modeler')
       parser.add_argument('--input', required=True, help='GRC report file')
       parser.add_argument('--framework', required=True, 
                          choices=['nist', 'iso27001', 'soc2', 'cis'])
       parser.add_argument('--output-dir', default='./outputs')
       parser.add_argument('--format', choices=['html', 'pdf', 'both'], 
                          default='both')
       args = parser.parse_args()
       
       # Run pipeline
       # 1. Parse report
       # 2. Map controls
       # 3. Analyze gaps
       # 4. Generate threats
       # 5. Create navigator layer
       # 6. Generate report
   ```

2. **Usage Example**
   ```bash
   python main.py \
     --input data/sample_reports/nist_assessment.csv \
     --framework nist \
     --output-dir outputs/acme_corp \
     --format both
   ```

3. **Add Logging**
   - Progress indicators
   - Error handling
   - Validation warnings

**Deliverable:** Fully automated CLI tool

---

## Detailed Implementation Guide

### Step-by-Step: Building the Control Mapper

```python
# src/mappers/control_mapper.py

import json
from typing import List, Dict
from pathlib import Path
from src.models.control import Control

class ControlMapper:
    def __init__(self, mapping_file: str):
        """Load framework-to-ATT&CK mappings"""
        with open(mapping_file, 'r') as f:
            self.mappings = json.load(f)
    
    def map_control_to_techniques(self, control: Control) -> List[str]:
        """
        Returns ATT&CK technique IDs mitigated by this control
        
        Args:
            control: Control object from parsed GRC report
            
        Returns:
            List of technique IDs (e.g., ['T1078', 'T1110'])
        """
        control_id = control.id
        if control_id in self.mappings:
            return self.mappings[control_id].get('mitigates_techniques', [])
        return []
    
    def identify_coverage_gaps(self, controls: List[Control]) -> Dict:
        """
        Identifies ATT&CK techniques NOT covered by implemented controls
        
        Args:
            controls: List of all controls from GRC assessment
            
        Returns:
            {
                'covered_techniques': ['T1078', ...],
                'gap_techniques': ['T1110', ...],
                'coverage_percentage': 65.5,
                'gaps_by_tactic': {
                    'Initial Access': ['T1190', 'T1133'],
                    'Persistence': ['T1136', 'T1053']
                }
            }
        """
        # Get all techniques that SHOULD be covered
        all_techniques = set()
        for mapping in self.mappings.values():
            all_techniques.update(mapping.get('mitigates_techniques', []))
        
        # Get techniques actually covered by implemented controls
        covered = set()
        for control in controls:
            if control.status == 'Implemented':
                covered.update(self.map_control_to_techniques(control))
        
        # Calculate gaps
        gaps = all_techniques - covered
        coverage_pct = (len(covered) / len(all_techniques) * 100) if all_techniques else 0
        
        # Group gaps by tactic
        gaps_by_tactic = self._group_by_tactic(gaps)
        
        return {
            'covered_techniques': list(covered),
            'gap_techniques': list(gaps),
            'coverage_percentage': round(coverage_pct, 2),
            'gaps_by_tactic': gaps_by_tactic,
            'total_techniques': len(all_techniques),
            'total_covered': len(covered),
            'total_gaps': len(gaps)
        }
    
    def _group_by_tactic(self, techniques: set) -> Dict[str, List[str]]:
        """Group techniques by MITRE ATT&CK tactic"""
        # Load ATT&CK data to get tactic mappings
        attack_data_path = Path('data/mitre_attack/enterprise-attack.json')
        with open(attack_data_path, 'r') as f:
            attack_data = json.load(f)
        
        # Build technique-to-tactic mapping
        technique_tactics = {}
        for obj in attack_data['objects']:
            if obj['type'] == 'attack-pattern':
                tech_id = obj['external_references'][0]['external_id']
                tactics = [phase['phase_name'] for phase in obj.get('kill_chain_phases', [])]
                technique_tactics[tech_id] = tactics
        
        # Group gaps by tactic
        gaps_by_tactic = {}
        for tech_id in techniques:
            tactics = technique_tactics.get(tech_id, ['Unknown'])
            for tactic in tactics:
                if tactic not in gaps_by_tactic:
                    gaps_by_tactic[tactic] = []
                gaps_by_tactic[tactic].append(tech_id)
        
        return gaps_by_tactic
```

---

### Step-by-Step: Creating NIST-to-ATT&CK Mapping

```json
// data/mappings/nist_csf_to_attack.json

{
  "PR.AC-1": {
    "control_name": "Identities and credentials are issued, managed, verified, revoked, and audited",
    "description": "Identity management processes and technologies",
    "mitigates_techniques": [
      "T1078",
      "T1110",
      "T1555",
      "T1552"
    ],
    "protects_assets": ["user_accounts", "authentication_systems", "identity_providers"],
    "tactics": ["Initial Access", "Credential Access", "Privilege Escalation"],
    "criticality": "High"
  },
  "PR.AC-4": {
    "control_name": "Access permissions and authorizations are managed",
    "description": "Principle of least privilege implementation",
    "mitigates_techniques": [
      "T1098",
      "T1136",
      "T1078.002",
      "T1484"
    ],
    "protects_assets": ["active_directory", "access_control_systems", "privileged_accounts"],
    "tactics": ["Persistence", "Privilege Escalation"],
    "criticality": "Critical"
  },
  "PR.AC-5": {
    "control_name": "Network integrity is protected",
    "description": "Network segmentation and segregation",
    "mitigates_techniques": [
      "T1021",
      "T1563",
      "T1210",
      "T1570"
    ],
    "protects_assets": ["network_infrastructure", "network_segments", "critical_systems"],
    "tactics": ["Lateral Movement"],
    "criticality": "High"
  },
  "DE.CM-1": {
    "control_name": "The network is monitored to detect potential cybersecurity events",
    "description": "Network monitoring and anomaly detection",
    "mitigates_techniques": [
      "T1071",
      "T1090",
      "T1095",
      "T1572",
      "T1048"
    ],
    "protects_assets": ["network_traffic", "network_devices", "data_flows"],
    "tactics": ["Command and Control", "Exfiltration"],
    "criticality": "High"
  },
  "DE.CM-7": {
    "control_name": "Monitoring for unauthorized personnel, connections, devices, and software",
    "description": "Asset and device monitoring",
    "mitigates_techniques": [
      "T1200",
      "T1091",
      "T1133",
      "T1199"
    ],
    "protects_assets": ["endpoints", "network_perimeter", "third_party_connections"],
    "tactics": ["Initial Access", "Lateral Movement"],
    "criticality": "Medium"
  },
  "PR.DS-1": {
    "control_name": "Data-at-rest is protected",
    "description": "Encryption and protection of stored data",
    "mitigates_techniques": [
      "T1005",
      "T1039",
      "T1025",
      "T1530"
    ],
    "protects_assets": ["databases", "file_shares", "backup_systems", "cloud_storage"],
    "tactics": ["Collection"],
    "criticality": "Critical"
  },
  "PR.DS-2": {
    "control_name": "Data-in-transit is protected",
    "description": "Encryption of data during transmission",
    "mitigates_techniques": [
      "T1040",
      "T1557",
      "T1185",
      "T1557.002"
    ],
    "protects_assets": ["network_communications", "web_traffic", "email_systems"],
    "tactics": ["Credential Access", "Collection"],
    "criticality": "Critical"
  },
  "PR.IP-12": {
    "control_name": "A vulnerability management plan is developed and implemented",
    "description": "Vulnerability scanning and patch management",
    "mitigates_techniques": [
      "T1190",
      "T1203",
      "T1210",
      "T1068"
    ],
    "protects_assets": ["web_applications", "servers", "workstations", "network_devices"],
    "tactics": ["Initial Access", "Execution", "Privilege Escalation"],
    "criticality": "Critical"
  },
  "RS.RP-1": {
    "control_name": "Response plan is executed during or after an incident",
    "description": "Incident response capabilities",
    "mitigates_techniques": [
      "T1070",
      "T1485",
      "T1490",
      "T1486"
    ],
    "protects_assets": ["all_systems", "backup_systems", "recovery_infrastructure"],
    "tactics": ["Impact", "Defense Evasion"],
    "criticality": "High"
  }
}
```

---

### Step-by-Step: Threat Scenario Generator

```python
# src/generators/scenario_generator.py

from typing import List, Dict
from src.models.threat import Threat, ThreatScenario, AttackChain
import json

class ScenarioGenerator:
    def __init__(self, attack_data_path: str):
        """Load MITRE ATT&CK data for scenario context"""
        with open(attack_data_path, 'r') as f:
            attack_data = json.load(f)
        
        # Build lookup dictionaries
        self.techniques = {}
        self.tactics = {}
        
        for obj in attack_data['objects']:
            if obj['type'] == 'attack-pattern':
                tech_id = obj['external_references'][0]['external_id']
                self.techniques[tech_id] = {
                    'name': obj['name'],
                    'description': obj['description'],
                    'tactics': [p['phase_name'] for p in obj.get('kill_chain_phases', [])],
                    'platforms': obj.get('x_mitre_platforms', [])
                }
    
    def generate_scenarios(self, gap_analysis: Dict) -> List[ThreatScenario]:
        """
        Generate realistic attack scenarios from identified gaps
        
        Args:
            gap_analysis: Output from ControlMapper.identify_coverage_gaps()
            
        Returns:
            List of ThreatScenario objects with narratives, risk scores
        """
        scenarios = []
        
        # Group gaps by attack progression (Initial Access → Impact)
        attack_chains = self._build_attack_chains(gap_analysis['gaps_by_tactic'])
        
        for chain in attack_chains:
            scenario = ThreatScenario(
                name=self._generate_scenario_name(chain),
                techniques=chain['techniques'],
                tactics=chain['tactics'],
                narrative=self._generate_narrative(chain),
                likelihood=self._calculate_likelihood(chain),
                impact=self._calculate_impact(chain),
                risk_score=0  # Will be calculated
            )
            
            # Risk score = likelihood × impact
            scenario.risk_score = round(scenario.likelihood * scenario.impact, 2)
            scenarios.append(scenario)
        
        # Sort by risk score descending
        scenarios.sort(key=lambda x: x.risk_score, reverse=True)
        
        return scenarios[:10]  # Return top 10 scenarios
    
    def _build_attack_chains(self, gaps_by_tactic: Dict) -> List[Dict]:
        """
        Build logical attack chains from technique gaps
        
        Chain progression: Initial Access → Execution → Persistence → 
                          Privilege Escalation → Defense Evasion → 
                          Credential Access → Discovery → Lateral Movement → 
                          Collection → Exfiltration → Impact
        """
        tactic_order = [
            'Initial Access', 'Execution', 'Persistence', 
            'Privilege Escalation', 'Defense Evasion',
            'Credential Access', 'Discovery', 'Lateral Movement',
            'Collection', 'Exfiltration', 'Impact'
        ]
        
        chains = []
        
        # Strategy 1: Ransomware chain
        if 'Initial Access' in gaps_by_tactic and 'Impact' in gaps_by_tactic:
            ransomware_chain = {
                'name': 'Ransomware Attack',
                'techniques': [],
                'tactics': []
            }
            for tactic in tactic_order:
                if tactic in gaps_by_tactic and gaps_by_tactic[tactic]:
                    # Pick first technique from this tactic
                    tech = gaps_by_tactic[tactic][0]
                    ransomware_chain['techniques'].append(tech)
                    ransomware_chain['tactics'].append(tactic)
            
            if len(ransomware_chain['techniques']) >= 3:
                chains.append(ransomware_chain)
        
        # Strategy 2: Data exfiltration chain
        if 'Initial Access' in gaps_by_tactic and 'Exfiltration' in gaps_by_tactic:
            exfil_chain = {
                'name': 'Data Breach',
                'techniques': [],
                'tactics': []
            }
            for tactic in ['Initial Access', 'Credential Access', 'Discovery', 
                          'Collection', 'Exfiltration']:
                if tactic in gaps_by_tactic and gaps_by_tactic[tactic]:
                    tech = gaps_by_tactic[tactic][0]
                    exfil_chain['techniques'].append(tech)
                    exfil_chain['tactics'].append(tactic)
            
            if len(exfil_chain['techniques']) >= 3:
                chains.append(exfil_chain)
        
        # Strategy 3: Insider threat / Privilege escalation
        if 'Privilege Escalation' in gaps_by_tactic:
            insider_chain = {
                'name': 'Insider Threat',
                'techniques': [],
                'tactics': []
            }
            for tactic in ['Privilege Escalation', 'Defense Evasion', 
                          'Credential Access', 'Lateral Movement', 'Collection']:
                if tactic in gaps_by_tactic and gaps_by_tactic[tactic]:
                    tech = gaps_by_tactic[tactic][0]
                    insider_chain['techniques'].append(tech)
                    insider_chain['tactics'].append(tactic)
            
            if len(insider_chain['techniques']) >= 3:
                chains.append(insider_chain)
        
        return chains if chains else [self._create_default_chain(gaps_by_tactic)]
    
    def _generate_narrative(self, chain: Dict) -> str:
        """Generate human-readable attack narrative"""
        narrative_parts = [
            f"## {chain['name']} Scenario\n",
            "### Attack Progression\n"
        ]
        
        for i, (technique, tactic) in enumerate(zip(chain['techniques'], chain['tactics']), 1):
            tech_info = self.techniques.get(technique, {})
            tech_name = tech_info.get('name', technique)
            
            narrative_parts.append(
                f"{i}. **{tactic}**: {tech_name} ({technique})\n"
                f"   - {tech_info.get('description', 'No description available')[:200]}...\n"
            )
        
        narrative_parts.append("\n### Attack Flow\n")
        narrative_parts.append(self._generate_story(chain))
        
        return ''.join(narrative_parts)
    
    def _generate_story(self, chain: Dict) -> str:
        """Generate narrative story of the attack"""
        if chain['name'] == 'Ransomware Attack':
            return (
                "An attacker gains initial access through an unpatched vulnerability "
                "or phishing email. They establish persistence and escalate privileges "
                "to domain administrator level. After disabling security controls, they "
                "deploy ransomware across the network, encrypting critical business data "
                "and demanding payment for decryption keys. Without adequate backups or "
                "recovery procedures, the organization faces extended downtime and potential "
                "data loss."
            )
        elif chain['name'] == 'Data Breach':
            return (
                "An adversary compromises user credentials through password spraying or "
                "credential stuffing. Using valid accounts, they move laterally through "
                "the network, discovering sensitive data repositories. They exfiltrate "
                "intellectual property, customer data, or financial records to external "
                "infrastructure. The breach remains undetected due to inadequate monitoring, "
                "potentially resulting in regulatory fines and reputational damage."
            )
        elif chain['name'] == 'Insider Threat':
            return (
                "A malicious insider with legitimate access abuses their privileges to "
                "access systems beyond their authorization. They evade detection by "
                "operating within normal business hours and mimicking legitimate activities. "
                "The insider exfiltrates proprietary data or sabotages critical systems "
                "before departure, leveraging knowledge of security gaps and monitoring "
                "blind spots."
            )
        else:
            return (
                "An attacker exploits identified control gaps to compromise the organization. "
                "The attack progresses through multiple stages, exploiting weaknesses in "
                "detection and response capabilities. Without proper controls in place, "
                "the organization faces significant business impact."
            )
    
    def _calculate_likelihood(self, chain: Dict) -> float:
        """
        Calculate likelihood score (0-10)
        Based on: technique prevalence, ease of exploit, required resources
        """
        # Simple heuristic: more common techniques = higher likelihood
        common_techniques = {
            'T1078': 9,  # Valid Accounts - very common
            'T1110': 8,  # Brute Force - common
            'T1190': 7,  # Exploit Public-Facing Application
            'T1566': 9,  # Phishing - very common
            'T1486': 7,  # Ransomware
        }
        
        scores = []
        for tech in chain['techniques']:
            scores.append(common_techniques.get(tech, 5))  # Default medium
        
        return round(sum(scores) / len(scores), 1) if scores else 5.0
    
    def _calculate_impact(self, chain: Dict) -> float:
        """
        Calculate impact score (0-10)
        Based on: affected assets, business criticality, recovery difficulty
        """
        # Impact based on final tactic
        impact_by_tactic = {
            'Impact': 10,  # Data destruction, ransomware
            'Exfiltration': 9,  # Data breach
            'Lateral Movement': 6,  # Spreading but not final impact
            'Collection': 7,  # Data aggregation
            'Credential Access': 8  # Admin compromise
        }
        
        final_tactic = chain['tactics'][-1] if chain['tactics'] else 'Unknown'
        return impact_by_tactic.get(final_tactic, 5.0)
    
    def _generate_scenario_name(self, chain: Dict) -> str:
        """Generate descriptive scenario name"""
        return chain.get('name', 'Generic Attack Chain')
    
    def _create_default_chain(self, gaps_by_tactic: Dict) -> Dict:
        """Create a default chain when specific patterns don't match"""
        techniques = []
        tactics = []
        
        for tactic, techs in gaps_by_tactic.items():
            if techs:
                techniques.append(techs[0])
                tactics.append(tactic)
        
        return {
            'name': 'Multi-Stage Attack',
            'techniques': techniques[:5],  # Limit to 5 stages
            'tactics': tactics[:5]
        }
```

---

## Data Models

```python
# src/models/control.py

from dataclasses import dataclass
from typing import Optional

@dataclass
class Control:
    """Represents a single GRC control"""
    id: str                    # e.g., "PR.AC-1"
    name: str
    description: str
    framework: str             # "NIST_CSF", "ISO27001", etc.
    category: str              # "Access Control", "Monitoring", etc.
    status: str                # "Implemented", "Partial", "Missing"
    severity: Optional[str] = None     # "Critical", "High", "Medium", "Low"
    notes: Optional[str] = None
    
    def is_implemented(self) -> bool:
        return self.status == "Implemented"
    
    def is_gap(self) -> bool:
        return self.status in ["Missing", "Partial"]


# src/models/threat.py

from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Threat:
    """Represents a MITRE ATT&CK technique"""
    technique_id: str          # e.g., "T1078"
    name: str
    description: str
    tactics: List[str]         # ["Initial Access", "Persistence"]
    platforms: List[str]       # ["Windows", "Linux", "macOS"]
    
    @property
    def is_critical(self) -> bool:
        """Check if technique is in critical tactics"""
        critical_tactics = ["Initial Access", "Impact", "Exfiltration"]
        return any(tactic in critical_tactics for tactic in self.tactics)


@dataclass
class ThreatScenario:
    """Represents a complete attack scenario"""
    name: str
    techniques: List[str]      # Technique IDs in attack chain
    tactics: List[str]         # Corresponding tactics
    narrative: str             # Human-readable story
    likelihood: float          # 0-10 score
    impact: float              # 0-10 score
    risk_score: float          # likelihood × impact
    exploited_gaps: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def get_risk_level(self) -> str:
        """Return risk category"""
        if self.risk_score >= 80:
            return "Critical"
        elif self.risk_score >= 60:
            return "High"
        elif self.risk_score >= 40:
            return "Medium"
        else:
            return "Low"


# src/models/asset.py

@dataclass
class Asset:
    """Represents a protected asset"""
    name: str
    asset_type: str            # "server", "database", "application", etc.
    criticality: str           # "Critical", "High", "Medium", "Low"
    protected_by: List[str]    # Control IDs protecting this asset
    exposed_techniques: List[str] = field(default_factory=list)
    
    def is_at_risk(self) -> bool:
        """Check if asset has exposed attack techniques"""
        return len(self.exposed_techniques) > 0
```

---

## Sample Data Creation

```python
# scripts/generate_sample_data.py

import csv
import json
import random
from pathlib import Path

def generate_nist_assessment():
    """Generate sample NIST CSF assessment CSV"""
    
    nist_controls = [
        ("ID.AM-1", "Physical devices and systems inventoried", "Identify", "Implemented"),
        ("ID.AM-2", "Software platforms and applications inventoried", "Identify", "Implemented"),
        ("ID.AM-3", "Organizational communication and data flows mapped", "Identify", "Partial"),
        ("PR.AC-1", "Identities and credentials managed", "Protect", "Partial"),
        ("PR.AC-4", "Access permissions managed", "Protect", "Missing"),
        ("PR.AC-5", "Network integrity protected", "Protect", "Implemented"),
        ("PR.DS-1", "Data-at-rest protected", "Protect", "Partial"),
        ("PR.DS-2", "Data-in-transit protected", "Protect", "Implemented"),
        ("PR.IP-12", "Vulnerability management plan", "Protect", "Missing"),
        ("DE.CM-1", "Network monitored", "Detect", "Implemented"),
        ("DE.CM-7", "Monitoring for unauthorized activity", "Detect", "Partial"),
        ("DE.AE-2", "Detected events analyzed", "Detect", "Implemented"),
        ("RS.RP-1", "Response plan executed", "Respond", "Missing"),
        ("RS.CO-3", "Information shared with stakeholders", "Respond", "Partial"),
        ("RC.RP-1", "Recovery plan executed", "Recover", "Missing"),
    ]
    
    output_path = Path("data/sample_reports/nist_csf_assessment.csv")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Control_ID", "Control_Name", "Category", "Status", 
                        "Framework", "Severity", "Notes"])
        
        for control_id, name, category, status in nist_controls:
            severity = random.choice(["Critical", "High", "Medium"])
            notes = f"Assessment notes for {control_id}"
            writer.writerow([control_id, name, category, status, 
                           "NIST_CSF", severity, notes])
    
    print(f"✓ Generated NIST assessment: {output_path}")


def generate_iso27001_audit():
    """Generate sample ISO 27001 audit JSON"""
    
    audit_data = {
        "audit_date": "2024-01-15",
        "organization": "ACME Corporation",
        "auditor": "SecureAudit LLC",
        "controls": [
            {
                "control_id": "A.9.2.1",
                "name": "User registration and de-registration",
                "status": "Implemented",
                "evidence": "User lifecycle policy documented",
                "findings": []
            },
            {
                "control_id": "A.9.4.1",
                "name": "Information access restriction",
                "status": "Partial",
                "evidence": "RBAC implemented but not enforced on legacy systems",
                "findings": ["3 systems without access controls"]
            },
            {
                "control_id": "A.12.6.1",
                "name": "Management of technical vulnerabilities",
                "status": "Missing",
                "evidence": "No vulnerability scanning process",
                "findings": ["No vulnerability management program", 
                           "Patch management inconsistent"]
            },
            {
                "control_id": "A.13.1.1",
                "name": "Network controls",
                "status": "Implemented",
                "evidence": "Firewall rules documented and reviewed quarterly",
                "findings": []
            },
        ]
    }
    
    output_path = Path("data/sample_reports/iso27001_audit.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(audit_data, f, indent=2)
    
    print(f"✓ Generated ISO 27001 audit: {output_path}")


if __name__ == "__main__":
    generate_nist_assessment()
    generate_iso27001_audit()
    print("\n✓ Sample data generation complete!")
```

---

## Testing Strategy

```python
# tests/test_mappers.py

import unittest
from src.mappers.control_mapper import ControlMapper
from src.models.control import Control

class TestControlMapper(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.mapper = ControlMapper('data/mappings/nist_csf_to_attack.json')
        
        self.test_controls = [
            Control(
                id="PR.AC-1",
                name="Identity Management",
                description="Test control",
                framework="NIST_CSF",
                category="Access Control",
                status="Implemented"
            ),
            Control(
                id="PR.AC-4",
                name="Access Permissions",
                description="Test control",
                framework="NIST_CSF",
                category="Access Control",
                status="Missing"
            ),
        ]
    
    def test_map_control_to_techniques(self):
        """Test control-to-technique mapping"""
        techniques = self.mapper.map_control_to_techniques(self.test_controls[0])
        
        # PR.AC-1 should map to identity-related techniques
        self.assertIn("T1078", techniques)  # Valid Accounts
        self.assertGreater(len(techniques), 0)
    
    def test_identify_coverage_gaps(self):
        """Test gap analysis"""
        gaps = self.mapper.identify_coverage_gaps(self.test_controls)
        
        self.assertIn('covered_techniques', gaps)
        self.assertIn('gap_techniques', gaps)
        self.assertIn('coverage_percentage', gaps)
        
        # Should have some gaps since PR.AC-4 is missing
        self.assertGreater(len(gaps['gap_techniques']), 0)
    
    def test_gaps_grouped_by_tactic(self):
        """Test gap grouping by tactic"""
        gaps = self.mapper.identify_coverage_gaps(self.test_controls)
        
        self.assertIn('gaps_by_tactic', gaps)
        self.assertIsInstance(gaps['gaps_by_tactic'], dict)


if __name__ == '__main__':
    unittest.main()
```

---

## Documentation

### README.md Template

```markdown
# GRC Threat Modeler

Automated tool that transforms GRC compliance reports into actionable threat models using the MITRE ATT&CK framework.

## Features

- 🔍 Parse GRC reports (NIST CSF, ISO 27001, SOC 2, CIS Controls)
- 🎯 Map control gaps to MITRE ATT&CK techniques
- 📊 Generate risk-scored threat scenarios
- 🗺️ Create ATT&CK Navigator heatmaps
- 📄 Produce professional threat model reports

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Download MITRE ATT&CK data
python scripts/download_mitre_data.py

# Run analysis
python main.py \
  --input data/sample_reports/nist_assessment.csv \
  --framework nist \
  --output-dir outputs/demo

# Open outputs/demo/report.html in browser
```

## Example Output

**Input:** NIST CSF assessment with 15 controls (5 missing, 4 partial)

**Output:**
- 📊 Coverage: 60% of ATT&CK techniques mitigated
- ⚠️ 47 exposed techniques across 8 tactics
- 🎯 8 high-risk attack scenarios
- 🗺️ ATT&CK Navigator heatmap highlighting gaps
- 📄 20-page threat model report with remediation roadmap

## Project Structure

```
grc-threat-modeler/
├── src/                 # Source code
├── data/                # Mappings and sample data
├── outputs/             # Generated reports
├── tests/               # Unit tests
└── docs/                # Documentation
```

## Use Cases

1. **Security Assessments**: Convert audit findings into threat intelligence
2. **Risk Prioritization**: Identify which gaps pose the highest threat
3. **Board Reporting**: Translate compliance into business risk language
4. **Pen Test Scoping**: Focus testing on highest-risk attack paths

## Supported Frameworks

- NIST Cybersecurity Framework (CSF)
- ISO/IEC 27001
- SOC 2
- CIS Controls v8

## License

MIT License - See LICENSE file
```

---

## Enhancement Ideas (Phase 7+)

### Advanced Features
1. **LLM Integration**
   - Use Claude/GPT API to generate detailed attack narratives
   - Automatically write executive summaries
   - Threat actor profiling based on industry/geography

2. **Web Dashboard**
   - FastAPI backend + React frontend
   - Real-time analysis updates
   - Interactive ATT&CK heatmap explorer
   - Multi-tenant support for consultants

3. **Integration Capabilities**
   - JIRA integration for remediation tracking
   - Slack/Teams notifications for critical findings
   - Export to GRC platforms (ServiceNow, Archer)

4. **Machine Learning**
   - Learn from historical assessments
   - Predict likelihood based on industry data
   - Recommend control implementations

5. **Red Team Tools**
   - Generate attack playbooks from threat models
   - Export to Atomic Red Team format
   - Integration with attack simulation platforms

---

## Portfolio Presentation Tips

### GitHub README Should Include:
1. **Demo GIF/Video**: Screen recording showing the tool in action
2. **Before/After**: Side-by-side of GRC report → Threat model
3. **Sample Output**: Link to example HTML report
4. **Architecture Diagram**: Visual of the processing pipeline
5. **Metrics**: "Analyzed 500+ controls, identified 200+ threat scenarios"

### Blog Post Ideas:
- "From Compliance to Threats: Automating GRC Analysis"
- "Mapping NIST CSF to MITRE ATT&CK: A Data-Driven Approach"
- "Why Your SOC 2 Audit Should Include Threat Modeling"

### LinkedIn Post Template:
```
🔒 New Project: GRC Threat Modeler

Built an automated tool that transforms compliance assessments into actionable threat intelligence:

✅ Parses NIST/ISO/SOC2 reports
✅ Maps gaps to MITRE ATT&CK techniques
✅ Generates risk-scored attack scenarios
✅ Creates visual threat heatmaps

Result: Organizations can now see exactly which compliance gaps create real-world attack vectors.

Tech: Python, MITRE ATT&CK, pandas, data visualization

[Link to GitHub]
```

---

## Getting Started Checklist

Week 1:
- [ ] Set up project structure
- [ ] Create data models (Control, Threat, Asset)
- [ ] Build NIST parser for CSV
- [ ] Download MITRE ATT&CK data
- [ ] Create 10 control-to-ATT&CK mappings

Week 2:
- [ ] Implement ControlMapper
- [ ] Build gap analyzer
- [ ] Test with sample NIST report
- [ ] Verify ATT&CK technique identification

Week 3:
- [ ] Build ScenarioGenerator
- [ ] Implement risk scoring
- [ ] Create threat narratives
- [ ] Test scenario generation

Week 4:
- [ ] Build ATT&CK Navigator generator
- [ ] Create JSON layer files
- [ ] Test in ATT&CK Navigator web app
- [ ] Verify color coding

Week 5:
- [ ] Build HTML report generator
- [ ] Add PDF export
- [ ] Create diagrams
- [ ] Polish styling

Week 6:
- [ ] Build CLI interface
- [ ] Add logging and error handling
- [ ] Write unit tests
- [ ] Create documentation

Week 7:
- [ ] Polish GitHub README
- [ ] Add demo video/GIF
- [ ] Write blog post
- [ ] Share on LinkedIn

---

## Success Criteria

Your project is portfolio-ready when:

✅ It processes a real GRC report end-to-end  
✅ Output loads in ATT&CK Navigator successfully  
✅ Generated threat scenarios are realistic and actionable  
✅ Code is clean, tested, and documented  
✅ GitHub README has clear usage instructions  
✅ You can demo it in under 5 minutes  
✅ Non-technical people can understand the value from README

---

## Questions to Consider

1. **Data Source**: Will you use real audit data or synthetic?
2. **Mapping Depth**: How many controls will you map initially? (Start with 20-30)
3. **Framework Priority**: Which framework first? (NIST CSF is easiest)
4. **Output Format**: PDF, HTML, or both? (HTML first, easier to build)
5. **Deployment**: CLI only or add web UI later? (CLI first)

---

## Final Tips

1. **Start Small**: Get one framework working end-to-end before adding others
2. **Document As You Go**: Write README sections as you complete features
3. **Real Data**: Use actual NIST CSF controls, don't make them up
4. **Visual Output**: ATT&CK Navigator heatmap is the "wow factor"
5. **Tell the Story**: Your README should explain WHY this matters, not just HOW it works

Good luck! This project will genuinely impress cybersecurity architects and hiring managers. The combination of compliance knowledge + threat intelligence + automation is rare and valuable.
