# ONG‑OT Vulnerability Prioritization Dataset
### A domain‑expert, reproducible Oil & Gas OT vulnerability intelligence pipeline
**Author:** Friday Ogochukwu Ikwuogu
**Affiliation:** Independent Researcher, Odessa, Texas, USA
**ORCID:** 0009-0009-2222-1318
**Portfolio:** https://foikwuogu.github.io
**GitHub:** https://github.com/foikwuogu
**LinkedIn:** Ogochukwu Friday Ikwuogu
**Email:** Friday.ikwuogu@gmail.com

---

## Overview
The ONG‑OT Vulnerability Prioritization Dataset is a fully automated pipeline that ingests real‑world CVE intelligence from authoritative public sources, applies domain‑specific Oil & Gas OT rules, and produces a versioned, provenance‑rich dataset suitable for open scientific publication.

This project integrates:

- **CISA ICS Advisories**
- **CISA Known Exploited Vulnerabilities (KEV)**
- **FIRST.org EPSS scores**
- **CISA Vulnrichment (ADP enrichment)**
- **MITRE ATT&CK for ICS STIX bundle**

The pipeline merges all sources on CVE ID and applies three expert‑defined YAML configurations:

- `product_class_taxonomy.yaml`
- `no_patch_rules.yaml`
- `compensating_controls_cpg2.yaml`

These encode Oil & Gas OT product classes, no‑patch logic, and CPG 2.0 compensating controls with multiplicative risk‑reduction stacking.

---

## Features
- Automated multi‑source CVE ingestion
- ICS‑specific vendor/product classification
- No‑patch flagging based on advisory text and vendor status
- CPG 2.0 compensating control mapping
- Multiplicative risk‑reduction logic
- Versioned CSV output
- Full provenance manifest (timestamps, URLs, row counts)
- Automated Zenodo DOI publication via GitHub Actions

---

## Data Sources
All sources are public and require no authentication:

| Source | Purpose | URL |
|--------|---------|-----|
| ICS Advisory Project | Clean CISA ICS advisories | https://github.com/icsadvprj/ICS-Advisory-Project |
| CISA KEV | Known exploited vulnerabilities | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| FIRST.org EPSS | Exploit prediction scores | https://api.first.org/data/v1/epss |
| CISA Vulnrichment | CVSS/CWE/SSVC enrichment | https://github.com/cisagov/vulnrichment |
| MITRE ATT&CK for ICS | Technique mapping | https://github.com/mitre-attack/attack-stix-data/tree/master/ics-attack |

---

## Running the Pipeline
To produce the real dataset:

```bash
pip install -r requirements.txt
python src/pipeline.py --full
```
