# ONG‑OT Vulnerability Prioritization Dataset

**Status:** v1.1 DRAFT — the real `--full` run against live sources is done
and verified (27,944 rows, 2026-09-12; see "Dataset at a glance" below and
`docs/VERIFY_CHECKLIST.md`). Still open before publication: the author's own
read of the primary TSA/CPG 2.0 policy PDFs, a Zenodo sandbox test of the
versioning workflow, and a final pre-publish pass (`docs/VERIFY_CHECKLIST.md`
has the complete list). The published, citable release remains **v1.0.0**
(DOI below) until v1.1 passes verification.

**Author:** Friday Ogochukwu Ikwuogu ([ORCID 0009-0009-2222-1318](https://orcid.org/0009-0009-2222-1318)), Independent Researcher, Odessa, Texas, USA
**Collaborators:** Silas Abutu (Petroleum Training Institute, Effurun, Delta State, Nigeria); Abidemi Orimogunje (Redeemer's University, Ede, Osun State, Nigeria) — full CRediT roles in `AUTHORS.json`
**License:** code [MIT](LICENSE), data & docs [CC BY 4.0](LICENSE)

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22503185.svg)](https://doi.org/10.5281/zenodo.22503185)

---

## Overview

The ONG‑OT Vulnerability Prioritization Dataset is a reproducible pipeline
that ingests real-world CVE intelligence from authoritative public sources,
applies domain-specific oil & gas OT rules, and produces a versioned,
provenance-rich dataset for open scientific publication.

This project integrates:

- **CISA ICS Advisories** (ICS Advisory Project mirror)
- **CISA Known Exploited Vulnerabilities (KEV)**
- **FIRST.org EPSS scores**
- **CISA Vulnrichment** (the full CVE record — CNA-submitted data plus CISA's own ADP enrichment)
- **MITRE ATT&CK for ICS** (technique, threat-group, and malware/tool profiles, joined into the dataset for the first time in v1.1 — see "What changed in v1.1")

The pipeline merges these sources on CVE ID and applies three expert-defined
YAML configurations:

- `config/product_class_taxonomy.yaml` — which oil & gas OT product class this row belongs to, and how much weight that carries
- `config/no_patch_rules.yaml` — whether a patch is available, from real vendor remediation text
- `config/compensating_controls_cpg2.yaml` — which CISA CPG 2.0 controls apply, with multiplicative risk-reduction stacking

## What changed in v1.1

v1.0 (published 2026-09-06, DOI above) shipped with three concrete gaps this
version fixes — see `docs/LIMITATIONS.md` and `docs/BUILD_SPEC.md` for the
full detail, and `docs/VERIFY_CHECKLIST.md` for what still needs the
author's sign-off:

1. **No-patch flagging was silently non-functional.** v1.0 matched against
   `Mitigation`/`Remediation` columns that don't exist in the real ICS
   Advisory Project source — so `no_patch_available` was `False` for all
   27,922 published rows. v1.1 matches against real Vulnrichment CNA
   solutions/workarounds text instead.
2. **Product-class taxonomy wasn't oil & gas-specific.** v1.0 mapped 3
   classes (`plc`/`rtu`/`scada`) to 7 generic industrial ICS vendors by bare
   vendor name — any product from Schneider, Rockwell, Siemens, ABB,
   Emerson, Honeywell, or Yokogawa scored the same regardless of product
   line. v1.1 fixes this twice: it adds a genuinely curated oil & gas
   product-family class (`ong_product_line`, weight 0.9: ROC800/FloBoss/
   ControlWave/Totalflow, SCADAPack, ValveLink, Micro Motion, tank gauging,
   custody transfer, etc.); and, per the author's explicit follow-up
   request, re-scopes `plc`/`rtu`/`scada` from bare vendor name down to
   specific process-control platforms those same vendors sell that are
   actually common in oil & gas/refining (Modicon/Foxboro, PlantPAx/
   ControlLogix, SIMATIC/PCS 7, 800xA/Freelance/RTU560, DeltaV/Ovation,
   Experion PKS, CENTUM/ProSafe), raising their weight from 0.5 to 0.6. It
   also adds a narrowly-scoped `electric_adjacent` class (weight 0.3) for
   equipment at ONG/grid interconnection points.
3. **MITRE ATT&CK for ICS was fetched but never joined into the dataset.**
   v1.1 adds `attack_ics_matched_entity` / `_entity_type` / `_technique_ids`
   columns, populated only where a row's Product text is explicitly named in
   a real ATT&CK for ICS group's or software's own description.

v1.1 also adds documentation and reproducibility infrastructure v1.0
shipped without: `AUTHORS.json`, `CITATION.cff`, `LICENSE`, a `docs/` set
(CODEBOOK, LIMITATIONS, VERIFY_CHECKLIST, NEXT_STEPS, BUILD_SPEC), a real
`data/processed/qa_report.txt` and `report/stats.json`, and provenance
logging for every raw fetch (`data/raw/PROVENANCE.txt`).

## Dataset at a glance (v1.1, real `--full` run, 2026-09-12)

Every number below is copied from `report/stats.json`, generated once by
`src/qa.py` from the dataset itself — nothing here is hand-typed. Re-derive
after any new `--full` run rather than editing these by hand.

| Metric | Value |
|--------|-------|
| Total rows (one CVE-advisory pair per row) | 27,944 |
| EPSS score matched | 27,784 (99.43%) |
| In CISA KEV catalog | 360 (1.29%) |
| Vulnrichment CNA remediation text present | 4,170 (14.92%) |
| `no_patch_available = True` | 270 (0.97%) |
| ATT&CK for ICS matched (group/software) | 100 (0.36%) — INCONTROLLER (82 rows) and EKANS (18 rows) only; see `docs/LIMITATIONS.md` item 6 |

Product class distribution: `unmapped` 23,246 · `plc` 4,274 · `rtu` 170 ·
`scada` 158 · `ong_product_line` 96.

For comparison, v1.0 published 27,922 rows — v1.1's 27,944 is within 0.1%,
consistent with normal source growth since v1.0's build date rather than a
taxonomy-driven swing.

## What is here

```
AUTHORS.json                  author block every document/citation reads from
CITATION.cff                  machine-readable citation
LICENSE                       code (MIT) + data/docs (CC BY 4.0)
config/
  product_class_taxonomy.yaml       oil & gas OT product classes + weights
  no_patch_rules.yaml                no-patch determination rules
  compensating_controls_cpg2.yaml    CPG 2.0 control crosswalk
src/
  fetch_ics_advisories.py       CISA ICS advisories (ICS Advisory Project)
  fetch_kev.py                   CISA KEV catalog
  fetch_epss.py                  FIRST.org EPSS scores
  fetch_vulnrichment.py          CISA Vulnrichment (CVSS/SSVC + CNA remediation text)
  fetch_attack_ics.py            MITRE ATT&CK for ICS techniques + group/software profiles
  join.py                        applies the three YAML configs, joins ATT&CK matches
  qa.py                          writes qa_report.txt + stats.json
  pipeline.py                    orchestrates fetch -> save raw + provenance -> join -> write
scripts/
  provenance.py                  appends one line per fetched file to PROVENANCE.txt
  publish_gate.py                 pre-publication scan for draft stamps / secrets
data/
  raw/                           as-fetched inputs + PROVENANCE.txt (+ sample_* demo fixtures)
  processed/                     ong_ot_dataset_<version>.csv (the released dataset) + qa_report.txt
docs/
  BUILD_SPEC.md  CODEBOOK.md  LIMITATIONS.md  VERIFY_CHECKLIST.md  NEXT_STEPS.md
report/
  stats.json                    every number quoted anywhere, computed once
```

## Run it

Requires `git`, `python3`, and outbound access to `github.com`, `cisa.gov`,
`epss.empiricalsecurity.com`, `api.first.org`, and `raw.githubusercontent.com`
for a real `--full` run. No API keys or tokens are needed, or wanted: the
ICS advisories and Vulnrichment fetches both read from
`raw.githubusercontent.com`, a public CDN that isn't subject to the GitHub
API's rate limits and actively rejects an `Authorization` header — see
`src/fetch_vulnrichment.py`'s module docstring for the incident this caused
in an earlier build. Only `src/fetch_ics_advisories.py`'s one directory
listing goes through the real `api.github.com`, which is unauthenticated and
low-volume enough that the default 60/hour limit is never an issue.

```bash
pip install -r requirements.txt

# Real dataset (needs the network access above):
python src/pipeline.py --full --version v1.1

# Or, offline smoke test against bundled fixtures (data/raw/sample_*.csv):
python src/pipeline.py --demo --version v1.1_demo
```

A stranger should be able to run these commands from this README alone and
reproduce `data/processed/ong_ot_dataset_v1.1.csv`, `qa_report.txt`, and
`report/stats.json` (modulo same-day EPSS/KEV drift — see
`docs/LIMITATIONS.md`).

## Data Sources

All sources are public and require no authentication:

| Source | Purpose | URL |
|--------|---------|-----|
| ICS Advisory Project | Clean CISA ICS advisories | https://github.com/icsadvprj/ICS-Advisory-Project |
| CISA KEV | Known exploited vulnerabilities | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| FIRST.org EPSS | Exploit prediction scores | https://api.first.org/data/v1/epss |
| CISA Vulnrichment | Full CVE record: CNA data + CISA ADP enrichment | https://github.com/cisagov/vulnrichment |
| MITRE ATT&CK for ICS | Technique + group/software profiles | https://github.com/mitre-attack/attack-stix-data/tree/master/ics-attack |

Full provenance (file hashes, exact paths, access dates) is written to
`data/raw/PROVENANCE.txt` on every `--full` run.

## Limitations

See `docs/LIMITATIONS.md` before using or citing anything here — in
particular, the CPG 2.0 `reduces_risk_by` risk-reduction values are the
author's own conservative estimate (not CISA-published figures), and the
current TSA Security Directive amendment in force, its exact CAP testing
cadence, and any MSSP-responsibility language are still pending the
author's own read of the primary PDF (item 7).

## Data sources & licensing

The released dataset and documentation are CC BY 4.0. It is derived in part
from the ICS Advisory Project (ODbL v1.0 — attribution and share-alike on
the database itself apply), the CISA KEV/Vulnrichment catalogs (public
domain), FIRST.org EPSS scores (freely redistributable), and MITRE ATT&CK
content (attribution required under the ATT&CK Terms of Use). See `LICENSE`
for the full text.

## Citation

See `CITATION.cff`. DOI: [10.5281/zenodo.22503185](https://doi.org/10.5281/zenodo.22503185) (v1.0.0; a v1.1 version of the same record is pending — see status line above).
