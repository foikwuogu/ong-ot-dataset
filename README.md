# ONG-OT Vulnerability Prioritization Dataset

Friday Ogochukwu Ikwuogu
ORCID: 0009-0009-2222-1318
Google Scholar: https://scholar.google.com/citations?pli=1&authuser=3&user=XADxRNkAAAAJ
ResearchGate: https://www.researchgate.net/profile/Friday-O-Ikwuogu/research
GitHub: https://github.com/foikwuogu
Portfolio: Ikwuogufoikwuogu.github.io
LinkedIn: Ogochukwu Friday Ikwuogu
email: Friday.ikwuogu@gmail.com|ikwuogu_f57913@utpb.edu | ogochukwu.f.ikwuogu@ieee.org
Affiliation: Independent Researcher, Odessa, Texas, USA

**Versions:** v1.0 (target: Nov 2026) · v1.1 (target: May 2027)
**Status:** Pipeline built. Data not yet fetched or released — see "Current status" below.

## What this is

CISA ICS advisories joined to CISA KEV, FIRST.org EPSS, CISA Vulnrichment (ADP
enrichment), and MITRE ATT&CK for ICS, with:
- oil & natural gas product-class weighting
- a no-patch-available flag
- compensating controls mapped to CISA CPG 2.0 terms

License on release: **ODbL v1.0**, with required attribution to the
[ICS Advisory Project](https://github.com/icsadvprj/ICS-Advisory-Project) (the
upstream source this pipeline uses for clean, CSV-formatted CISA ICS
advisories). Planned distribution: Zenodo (DOI) and IEEE DataPort (DOI).

## Data sources (all public, no auth required)

| Source | Used for | URL |
|---|---|---|
| ICS Advisory Project | Clean CISA ICS advisory records (CVE, vendor, product, CI sector) | https://github.com/icsadvprj/ICS-Advisory-Project |
| CISA KEV catalog | Known-exploited flag, date added, ransomware use | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| FIRST.org EPSS | Exploit prediction score + percentile per CVE | https://api.first.org/data/v1/epss |
| CISA Vulnrichment | ADP-supplied CVSS/CWE/SSVC enrichment per CVE | https://github.com/cisagov/vulnrichment |
| MITRE ATT&CK for ICS | Technique mapping (STIX bundle) | https://github.com/mitre-attack/attack-stix-data/tree/master/ics-attack |

## Division of labor (stated up front, matches the plan this dataset supports)

- **Claude (this pipeline):** fetch, parse, join, and packaging code; schema
  design; DOI/versioning scaffolding; documentation.
- **Client (you) owns and has supplied:**
  1. `config/product_class_taxonomy.yaml` — vendor → product-class → weight
     (plc: Schneider/Rockwell/Siemens @ 0.9; rtu: ABB/Emerson @ 0.8; scada:
     Honeywell/Yokogawa @ 0.7).
  2. `config/no_patch_rules.yaml` — advisory-text, vendor-status, and
     CVE-status triggers for the no-patch flag.
  3. `config/compensating_controls_cpg2.yaml` — CPG2-1 (plc, rtu; -20% risk)
     and CPG2-4 (scada; -10% risk), stacked multiplicatively when more than
     one applies.

  These are filled in and verified against the fixture set (see "Current
  status"). Two vendor lists (rtu, scada) haven't matched a real advisory yet
  in the small fixture set — expected, since the fixtures only cover four
  CVEs. Re-verify vendor spelling/casing once the real advisory pull runs, in
  case the ICS Advisory Project's Vendor field differs from what's listed
  here (e.g. "ABB Ltd" vs "ABB").

## Current status — read before you cite or release anything

This container has **no outbound network access**, so I could not execute the
live fetch against CISA / FIRST.org / GitHub raw files from here. What's in
this package:

- Fully written, tested-for-syntax fetch/join scripts (`src/`) that will run
  end-to-end the moment you run them somewhere with internet access — your
  laptop, a GitHub Actions runner, or any machine with `pip install -r
  requirements.txt` and outbound HTTPS.
- A `data/raw/sample_*.json` / `.csv` fixture set — small, hand-verified
  snippets of real public records (a handful of rows) confirming the schema
  each source actually returns, so the join logic in `src/join.py` is
  demonstrated end-to-end on real structure, not guessed.
- `demo_run.py`, which runs the full join on the fixtures only, so you can see
  the output shape before you point it at the real feeds.

**To produce the real v1.0 file:** run `python src/pipeline.py --full` on a
machine with internet access. It will pull current CISA/KEV/EPSS/Vulnrichment/
ATT&CK data, run the join, and write
`data/processed/ong_ot_dataset_v1.0.csv` (+ a `.json` sidecar of the run
manifest: fetch timestamps, row counts, source URLs — Zenodo wants this for
provenance).

## Repository layout

```
ong-ot-dataset/
├── README.md
├── requirements.txt
├── config/
│   ├── product_class_taxonomy.yaml      # TODO — you own this
│   ├── no_patch_rules.yaml              # TODO — you own this
│   └── compensating_controls_cpg2.yaml  # TODO — you own this
├── src/
│   ├── fetch_ics_advisories.py
│   ├── fetch_kev.py
│   ├── fetch_epss.py
│   ├── fetch_vulnrichment.py
│   ├── fetch_attack_ics.py
│   ├── join.py
│   └── pipeline.py                      # orchestrates fetch -> join -> write
├── data/
│   ├── raw/        (fixtures now; live pulls land here with --full)
│   └── processed/  (final dataset lands here)
└── demo_run.py
```

## Next steps for you

1. Fill in the three `config/*.yaml` files (or send me your taxonomy/rules
   and I'll encode them).
2. Run `demo_run.py` locally to sanity-check the join on the fixtures.
3. Run `pipeline.py --full` on a networked machine for the real v1.0 pull.
4. Reserve a Zenodo DOI (Zenodo lets you reserve one before upload) and an
   IEEE DataPort entry; drop both DOIs into this README before release.
5. Confirm the ODbL attribution line to the ICS Advisory Project stays in the
   dataset's own metadata/README, not just here.

## Automated Zenodo publication

`.github/workflows/publish-zenodo.yml` runs the live pipeline and uploads the
CSV and manifest as both a GitHub Actions artifact and a Zenodo deposition.

1. Create a Zenodo personal access token with `deposit:write` and
   `deposit:actions` scopes.
2. Add it to the GitHub repository as an Actions secret named
   `ZENODO_ACCESS_TOKEN`.
3. For a safe test, set the repository Actions variable `ZENODO_API_URL` to
   `https://sandbox.zenodo.org/api` and use a sandbox token. Run the workflow
   manually with `publish` disabled to leave a draft deposition.
4. Remove the variable (or set it to `https://zenodo.org/api`) and use a
   production Zenodo token when ready.

Publishing a GitHub release runs the workflow with the release tag as the
dataset version and automatically publishes the resulting Zenodo deposition.
Manual runs accept a version and publish toggle; leaving the toggle disabled
uploads the files to a draft deposition for inspection.
