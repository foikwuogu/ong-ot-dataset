# Build Spec — ONG-OT Vulnerability Prioritization Dataset, v1.1

**Status: DRAFT — pipeline changes complete and demo-tested; a `--full` run
against live sources, author verification, and publication are still
pending.**

```
PROJECT:        ONG-OT Vulnerability Prioritization Dataset, v1.1
                Archetype: open dataset, extending a published v1.0
                (Zenodo DOI 10.5281/zenodo.22503185, IEEE DataPort DOI
                10.21227/km25-8h77, GitHub github.com/foikwuogu/ong-ot-dataset)

QUESTION:       For U.S. oil & natural gas OT assets (pipeline, midstream,
                upstream, and electric-adjacent), which publicly disclosed
                vulnerabilities carry the highest real-world exploitation
                risk once ONG-specific product relevance, no-patch status,
                and CPG 2.0 compensating controls are properly weighted —
                and how does each map to CPG 2.0, DOE CESER FY2026-2030,
                EO 14412, and the TSA Pipeline Security Directives?

SOURCES:
  1. ICS Advisory Project (CISA ICS advisories) —
     github.com/icsadvprj/ICS-Advisory-Project, ODbL v1.0, refreshed to
     build date via `src/fetch_ics_advisories.py`.
  2. CISA KEV catalog — cisa.gov feed, public domain, refreshed to build
     date via `src/fetch_kev.py`.
  3. FIRST.org EPSS — api.first.org / epss.empiricalsecurity.com, refreshed
     to build date via `src/fetch_epss.py`.
  4. CISA Vulnrichment (full CVE record: CNA + ADP containers) —
     github.com/cisagov/vulnrichment, refreshed to build date via
     `src/fetch_vulnrichment.py`. v1.1 reads `containers.cna.solutions` /
     `.workarounds` in addition to v1.0's `containers.adp` (CVSS/SSVC) —
     see CODEBOOK.md and no_patch_rules.yaml.
  5. MITRE ATT&CK for ICS (STIX bundle) —
     github.com/mitre-attack/attack-stix-data. v1.0 fetched this but never
     joined it into the dataset. v1.1 fetches technique, intrusion-set, and
     malware/tool objects plus their `uses` relationships
     (`src/fetch_attack_ics.py`) and tags a row only where its Product text
     contains a distinctive token from a named group's or software's own
     STIX description (`src/join.py:apply_attack_ics_match`) — auditable,
     row-by-row, never a bulk/class-level inference.
  6. Policy text (read/cited, not row data): CISA CPG 2.0 (Dec 2025), DOE
     CESER Strategic Plan FY2026-2030, EO 14412, TSA SD
     Pipeline-2021-01G/-02F.
     NOTE: the primary CPG 2.0 and TSA SD PDFs return HTTP 403 to automated
     fetch from every build environment tried so far. The CPG goal IDs used
     in `config/compensating_controls_cpg2.yaml` are reconstructed from
     CISA's own CPG web pages and third-party summaries, cross-checked
     against each other — NOT read directly from the primary PDF.
     **[VERIFY]** re-read the primary document yourself before publication.

UNIT:           One row = one (CVE, CISA ICS Advisory) pair. Same grain as
                v1.0. No hard oil-and-gas filter — the full ICS advisory
                universe is kept, with ONG relevance expressed through
                `ong_product_class` / `ong_product_weight` rather than
                row exclusion (this was v1.0's design and v1.1 keeps it).

MEASURES (new or materially changed vs. v1.0 — full definitions in
CODEBOOK.md):
  - ong_product_class / ong_product_weight — rebuilt taxonomy: a genuinely
    oil & gas-specific `ong_product_line` class (curated vendor/product
    family allowlist, weight 0.9); `plc`/`rtu`/`scada` re-scoped, per the
    author's explicit follow-up request, from bare vendor name (v1.0 — any
    Schneider/Rockwell/Siemens/ABB/Emerson/Honeywell/Yokogawa product
    regardless of line) down to specific process-control platforms those
    vendors sell that are actually common in oil & gas/refining (Modicon/
    Foxboro, PlantPAx/ControlLogix, SIMATIC/PCS 7, 800xA/Freelance/RTU560,
    DeltaV/Ovation, Experion PKS, CENTUM/ProSafe), weight raised from 0.5 to
    0.6 to reflect that tighter scope while staying below `ong_product_line`
    (these platforms are still shared with other process industries, not
    oil & gas-exclusive); and a new, narrowly-scoped `electric_adjacent`
    class (weight 0.3) for equipment at ONG/grid interconnection points
    specifically — **[VERIFY]** every allowlist and weight against your own
    field knowledge.
  - no_patch_available / no_patch_basis — v1.0's trigger checked a
    `Mitigation`/`Remediation` column that does not exist in the real ICS
    Advisory Project source (confirmed against the source's actual CSV
    header), so it silently never fired on real `--full` output. v1.1
    matches against real Vulnrichment CNA solutions/workarounds text, with
    a separate `no_patch_basis` column so "we don't have remediation text
    for this CVE" is never silently folded into "patched" —
    **[VERIFY]** the phrase list.
  - attack_ics_matched_entity / _entity_type / _technique_ids (new) — see
    Source 5 above.
  - cpg2_applicable_controls / cpg2_combined_risk_reduction — expanded
    control set covering every class in the v1.1 taxonomy —
    **[VERIFY]** against the primary CPG 2.0 PDF.

OUTPUTS:
  - data/processed/ong_ot_dataset_v1.1.csv + _manifest.json
  - data/processed/qa_report.txt (new in v1.1 — v1.0 shipped none)
  - report/stats.json (new in v1.1)
  - data/raw/*_v1.1.csv + PROVENANCE.txt (new in v1.1 — v1.0's `--full` run
    never saved its raw fetches or logged their provenance)
  - docs/CODEBOOK.md, LIMITATIONS.md, VERIFY_CHECKLIST.md, NEXT_STEPS.md,
    BUILD_SPEC.md (all new in v1.1)
  - AUTHORS.json, CITATION.cff, LICENSE (all new in v1.1)
  - Updated README.md and .zenodo/description.html

VENUES:         GitHub (foikwuogu/ong-ot-dataset, tagged release v1.1) ->
                Zenodo (new version of the existing record, DOI
                10.5281/zenodo.22503185, via the corrected
                .github/workflows/publish-zenodo.yml) -> IEEE DataPort
                (updated listing, DOI 10.21227/km25-8h77 — no API exists
                for this platform; see docs/PUBLISH_GUIDE.md once written).

VERIFY POINTS (the author must personally rule on these before the gate
passes — see VERIFY_CHECKLIST.md):
  1. Oil & gas / electric-adjacent product taxonomy and every weight.
  2. no_patch_available phrase list, and what "no remediation text
     captured" should mean for rows where it's common.
  3. CPG 2.0 goal IDs and control mappings, against the primary PDF.
  4. ATT&CK for ICS technique-family matches — spot-check named rows.
  5. A real `--full` run has not yet been executed anywhere network access
     allows it (see LIMITATIONS.md, "sandbox network constraints") — the
     numbers above are demo-fixture numbers for logic verification only,
     not real dataset statistics. The QA report and stats.json from an
     actual `--full` run must be reviewed before anything is cited.

LICENSE:        Code: MIT. Data + docs: CC BY 4.0, attribution passed
                through to ICS Advisory Project (ODbL v1.0) and
                CISA/FIRST.org/MITRE per their own terms.

ASSUMPTIONS (proceeding without further confirmation unless flagged
otherwise):
  - Refresh all source pulls to a current snapshot at `--full` run time
    rather than reusing v1.0's 2026-09-06 snapshot (confirmed by the
    author).
  - Author block and collaborators per AUTHORS.json (confirmed by the
    author).
  - Same three venues as v1.0 (GitHub / Zenodo / IEEE DataPort), new
    versions of each rather than new records (confirmed by the author).
  - electric_adjacent scoped narrowly to interconnection-point equipment
    only, not the broader "any vendor serving both sectors" option
    (confirmed by the author).
  - The dead no_patch vendor_status/cve_status triggers are removed and
    documented, not kept as no-ops (author's default; flagged as still
    open — see VERIFY_CHECKLIST.md).
```
