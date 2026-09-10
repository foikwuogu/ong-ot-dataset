# Codebook — `data/processed/ong_ot_dataset_v1.1.csv`

**Status: DRAFT — unverified.** One row = one (CVE, CISA ICS advisory) pair
from the full ICS advisory universe (no hard oil & gas filter — relevance is
expressed through `ong_product_class` / `ong_product_weight`).

## From the ICS Advisory Project (unchanged join, real source columns)

| Column | Type | Definition |
|---|---|---|
| `cve_id` | string | One CVE per row; advisories listing multiple CVEs are exploded so each CVE gets its own row (`src/fetch_ics_advisories.py`). |
| `ICS-CERT_Number` | string | CISA's advisory identifier (e.g. `ICSA-22-221-02`). Look it up at `cisa.gov/news-events/ics-advisories/<id>` for the primary source. |
| `ICS-CERT_Advisory_Title` | string | As published. |
| `Vendor`, `Product`, `Products_Affected` | string | As published. |
| `Cumulative_CVSS` | float [0,10] or blank | The ICS Advisory Project's own cumulative/worst CVSS v3 base score for the *advisory* (not per-CVE — see LIMITATIONS.md). |
| `CVSS_Severity` | string | CISA's own Low/Medium/High/Critical label. |
| `Critical_Infrastructure_Sector` | string | CISA's own sector tag(s), verbatim. |

Note: the real ICS Advisory Project CSV has **no** `Mitigation` or
`Remediation` column (confirmed against the source's actual header) — v1.0's
demo fixture invented those two column names for its own hand-made test
data, which is why v1.0's `no_patch_available` logic silently never fired on
real `--full` output. v1.1's demo fixture uses the real column set.

## From CISA KEV (`src/fetch_kev.py`)

| Column | Type | Definition |
|---|---|---|
| `known_exploited` | boolean | `True` if this CVE appears in the CISA KEV catalog as of build time. |

## From FIRST.org EPSS (`src/fetch_epss.py`)

| Column | Type | Definition |
|---|---|---|
| `epss` | float [0,1] or blank | Estimated 30-day probability of exploitation. Blank = not in the EPSS scored set at build time. |
| `percentile` | float [0,1] or blank | Percentile rank among all EPSS-scored CVEs, same model run. |

## From CISA Vulnrichment (`src/fetch_vulnrichment.py`) — v1.1 reads more of the record than v1.0

| Column | Type | Definition |
|---|---|---|
| `vulnrichment_cvss` | float or blank | CISA ADP's own CVSS v3.1 base score, when supplied (unchanged from v1.0). |
| `vulnrichment_ssvc` | string or blank | CISA ADP's SSVC decision-point options (unchanged from v1.0). |
| `vulnrichment_cna_solutions` | string | **New in v1.1.** The CVE record's `containers.cna.solutions` text (the CNA/vendor's own published remediation), when supplied. |
| `vulnrichment_cna_workarounds` | string | **New in v1.1.** `containers.cna.workarounds` text, when supplied. |
| `vulnrichment_remediation_text` | string | **New in v1.1.** The two fields above, concatenated — what `no_patch_rules.yaml` actually matches against. |
| `vulnrichment_remediation_text_present` | boolean | **New in v1.1.** Whether Vulnrichment supplied any solutions/workarounds text at all for this CVE. Real coverage is partial — many CVE records carry neither field (confirmed by spot-checking; see LIMITATIONS.md) — so this stays a visible column rather than being silently treated as "no patch." |

## Derived (`config/*.yaml` + `src/join.py`)

| Column | Type | Definition |
|---|---|---|
| `ong_product_class` | string | `ong_product_line`, `plc`, `rtu`, `scada`, `electric_adjacent`, or `unmapped` — see `config/product_class_taxonomy.yaml` for the exact matching rule per class and **[VERIFY]** the allowlist. |
| `ong_product_weight` | float [0, 0.9] | The class's configured weight; `0.0` for unmapped. |
| `no_patch_available` | boolean | `True` if any configured phrase matched `vulnrichment_remediation_text`. See `config/no_patch_rules.yaml`. |
| `no_patch_basis` | string | `cna_text_match:<phrase>`, `cna_text_no_match`, or `no_remediation_text_captured` — always shows *why* the flag landed where it did, so "we have no signal" is never confused with "confirmed patched." |
| `cpg2_applicable_controls` | string | Comma-joined CPG 2.0 control IDs applicable to this row's `ong_product_class`, or `"unmapped — needs review"`. See `config/compensating_controls_cpg2.yaml` and **[VERIFY]** every goal ID against the primary CPG 2.0 PDF. |
| `cpg2_combined_risk_reduction` | float [0,1] | Combined multiplicative risk reduction across every matched control. |
| `attack_ics_matched_entity` | string | Name of an ATT&CK for ICS group or software whose own STIX description contains a distinctive token from this row's `Product` field, or blank. Expected to be a narrow, mostly-blank overlap — but the first real `--full` run matched 31% of rows, including non-ICS-specific entities (FIN7, REvil, Conficker); **[VERIFY]** — see LIMITATIONS.md item 6. See `src/join.py:apply_attack_ics_match`. |
| `attack_ics_entity_type` | string | `group` or `software`, when matched. |
| `attack_ics_technique_ids` | string | Comma-joined ATT&CK technique IDs that matched entity `uses`, when matched. |
| `attack_ics_matched_token` | string | New in this fix: the exact distinctive token (from `Product`) found in the matched entity's description — added so a QA reviewer can see *why* a match fired, not just *that* it fired, without re-running any code. |

## Reproducing a row

Every row can be traced back to a specific CISA advisory (`ICS-CERT_Number`)
and a specific EPSS/KEV/Vulnrichment/ATT&CK pull (dated in
`data/raw/PROVENANCE.txt` and `report/stats.json`). To re-derive any
derived column by hand, read the corresponding function in `src/join.py` —
nothing in this dataset is asserted without a function that computes it from
the columns to its left.
