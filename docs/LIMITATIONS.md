# Limitations — ONG-OT Vulnerability Prioritization Dataset, v1.1

**Status: DRAFT — unverified.** Written before any discussion section, per
this project's build standard, so nothing downstream can outrun what is
honestly known about the data.

1. **No real `--full` run has been executed yet for v1.1.** The build
   environment used to write and test this pipeline has outbound network
   access to `github.com`/`api.github.com` only — `cisa.gov`,
   `epss.empiricalsecurity.com`, `api.first.org`, and
   `raw.githubusercontent.com` are all blocked by that environment's egress
   policy. Every number produced so far comes from a small, hand-built demo
   fixture (`data/raw/sample_*.csv`) used to verify the *logic* (does each
   config rule fire the way it's meant to), not the real dataset. A real
   `--full` run — via the repository's own GitHub Actions workflow, which
   runs on unrestricted infrastructure — is required before any row count,
   match rate, or distribution can be cited. **[VERIFY]** run it and replace
   every number in this document set with the real output before
   publication.

2. **v1.0's `no_patch_available` never actually fired on real data.**
   `config/no_patch_rules.yaml` (v1.0) matched against `Mitigation` /
   `Remediation` columns; the real ICS Advisory Project CSV has no such
   columns (confirmed against the source's actual header — those names only
   ever existed in v1.0's own hand-made demo fixture). This means the
   published v1.0.0 dataset's `no_patch_available` column is `False` for
   every one of its 27,922 rows, despite the README describing "no-patch
   flagging based on advisory text and vendor status" as a working feature.
   v1.1 replaces this with real Vulnrichment CNA solutions/workarounds text
   (see CODEBOOK.md) — a working signal, but a partial one: many CVE
   records simply have no solutions/workarounds field, which v1.1 records
   honestly as `no_patch_basis = "no_remediation_text_captured"` rather than
   assuming a patch exists. **[VERIFY]** the phrase list and what share of
   rows land in that "no signal" bucket once real data comes back.

3. **v1.0's `product_class_taxonomy.yaml` was not oil & gas-specific.** It
   mapped only 3 classes to 7 generic industrial ICS vendors (Schneider,
   Rockwell, Siemens, ABB, Emerson, Honeywell, Yokogawa) — vendors that sell
   into every ICS sector, not oil & gas specifically — so nearly all of
   v1.0's 27,922 rows fell to `unmapped_default_weight: 0.0`. v1.1 adds a
   genuinely oil & gas-specific `ong_product_line` class (curated
   vendor/product-family allowlist: ROC800/FloBoss/ControlWave/Totalflow,
   SCADAPack/RemoteConnect, ValveLink, Micro Motion, gas chromatographs,
   tank-gauging systems, etc.) at the highest weight. **This is a curated
   judgment call, not a fetched fact — [VERIFY] the allowlist against your
   own field knowledge before this dataset is cited or published.**

4. **The new `electric_adjacent` class is deliberately narrow and may match
   zero or very few rows in a given build.** Per the author's scoping
   decision, it requires BOTH a curated protection-relay/interconnection
   product match AND a context keyword (interconnection, substation,
   compressor station, etc.) in the same row — a real signal is rare in
   public advisory text at this level of specificity. A low or zero match
   count is the expected result of the narrow scope, not a pipeline defect.
   **[VERIFY]** the product allowlist and the boundary itself against your
   own field knowledge.

5. **CVSS is advisory-level, not per-CVE.** `Cumulative_CVSS` is the
   worst/aggregate score CISA published for the whole advisory; when one
   advisory lists several CVEs, every exploded row for that advisory
   carries the same value even if the underlying CVEs differ in severity
   (unchanged from v1.0; NVD per-CVE CVSS enrichment remains a candidate for
   a future version — see NEXT_STEPS.md).

6. **ATT&CK for ICS matches will be rare.** `attack_ics_matched_entity`
   only fires when a row's Product text contains a distinctive token that
   also appears in a named ATT&CK for ICS group's or software's own STIX
   description (e.g. TRITON's description names "Triconex" explicitly).
   Most rows will be blank. This reflects the real, narrow overlap between
   publicly documented ICS threat-actor profiles and the ONG OT product
   landscape — it is not a join failure. (An earlier version of this
   matching function used the bare vendor name as well, which produced
   false positives — e.g. tagging every Schneider Electric row, including
   unrelated Modicon PLCs, with TRITON, which actually targeted only
   Schneider's separate Triconex safety-controller line. Caught and fixed
   during `--demo` testing; see `src/join.py:apply_attack_ics_match`.)
   **[VERIFY]** spot-check every row this produces once real data comes
   back — a distinctive-token match is still a heuristic, not a certainty.

7. **Two of the four primary policy documents could not be automatically
   retrieved.** The CISA CPG 2.0 PDF and the TSA Security Directive
   Pipeline-2021-01G PDF both return HTTP 403 to automated fetch (likely
   bot-protection on cisa.gov/tsa.gov, not a redistribution restriction, and
   the same issue v1.0's build notes hit). The CPG 2.0 goal IDs used in
   `config/compensating_controls_cpg2.yaml` are reconstructed from CISA's
   own CPG web pages and third-party summaries, cross-checked against one
   another, NOT read from the primary PDF. **[VERIFY]** re-read the primary
   document directly before publication and correct anything this
   reconstruction got wrong.

8. **Single point-in-time pull, once `--full` is run.** EPSS scores, KEV
   membership, and Vulnrichment enrichment all change over time. Every value
   in a given release reflects that run's pull (recorded in
   `report/stats.json` and `data/raw/PROVENANCE.txt`); re-running the
   pipeline on a later date will produce different values for the same
   CVEs — expected drift, not an inconsistency.

9. **Licensing of the upstream ICS Advisory Project data (ODbL v1.0)**
   requires attribution and, for produced works built from the database,
   share-alike terms for the database itself. See `LICENSE`; this has not
   been independently reviewed by a lawyer.

10. **The Zenodo publish workflow was fixed but not yet exercised
    end-to-end.** `.github/workflows/publish-zenodo.yml` previously created
    a brand-new deposition on every run, which would have minted an
    unrelated second DOI for v1.1 instead of a new version of
    10.5281/zenodo.22503185. It now calls the Zenodo "new version" action
    first. **[VERIFY]** this against a Zenodo sandbox deposition before
    running it against the production record — see docs/VERIFY_CHECKLIST.md.
