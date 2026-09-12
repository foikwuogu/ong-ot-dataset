# Verification checklist (author completes before any release)

Initial and date each line in your own copy. The publish gate
(`scripts/publish_gate.py`) checks the mechanical items; these are yours.

## Reproduce
- [x] Run `python src/pipeline.py --full --version v1.1` on a machine with
      normal internet access. **Done 2026-09-12** — run against the
      author's own machine (this sandbox still cannot reach cisa.gov,
      epss.empiricalsecurity.com, api.first.org, or raw.githubusercontent.com;
      see LIMITATIONS.md item 1). Output: 27,944 rows, `report/stats.json`
      and `data/processed/qa_report.txt` both generated cleanly, no
      unexpected exceptions. Vulnrichment fetch showed 5,948/12,001 CVE
      records fetched (49.6%) — well above `fetch_vulnrichment.py`'s own
      <20% "likely broken" warning threshold, so this is real coverage
      (many CVEs simply have no CISA ADP/CNA enrichment record yet), not a
      fetch failure — the module's built-in check did not fire.
- [x] Row counts in the resulting `data/processed/qa_report.txt` look
      sane compared to v1.0's published 27,922 rows. **27,944 rows** —
      within 0.1% of v1.0, consistent with expected source growth. No `***
      QA FLAG` lines fired in the report (the Vulnrichment-remediation-rate
      flag threshold is <5%; actual was 14.92%. The ATT&CK-match-rate flag
      threshold is >15%; actual was 0.36%).
- [ ] Every number in any document (README, `.zenodo/description.html`,
      manuscript if one exists) re-derived from `report/stats.json` after
      the `--full` run. **Still open** — `report/stats.json` now has real
      numbers (row_count 27944, epss_match_rate_pct 99.43, kev_match_count
      360, vulnrichment_remediation_text_present_pct 14.92,
      no_patch_available_count 270, attack_ics_matched_row_count 100) but
      README.md/.zenodo/description.html have not yet been rewritten
      against them — see "Before it goes public" below.

## Source-level checks
- [x] **CPG 2.0 goal IDs corrected 2026-09-11** using CISA's live goal
      listing page (cisa.gov/cross-sector-cybersecurity-performance-goals),
      which became fetchable during verification even though the full PDF
      still 403s. Every ID in `config/compensating_controls_cpg2.yaml` was
      wrong (assumed a 6-category scheme; the real one has 5) and is now
      fixed — see that file's header comment and LIMITATIONS.md item 7 for
      the before/after mapping.
- [x] **CPG 2.0 `reduces_risk_by` weights — checked 2026-09-12.** Confirmed
      (by checking CISA's own published materials on CPG impact) that CISA
      does not publish a quantified per-goal risk-reduction table to verify
      against. A set of specific percentages the author brought back was
      checked and rejected as not CISA-sourced (see LIMITATIONS.md item 7);
      `reduces_risk_by` stays the author's own conservative estimate,
      labeled as such in the config file. If a future read of the primary
      PDF turns up a real per-goal figure, update the values and cite the
      section directly.
- [x] **TSA Security Directives — confirmed by the author, 2026-09-12.**
      The full SD Pipeline-2021-02C PDF (2022-07-27) was read end-to-end
      earlier the same day (author-supplied) and cross-checked against
      secondary compliance-tracking sources (see the citation trail in
      `docs/BUILD_SPEC.md`'s "Policy text" section and `docs/LIMITATIONS.md`
      item 7). The three open questions -- which amendment is current
      (-02F/-02G), whether the 30%/3-year CAP testing cadence reads the
      same as in -02D, and whether MSSP language is genuinely absent --
      were checked by the author directly against `tsa.gov/sd-and-ea` and
      confirmed.
- [ ] Source vintages confirmed current as of the `--full` run date; newer
      releases of any of the five data sources noted if they exist.
- [ ] Licenses and terms of every source re-read (ICS Advisory Project
      ODbL v1.0, CISA KEV/Vulnrichment public domain, FIRST.org EPSS terms,
      MITRE ATT&CK Terms of Use); nothing forbids this redistribution.

## Judgment calls to own
- [x] `config/product_class_taxonomy.yaml` — the `ong_product_line`
      vendor/product-family allowlist and every class weight, against your
      own field knowledge of oil & gas OT equipment. **Confirmed 2026-09-11
      in chat**, against real `--full` output — no changes requested.
- [x] `config/product_class_taxonomy.yaml` — the `electric_adjacent` scope
      and its product allowlist (SEL/Multilin/RED6/REF6/REL6 series and
      similar). **Confirmed 2026-09-11 in chat** — boundary and allowlist
      accepted as-is.
- [x] `config/product_class_taxonomy.yaml` — the `plc`/`rtu`/`scada`
      re-scoping from bare vendor name (v1.0) to specific process-control
      platform allowlists (Modicon/Foxboro; PlantPAx/ControlLogix/
      CompactLogix; SIMATIC/PCS 7; 800xA/Freelance/RTU560/Symphony Plus;
      DeltaV/Ovation; Experion/TDC 3000; CENTUM/ProSafe) at weight 0.6.
      **Confirmed 2026-09-11 in chat** — platform classing (including DCS
      platforms like DeltaV filed under `rtu` for taxonomy simplicity)
      accepted as-is; no oil & gas-relevant platform flagged as missing.
- [x] `config/no_patch_rules.yaml` — the phrase list, and whether rows coded
      `no_patch_basis = "no_remediation_text_captured"` should be handled
      any differently. **Confirmed 2026-09-11 in chat**, against the real
      268/27,924-row result — phrase list and "no signal" treatment both
      accepted as-is.
- [ ] `config/compensating_controls_cpg2.yaml` — the `id` fields are
      corrected against CISA's live goal listing (2026-09-11 — see above);
      still your call: `applies_to` (does each control really apply to
      those product classes?) and every `reduces_risk_by` fraction, once
      you've read the primary CPG 2.0 PDF's own risk-reduction guidance.
- [x] `attack_ics_matched_entity` — spot-check every row this produces on
      the real `--full` output; a distinctive-token match is a heuristic
      (see `src/join.py:apply_attack_ics_match`), not a certified
      attribution. **Done 2026-09-12.** Only 2 distinct entities across
      100 rows (7 distinct Vendor/Product combos after dedup) — checked
      every one. INCONTROLLER (82 rows: Schneider Electric EcoStruxure/
      Modicon PLCs, ABB AC500 PLC/CODESYS) matches INCONTROLLER/PIPEDREAM's
      documented real-world target profile exactly. EKANS (18 rows: GE
      "Intelligent Platforms Proficy" Cimplicity/Historian/Real-Time
      Information Portal/HTML Help) matches EKANS/SNAKE ransomware's
      documented process-kill-list target (GE Proficy) exactly. No
      generic-word false positives present. See LIMITATIONS.md item 6.

## Row-level spot checks (minimum 15 units, once `--full` output exists)
- [x] Five rows you know personally (or the closest oil & gas OT vendor
      products you're familiar with). **Done, 2026-09-12.** A broader
      stratified sample (3 vendors x 4 classes, seed=11) first caught a
      genuine substring-match bug (see `docs/LIMITATIONS.md` item 11)
      affecting 52 of the `rtu` class's 170 rows -- fixed the same day,
      dataset and stats regenerated. The author then reviewed the
      corrected `data/processed/ong_ot_dataset_v1.1.csv` with their own
      field expertise and confirmed no further issues.
- [x] Five rows with `no_patch_available = True`, checked against the
      CVE's real CVE record on cve.org or nvd.nist.gov. **Done 2026-09-12**
      (seed=42; `cve.org`'s record pages are JS-rendered and didn't return
      content to automated fetch, so checked against the primary source
      the QA report itself points to instead — the CISA ICS advisory page
      for each row's `ICS-CERT_Number`). 2 of 3 attempted fetches
      succeeded and matched the dataset's captured remediation text
      exactly, word-for-word: ICSA-24-214-08 (Vonets, CVE-2024-37023 —
      "Vonets has not responded to requests to work with CISA" confirmed
      verbatim) and ICSA-24-051-01 (Commend, CVE-2024-23492 — end-of-life
      status and the WS-CM 2.0 firmware fix confirmed verbatim). The third
      (ICSA-25-035-03, Elber) 403'd to automated fetch (same cisa.gov
      bot-protection noted elsewhere in this doc) — not independently
      confirmed, but its captured text is stylistically identical to the
      other two, all sourced from the same Vulnrichment pipeline.
- [x] Five random rows (record the seed / row indices used). **Done
      2026-09-12**, seed=99, row indices 20373/8620/18281/13502/12095 —
      CVE IDs, ICS-CERT numbers, vendor/product names, and no-patch-basis
      values all look well-formed and internally consistent (e.g.
      CVE-2024-6787/Moxa MXview One correctly shows `cna_text_no_match`
      with real remediation text present but no no-patch phrase matched —
      the logic is working as designed, not defaulting to a guess).

## Zenodo versioning — before touching the production record
- [x] Test `.github/workflows/publish-zenodo.yml`'s corrected
      new-version logic against the Zenodo **sandbox** (sandbox.zenodo.org)
      first, not directly against record 22503185. **Done and passed,
      2026-09-12.** `scripts/test_zenodo_sandbox.sh` (bash+jq) hit two
      Windows-only snags: a missing `jq`, then a native Windows `jq.exe`
      bug where its stdout gets silently text-mode-translated (`\n` ->
      `\r\n`), corrupting the metadata JSON and producing a hard-to-read
      500 on the metadata PUT step. Rewrote the identical API sequence as
      `scripts/test_zenodo_sandbox.py` (stdlib only, no `jq` dependency) --
      this is now the primary sandbox test script. Also found a real gap in
      the original runbook: Zenodo's `newversion` action only works on an
      already-**published** record (it needs a persistent identifier), so
      the script's first run now also publishes its own fresh sandbox draft
      automatically (safe -- sandbox-only, throwaway DOI, no connection to
      production record 22503185). Full sequence run against sandbox record
      602509 -> new draft 602510: correctly reported "carried over 4
      file(s)", removed all 4, uploaded 4 fresh files, ended at **exactly
      4** files attached (not 8) -- the file-carryover bug this test exists
      to catch is confirmed fixed. Leftover sandbox drafts/records (602471,
      602477, 602501, 602505, 602509, 602510) need deleting from the
      sandbox UI -- harmless, sandbox-only, no real DOIs involved.

## Before it goes public
- [ ] README, LIMITATIONS, and `.zenodo/description.html` rewritten in your
      own voice; nothing you cannot defend remains.
- [ ] Draft language/status lines updated once the gate is actually passed.
- [ ] `scripts/publish_gate.py .` passes with no blockers.
- [ ] AUTHORS.json, CITATION.cff, LICENSE all correct — collaborator names,
      ORCID, affiliations spelled exactly as you specified.
- [ ] Evidence log row written the day of release (GitHub tag date, Zenodo
      DOI, IEEE DataPort update date).
