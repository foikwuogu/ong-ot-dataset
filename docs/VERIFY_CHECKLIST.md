# Verification checklist (author completes before any release)

Initial and date each line in your own copy. The publish gate
(`scripts/publish_gate.py`) checks the mechanical items; these are yours.

## Reproduce
- [ ] Run `python src/pipeline.py --full --version v1.1` on a machine with
      normal internet access (the sandbox used to write this pipeline could
      not reach cisa.gov, epss.empiricalsecurity.com, api.first.org, or
      raw.githubusercontent.com — only github.com — so no real `--full` run
      has happened yet; see LIMITATIONS.md item 1). The repository's GitHub
      Actions workflow (`.github/workflows/publish-zenodo.yml`, dispatched
      manually with `publish: false`) is the easiest way to do this without
      needing those hosts reachable from your own machine.
- [ ] Row counts in the resulting `data/processed/qa_report.txt` look
      sane compared to v1.0's published 27,922 rows (some change is
      expected — the source keeps growing and the taxonomy changed — but a
      wildly different number should be investigated before anything else).
- [ ] Every number in any document (README, `.zenodo/description.html`,
      manuscript if one exists) re-derived from `report/stats.json` after
      the `--full` run.

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
- [~] **TSA Security Directives — partially confirmed 2026-09-12, extended
      same day.** The full SD Pipeline-2021-02C PDF (2022-07-27) was read
      end-to-end (author-supplied) and used to confirm OT as "Critical
      Cyber System," written confirmation of receipt, annual CAP
      submission, 2-yearly design review, and — new — that -02C's own
      header states it **expired 2023-07-27** and contains **no MSSP
      language anywhere**. A reliable secondary summary of the original
      SD Pipeline-2021-01 confirmed the Cybersecurity Coordinator
      requirement (must be a U.S. citizen eligible for a security
      clearance — **this corrected a wrong claim** in material the author
      first brought back, which said a NEXUS/Global Entry alternative
      existed; it does not, in any source checked) and the 12-hour
      incident-reporting window. Web research the same day found: the
      30%-annually/100%-over-3-years CAP testing cadence is real, dated to
      **-02D** specifically (secondary source, direct quote); the current
      amendments are most likely **SD Pipeline-2021-02F** (02-series,
      effective 2025-05-03) and **SD Pipeline-2021-01G** (01-series, early
      January 2026) per secondary/compliance-tracking sources — not a
      primary-PDF read, `tsa.gov` still 403s every SD PDF tried, -02C
      included on retest; and no MSSP language turned up in any source
      covering -02D/-02E/-02F/-01G either, three negative checks now.
      **Still needed from you, and now narrower:** (1) confirm whether
      -02F or a further -02G (a file was found but not independently
      dated/confirmed as current) is actually in force — check
      `tsa.gov/sd-and-ea` directly; (2) confirm the 30%/3-year CAP testing
      language reads the same in the current amendment as it did in -02D;
      (3) MSSP language can likely be dropped as "not part of this
      directive series" rather than left as an open verification item,
      once you've glanced at the current amendment's text yourself to be
      sure. See `docs/BUILD_SPEC.md`'s "Policy text" section and
      `docs/LIMITATIONS.md` item 7 for the full citation trail.
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
- [ ] `attack_ics_matched_entity` — spot-check every row this produces on
      the real `--full` output; a distinctive-token match is a heuristic
      (see `src/join.py:apply_attack_ics_match`), not a certified
      attribution.

## Row-level spot checks (minimum 15 units, once `--full` output exists)
- [ ] Five rows you know personally (or the closest oil & gas OT vendor
      products you're familiar with)
- [ ] Five rows with `no_patch_available = True`, checked against the
      CVE's real CVE record on cve.org or nvd.nist.gov
- [ ] Five random rows (record the seed / row indices used)

## Zenodo versioning — before touching the production record
- [ ] Test `.github/workflows/publish-zenodo.yml`'s corrected
      new-version logic against the Zenodo **sandbox** (sandbox.zenodo.org)
      first, not directly against record 22503185 — see
      docs/PUBLISH_GUIDE.md once written.

## Before it goes public
- [ ] README, LIMITATIONS, and `.zenodo/description.html` rewritten in your
      own voice; nothing you cannot defend remains.
- [ ] Draft language/status lines updated once the gate is actually passed.
- [ ] `scripts/publish_gate.py .` passes with no blockers.
- [ ] AUTHORS.json, CITATION.cff, LICENSE all correct — collaborator names,
      ORCID, affiliations spelled exactly as you specified.
- [ ] Evidence log row written the day of release (GitHub tag date, Zenodo
      DOI, IEEE DataPort update date).
