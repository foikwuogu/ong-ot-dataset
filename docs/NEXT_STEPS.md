# Next steps — what v1.2 / v2 could add

v1.1 fixes v1.0's dormant no-patch logic, adds a real oil & gas-specific
product taxonomy, joins ATT&CK for ICS for the first time, and expands the
CPG 2.0 control crosswalk. Candidates for a next version, in rough priority
order:

1. **Per-CVE CVSS from NVD**, to replace the advisory-level
   `Cumulative_CVSS` with a true per-CVE score where advisories bundle
   multiple CVEs of differing severity (carried over from v1.0's
   NEXT_STEPS).
2. **Broaden `electric_adjacent` if the narrow scope proves too sparse in
   practice.** v1.1 deliberately scoped this class narrowly
   (interconnection-point equipment only, per the author's choice); if a
   real `--full` run shows it matching too few rows to be useful, the
   broader "any vendor serving both ONG and electric utilities" option
   considered during v1.1 scoping is the natural next step.
3. **A vendor-support/EOL registry**, to give `no_patch_available` a second,
   independent signal beyond Vulnrichment CNA text — no such public,
   structured feed was found during the v1.1 build; if the author knows one,
   it would materially improve coverage over the "no_remediation_text_
   captured" bucket documented in LIMITATIONS.md item 2.
4. **Extend the time window to the full ICS-CERT history (2010–present)**
   if a future version wants trend analysis; v1.1, like v1.0, keeps the
   full available window rather than filtering by date.
5. **A versioned, scheduled rebuild** (e.g. quarterly), so
   `no_patch_available`, KEV, and EPSS status stay current — a natural fit
   for a dated Zenodo version series now that
   `.github/workflows/publish-zenodo.yml` correctly creates a new version of
   the existing record instead of a new one each time.
6. **Confirm the primary CPG 2.0 and TSA SD PDFs by hand and correct any
   goal ID the automated-fetch workaround got wrong** (LIMITATIONS.md item
   7) — this should happen before v1.1 ships, not deferred to v1.2, but is
   listed here as the standing item until it's done.
7. **~~Replace the ATT&CK for ICS single-token match with something that
   doesn't structurally whack-a-mole.~~ DONE (commit after `0cff2bb`, real
   run #5, 2026-09-12).** Three real `--full` runs on 2026-09-11 each fixed
   the top offenders in `_GENERIC_TOKENS` and each time the match rate
   stayed well above the "rare" LIMITATIONS.md item 6 originally expected
   (31.4% -> 26.7%). A fourth real run on 2026-09-12 found and fixed a
   separate bug — `token in description` was substring containment, not
   word-boundary matching, which is what actually produced APT38's
   nonsense tokens (http/incl/lion/opera/over); fixing that alone only
   moved the rate 17.47% -> 15.92%, because it just promoted the next tier
   of ordinary whole words (Industroyer2: impact/initial/over/protocol/
   voltage; Bad Rabbit: secure) into the top 10 — confirming this really
   was the structural problem this item describes, not just the substring
   bug. Implemented the **require 2+ independently-matching tokens**
   option below (not TF-IDF): `apply_attack_ics_match` now requires 2+
   distinct Product-field tokens to each independently word-boundary-match
   the same entity's description before tagging it, and returns all of
   them (joined with " + ") in `attack_ics_matched_token` instead of just
   one. Re-validated against `--demo`: TRITON still matches CVE-2025-30001
   on "triconex + tricon" — the flagged risk (a row whose Product field
   has only one very strong, unambiguous token, e.g. just "Triconex" alone)
   was checked against the real ATT&CK bundle and did not affect any of
   the four confirmed true positives (PLC-Blaster, VPNFilter, Triton,
   INCONTROLLER), all of which fire on 2+ tokens in practice. **Still
   needed:** one more real `--full` run to get the actual post-fix match
   rate and re-do the row-level spot-check sign-off in
   `docs/VERIFY_CHECKLIST.md` against it — the 15.92% figure above is
   pre-this-fix and will drop further. TF-IDF rarity scoring remains a
   theoretical alternative if 2+-token matching still proves too noisy on
   the next real run, but is not expected to be needed.
