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
7. **Replace the ATT&CK for ICS single-token match with something that
   doesn't structurally whack-a-mole.** Three real `--full` runs on
   2026-09-11 each fixed the top offenders in `_GENERIC_TOKENS` and each
   time the match rate stayed well above the "rare" LIMITATIONS.md item 6
   originally expected (31.4% -> 26.7% -> not yet re-measured after round
   3), because any single-word match against a long free-text description
   will eventually collide with *some* ordinary English word from *some*
   row's Product field, and the blocklist can only ever be as complete as
   the data seen so far. Two structural options, neither implemented
   because neither could be validated against the real ATT&CK for ICS
   bundle from the build environment (no network access to
   raw.githubusercontent.com) without risking silently breaking a
   confirmed true positive like TRITON's single-token match on
   "triconex":
   - **Require 2+ independently-matching tokens** from the same Product
     string against the same entity description, not just one. Likely
     kills most remaining generic-word collisions (two unrelated common
     words both landing in the same description by chance is much rarer
     than one) while probably still passing multi-word true positives
     (PLC-Blaster: siemens+plcs; Triton: schneider+tricon+triconex).
     Risk: could suppress a genuine match built on one very strong,
     unambiguous token (e.g. a row whose Product field is just
     "Triconex" alone, no second token) — would need real data to check
     before shipping.
   - **Score by token rarity (TF-IDF against the ATT&CK for ICS corpus)**
     instead of binary inclusion, so common words contribute near-zero
     match weight automatically instead of needing to be hand-listed.
     More principled, more implementation and testing effort.
   Whichever the author picks, re-validate with `--demo` first (does
   TRITON still match on "triconex"?) before running `--full` again.
