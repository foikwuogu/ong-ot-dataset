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
