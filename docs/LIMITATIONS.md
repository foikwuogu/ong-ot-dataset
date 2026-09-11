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

   **Update, 2026-09-10:** the first real `--full` run (on GitHub Actions)
   returned `vulnrichment_remediation_text_present_pct = 0.0` across all
   27,924 rows — every single Vulnrichment fetch silently failed. Root
   cause (partial — see 2026-09-11 below): `src/fetch_vulnrichment.py` was
   sending the GitHub Actions job token (`GITHUB_TOKEN`, wired into the
   workflow to raise the *API* rate limit) as an `Authorization: Bearer`
   header on requests to `raw.githubusercontent.com` — a public content
   CDN, not the `api.github.com` contents endpoint the original code
   comment described. That endpoint doesn't need or reliably accept that
   header. Removed it; also added a fetch-success-rate stderr warning and a
   `qa.py` flag for any run under 5% coverage.

   **Update, 2026-09-11:** removing the header did NOT fix it — the re-run
   still came back `0.0%`. The actual root cause was a second, independent
   bug: `_shard_path()` built request paths with an extra `cves/` prefix
   (`cves/2024/3xxx/CVE-2024-3400.json`), but the real repository shards
   directly at the root (`2024/3xxx/CVE-2024-3400.json`, no `cves/`
   segment) — every single request 404'd regardless of the header, for a
   completely unrelated reason. Confirmed by fetching that exact corrected
   path live and inspecting its contents (a KEV-listed CVE with real
   `solutions`/`workarounds` text present, as expected). Neither bug was
   catchable by `--demo` testing, which reads a static local fixture and
   never makes an HTTP request — a real lesson for future fetch modules:
   verify the *exact* URL against the live source before trusting the
   module, not just its response schema against a hand-typed example.
   **[VERIFY]** re-run `--full` with both fixes in place and confirm
   `no_patch_available` is finally nonzero before trusting any `no_patch_*`
   number — two zero-result runs in a row must not be the one that ships.

3. **v1.0's `product_class_taxonomy.yaml` was not oil & gas-specific.** It
   mapped only 3 classes to 7 generic industrial ICS vendors (Schneider,
   Rockwell, Siemens, ABB, Emerson, Honeywell, Yokogawa) by bare vendor name
   — so an unrelated product from one of those vendors got the same
   ONG-relevance weight as an oil & gas-specific one, and nearly all of
   v1.0's 27,922 rows fell to `unmapped_default_weight: 0.0` anyway since the
   list was so narrow. v1.1 fixes this twice: it adds a genuinely oil &
   gas-specific `ong_product_line` class (curated vendor/product-family
   allowlist: ROC800/FloBoss/ControlWave/Totalflow, SCADAPack/RemoteConnect,
   ValveLink, Micro Motion, gas chromatographs, tank-gauging systems, etc.)
   at the highest weight (0.9); and, per the author's explicit follow-up
   request, re-scopes `plc`/`rtu`/`scada` from bare vendor name down to
   specific process-control platforms those same vendors sell that are
   actually common in oil & gas/refining (Modicon/Foxboro, PlantPAx/
   ControlLogix, SIMATIC/PCS 7, 800xA/Freelance/RTU560, DeltaV/Ovation,
   Experion PKS, CENTUM/ProSafe), raising their weight from 0.5 to 0.6 to
   reflect the tighter scope while staying below `ong_product_line` (these
   platforms are still shared with other process industries — chemicals,
   pharma, water — not oil & gas-exclusive). **This is a curated
   judgment call, not a fetched fact — [VERIFY] the allowlist against your
   own field knowledge before this dataset is cited or published.**

   **Update, 2026-09-11:** a real `--full` run against the code *before*
   the plc/rtu/scada re-scoping (bare vendor name, commit `86bb436`) showed
   `plc` matching 14,316/27,924 rows (51.3%) — an unmapped-default-heavy
   dataset was clearly not resulting. A second real run *with* the
   re-scoping (commit `f343a32`) showed `plc` drop to 4,274/27,924 (15.3%)
   and `unmapped` rise from 44.3% to 83.2% — the re-scoping fix worked as
   intended on real data, not just the 7-row demo fixture. Still
   **[VERIFY]** the specific platform list per the paragraph above; a lower
   match rate confirms the fix narrowed matching, not that every remaining
   match is correct.

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

   **Update, 2026-09-10:** the first real `--full` run matched 8,770 of
   27,924 rows (31.4%) — nowhere near "rare," and the top 10 matched
   entities include FIN7, REvil, and Conficker: a financially-motivated
   cybercrime group and two pieces of generic/ransomware malware, none of
   them ICS-specific threat actors, alongside genuinely ICS-relevant hits
   (PLC-Blaster, Stuxnet, INCONTROLLER, Dragonfly, OilRig). The `_demo`
   fixture (7 rows) was structurally too small to ever have caught this —
   the failure mode only shows up at real scale, where a short, generic
   English word from a Product field (candidate culprits: something like
   "card" for FIN7's payment-card focus, or "drive"/"backup" for
   Conficker/REvil) can coincidentally appear inside a long, unrelated
   entity's own STIX description, and `_GENERIC_TOKENS` — hand-curated
   from ICS-domain vocabulary only — was never built to catch ordinary
   English/IT words like these. **Fixed enough to diagnose, not yet fixed
   outright**: `apply_attack_ics_match` and `build_dataset` now also
   return/store `attack_ics_matched_token` (the literal word that fired
   each match), and `qa.py` prints it alongside each top-10 entity and
   flags any run matching over 15% of rows. **[VERIFY]** re-run `--full`
   and read the new matched-token column for FIN7/REvil/Conficker rows
   before deciding whether to (a) accept these as legitimate — MITRE's own
   ATT&CK for ICS matrix does include some non-ICS-native
   malware/ransomware as documented real-world OT-impact case studies, so
   this is not automatically wrong — or (b) tighten `_GENERIC_TOKENS`
   further (or require a longer minimum token length) once the exact
   triggering words are visible.

   **Update, 2026-09-11:** the matched-token column answered the question.
   Dragonfly and APT38 were matching almost entirely on bare 4-digit years
   (2010/2014/2017/2019/2020/2021/2022 — the entities' own activity-history
   dates, not product identifiers); REvil matched on the single word
   "family"; FIN7/Conficker/OilRig matched on ordinary English/IT words
   ("food", "cloud", "carbon", "drives", "plant", "power", "computers",
   "ability", "comm"/"communication", "agent", "advisor", "base"/"based")
   that a long STIX description contains almost by chance. Meanwhile some
   matches were confirmed genuinely correct by the same data: PLC-Blaster
   via "siemens"/"plcs", VPNFilter via "modbus" (a real ICS protocol, not a
   coincidence), and INCONTROLLER via "codesys"/"omron" (INCONTROLLER/
   PIPEDREAM is documented malware that specifically targets CODESYS and
   Omron products). **Fixed**: `_distinctive_tokens` now drops bare numeric
   tokens entirely (a number alone is never a real product identifier —
   real ones mix letters and digits, like "sel-451" or "s7-1500", or are
   pure letters, like "triconex" or "modbus"), and `_GENERIC_TOKENS` gained
   the specific English/IT words this run's data evidenced. Genuinely
   distinctive ICS terms (modbus, codesys, omron, siemens, triconex, etc.)
   were deliberately left untouched. **Still open, [VERIFY] against your
   own judgment**: Stuxnet matched on "advisor, component, components,
   large, micro" and OilRig on "comm, communication" (now stoplisted) plus
   "agent, based" (now stoplisted) — after this round's fix, re-run and
   check whether Stuxnet's remaining tokens ("component"/"components"/
   "large"/"micro" — not stoplisted, deliberately left for your call since
   Stuxnet's real description does discuss Siemens system *components*)
   still produce a defensible match or need one more round.

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
