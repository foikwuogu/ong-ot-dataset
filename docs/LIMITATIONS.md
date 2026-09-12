# Limitations — ONG-OT Vulnerability Prioritization Dataset, v1.1

**Status: DRAFT — unverified.** Written before any discussion section, per
this project's build standard, so nothing downstream can outrun what is
honestly known about the data.

1. **A real `--full` run against live sources is required before any row
   count, match rate, or distribution can be cited** — the build
   environment used to write and test this pipeline has outbound network
   access to `github.com`/`api.github.com` only (`cisa.gov`,
   `epss.empiricalsecurity.com`, `api.first.org`, and
   `raw.githubusercontent.com` are all blocked by that environment's egress
   policy), so anything produced there comes from a small, hand-built demo
   fixture (`data/raw/sample_*.csv`) that verifies the *logic* only, not the
   real dataset. The repository's own GitHub Actions workflow, which runs
   on unrestricted infrastructure, is the way to get a real run.

   **Update, 2026-09-11:** three real `--full` runs have now happened via
   that workflow (see items 2–3 below and `docs/v1.1-build-status` history
   for the bugs each one surfaced and fixed). The current real numbers:
   27,924 total rows, 5,937 Vulnrichment records fetched, 268 rows flagged
   `no_patch_available = True`, `plc` matching 15.3% of rows, ATT&CK for ICS
   matching 17.5%. **Still [VERIFY]:** these numbers, and every other one
   quoted in `README.md`, `.zenodo/description.html`, or a manuscript if
   one exists, still need to be mechanically re-derived from
   `report/stats.json` after this run rather than hand-copied here — see
   `docs/VERIFY_CHECKLIST.md`'s "Reproduce" section.

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
   assuming a patch exists.

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

   **Update, 2026-09-11 (confirmed):** the re-run with both fixes in place
   returned 5,937 Vulnrichment records fetched and 268/27,924 rows flagged
   `no_patch_available = True`, with a sane, auditable phrase-hit breakdown
   in `qa_report.txt`. The author reviewed the phrase list above and the
   "no signal" treatment for rows with no solutions/workarounds text at all
   and confirmed both as-is, in chat, against this real output — see
   `config/no_patch_rules.yaml`'s header comment.

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
   pharma, water — not oil & gas-exclusive). This is a curated judgment
   call, not a fetched fact.

   **Update, 2026-09-11:** a real `--full` run against the code *before*
   the plc/rtu/scada re-scoping (bare vendor name, commit `86bb436`) showed
   `plc` matching 14,316/27,924 rows (51.3%) — an unmapped-default-heavy
   dataset was clearly not resulting. A second real run *with* the
   re-scoping (commit `f343a32`) showed `plc` drop to 4,274/27,924 (15.3%)
   and `unmapped` rise from 44.3% to 83.2% — the re-scoping fix worked as
   intended on real data, not just the 7-row demo fixture. The author
   reviewed the full allowlist and weight for every class (including the
   plc/rtu/scada platform groupings) against this real output and confirmed
   it as-is, in chat, no changes requested — see
   `config/product_class_taxonomy.yaml`'s header comment.

4. **The new `electric_adjacent` class is deliberately narrow and may match
   zero or very few rows in a given build.** Per the author's scoping
   decision, it requires BOTH a curated protection-relay/interconnection
   product match AND a context keyword (interconnection, substation,
   compressor station, etc.) in the same row — a real signal is rare in
   public advisory text at this level of specificity. A low or zero match
   count is the expected result of the narrow scope, not a pipeline defect.
   **Confirmed 2026-09-11:** the author reviewed the product allowlist and
   the interconnection-point boundary itself, in chat, and confirmed it
   as-is, no changes requested.

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
   were deliberately left untouched.

   **Update, 2026-09-11 (same day, round 3):** re-ran after the round-2
   fix — match rate dropped 31.4% -> 26.7%, still far above "rare," because
   the fix only removed the top offenders and let the next tier of
   generic-word collisions rise into the top 10: FIN7 (including/link/
   malware/medical/multiple), CyberAv3ngers (asset/engage/health/
   healthcare/human), APT38 again (active/cisa/endpoint/fire/general),
   FIN6 (card/data/hospital/mark/sold). Stuxnet's tokens
   (component/components/large/micro/micros) turned out unchanged from
   round 2 — the "maybe legitimate, Stuxnet's description does discuss
   Siemens components" leniency from the note above was wrong; real data
   showed zero sign of an actual Stuxnet-specific token, so these are now
   stoplisted too. Fixed (round 3): a much larger, more conservative
   stoplist addition covering both these specific words and preemptive
   general security/IT vocabulary (threat, actor, campaign, victim,
   exploit, vulnerability, sector, energy, etc.) likely to recur. Confirmed
   genuinely correct matches survived every round: PLC-Blaster
   (siemens/plcs), VPNFilter (modbus), INCONTROLLER (codesys/omron), and a
   second entity, Triton (capitalization variant of TRITON in the real
   ATT&CK for ICS data), matched correctly on schneider/tricon/triconex.

   **This is structurally a whack-a-mole problem, not a bug with a final
   fix.** A single-token substring match against long free-text
   descriptions will always eventually collide with some ordinary word
   from some row's Product field; the stoplist can only ever cover what
   real data has shown so far. `docs/NEXT_STEPS.md` item 7 lays out two
   real structural fixes (requiring 2+ corroborating tokens per match, or
   TF-IDF-style rarity scoring) that were not implemented because neither
   could be validated against the live ATT&CK for ICS bundle from this
   build environment without risking a false negative on a confirmed true
   positive (e.g. a row whose Product is just "Triconex" alone). **[VERIFY]**
   whatever match rate the next `--full` run shows, read the top-10 list
   with matched tokens every time — do not assume a lower number means the
   list has become trustworthy without eyes on it.

7. **Two of the four primary policy documents could not be automatically
   retrieved as PDFs.** The CISA CPG 2.0 PDF and the TSA Security Directive
   Pipeline-2021-01G PDF both return HTTP 403 to automated fetch (likely
   bot-protection on cisa.gov/tsa.gov, not a redistribution restriction, and
   the same issue v1.0's build notes hit).

   **Update, 2026-09-11 (during verification):** although the CPG 2.0 PDF
   itself is still unreachable, CISA's own goal-listing page
   (cisa.gov/cross-sector-cybersecurity-performance-goals) *was* reachable
   during verification and gave the real, current CPG 2.0 goal IDs. This
   exposed a real error: every goal ID originally reconstructed for
   `config/compensating_controls_cpg2.yaml` (CPG2-2A, CPG2-2C, CPG2-1B,
   CPG2-3X-SEG, CPG2-1G, CPG2-2O) was wrong — the reconstruction had
   assumed a 6-category "Govern/Identify/Protect/Detect/Respond/Recover"
   structure with IDs numbered 1–7, but the real CPG 2.0 has only five
   categories (Identify 1.*, Protect 2.*, Detect 3.A only, Respond 4.*,
   Recover 5.A) and no ID above 5.*. Every control's underlying *concept*
   and title had been matched correctly (asset inventory, network
   segmentation, vendor/supplier requirements, no exploitable services, OT
   leadership, known-vulnerability mitigation) — only the ID codes
   themselves were fabricated-sounding placeholders that happened to read
   as plausible CPG-style IDs. Corrected to the real IDs (1.A, 2.W, 1.C,
   2.F, 1.I, 1.E respectively — see the config file's own header comment
   for the full mapping).

   **Update, 2026-09-12 (author-supplied source material, checked before
   use):** the author brought back a written summary of both the CPG 2.0
   risk-reduction guidance and the TSA Security Directives for this item.
   Checked the CPG 2.0 half against CISA's own published materials before
   adopting it: CISA does **not** publish a quantified, per-goal
   risk-reduction percentage table (confirmed via a direct search of
   cisa.gov's own reporting on CPG impact, which gives only aggregate
   before/after trends, not per-goal figures). The specific percentage
   ranges supplied (e.g. "20-30% for asset inventory", "25-40% for MFA on
   OT remote access") do not appear in any CISA publication found and were
   **not** adopted; `reduces_risk_by` in `config/compensating_controls_cpg2.yaml`
   remains the author's own conservative estimate, now labeled as such
   explicitly in that file's header rather than implied to be CISA-sourced.

   The TSA half fared better: one primary document, SD Pipeline-2021-02C
   (effective 2022-07-27), was directly reachable and confirmed OT is
   explicitly named a "Critical Cyber System," written confirmation of
   receipt is required, and an annual CAP submission plus a two-yearly
   architectural design review are required. A reliable secondary summary
   of the original SD Pipeline-2021-01 (May 2021) confirmed the
   Cybersecurity Coordinator requirement, incident-reporting timeline (12
   hours), and — importantly — **corrected** a wrong claim in the
   author-supplied material: the Coordinator must be a U.S. citizen
   eligible for a security clearance, not (as first supplied) someone
   satisfying a NEXUS/Global Entry alternative; no such alternative appears
   in any source checked. Still **[VERIFY]** and unconfirmed from a primary
   source: the exact current Cybersecurity Assessment Program audit
   percentage/cadence (a secondary source describes "30% annually" for the
   `-02D` amendment specifically; the `-02C` text itself states no
   percentage, only the two-year design review), any managed-security-
   service-provider responsibility language, and which numbered amendment
   (`-01G`, `-02F`, or later) is the one currently in force — `tsa.gov`
   403s most of its own PDFs to automated fetch, including every later
   amendment tried. See `docs/BUILD_SPEC.md`'s "Policy text" section for
   the full citation trail.

   **Update, 2026-09-12 (full direct read of the -02C primary PDF, plus web
   research for the amendments after it):** the author supplied the full
   SD Pipeline-2021-02C PDF and it was read end-to-end (all 21 pages plus
   the annotated attachment), not just excerpted as before. Two things
   this closes out: (1) no managed-security-service-provider language of
   any kind appears anywhere in -02C's text, definitions section, or
   attachment; and (2) -02C's own header states its **EXPIRATION DATE as
   2023-07-27** — confirming directly, not just inferring, that -02C is
   long superseded and cannot be cited as the current requirement.

   Web research (search + fetches of secondary sources; `tsa.gov`'s own
   SD PDFs still 403 to automated fetch, -02C included on a retest today)
   filled in more of the amendment chain than was available on 2026-09-11:
   - The 30%-annually / 100%-over-3-years CAP testing cadence is real and
     dated: a law firm's direct quote of **SD Pipeline-2021-02D** (Vinson
     & Elkins, "Resilience Reimagined," velaw.com) gives the operative
     sentence as *"testing at least 30% of measures and capabilities
     implemented under a CAP, with 100% to be tested over any three-year
     period."* -02D was effective 2023-07-27 and expired 2024-07-27. No
     source checked confirms word-for-word that this exact sentence
     carried forward unchanged into -02E/-02F/-02G, though nothing found
     suggests it was removed either — **[VERIFY]** against whichever
     amendment is current when you have primary-PDF access.
   - **Still no MSSP language found** in any source describing any
     amendment (-02C read directly; -02D, -02E, -02F, -01G described only
     in secondary sources) — three independent negative checks now,
     across four amendments. Treat this as "not part of this directive
     series in any version checked," not merely "unconfirmed," though a
     primary-source read of the current amendment would make it certain.
   - **Currently in force, best evidence available today:** SD
     Pipeline-2021-**02F** (02-series, effective 2025-05-03) and SD
     Pipeline-2021-**01G** (01-series, effective per one compliance-
     tracking source 2026-01-16, per a filename-dated TSA memo
     2026-01-09) — both per secondary/compliance-tracking sources, not a
     primary PDF read. A file at a URL suggesting a further **02G**
     amendment was also found via search, but no source could confirm its
     date or that it (rather than -02F) is the one actually in force —
     **[VERIFY]** this specifically against `tsa.gov/sd-and-ea` (TSA's own
     current listing page, which was reachable and listed -02F as the
     newest 02-series entry as of 2026-09-12, but did not reliably expose
     amendment dates to automated parsing).
   - New context: TSA proposed converting the SD series into a permanent
     49 CFR rule (NPRM, November 2024); the public comment period closed
     2025-02-05. As of the most recent secondary source found (a 2026
     OMB/PRA renewal notice for the SD series' information-collection
     requirements), the SD series was still the operative mechanism and no
     final rule had yet issued — but this should be re-checked at release
     time since it can change without much notice.

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
