"""
Join ICS advisories with KEV, EPSS, and Vulnrichment on cve_id, match against
MITRE ATT&CK for ICS group/software descriptions, then apply the three
client-owned config files (product class, no-patch rule, compensating
controls) to produce the final ONG-OT Vulnerability Prioritization row set.

This module is deliberately dumb about the three config-driven fields: it
applies whatever is in config/*.yaml literally, and leaves a column
'unmapped' / weight 0.0 / "unmapped — needs review" wherever the config
doesn't cover a row. It does not invent taxonomy, no-patch judgment, or
control mappings — see README.md, "Division of labor."

CHANGED IN v1.1 (see BUILD_SPEC.md / CODEBOOK.md for the full rationale):
  - apply_product_class: now supports three match modes (vendor_only,
    vendor_or_product, vendor_or_product_and_context) so the new
    ong_product_line and electric_adjacent classes in
    product_class_taxonomy.yaml can match on product text, not vendor alone.
  - apply_no_patch_flag: v1.0's trigger checked Mitigation/Remediation
    columns that do not exist in the real ICS Advisory Project source (see
    no_patch_rules.yaml). v1.1 matches against real Vulnrichment CNA
    solutions/workarounds text instead, and separately records when that
    text is simply absent (no_patch_basis) rather than treating absence as
    a negative determination.
  - apply_attack_ics_match (new): tags a row with any ATT&CK for ICS
    group/software whose own STIX description explicitly names this row's
    Vendor or Product text — auditable, row-by-row, never a bulk/class-level
    inference. Most rows will not match; that is expected (see
    LIMITATIONS.md), not a bug.
"""
from __future__ import annotations
import re
import yaml
import pandas as pd


def load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _text_fields(row: pd.Series, fields: list[str]) -> str:
    return " ".join(str(row.get(f, "") or "") for f in fields).lower()


def apply_product_class(row: pd.Series, taxonomy: dict) -> tuple[str, float]:
    """Match this row against each taxonomy class in the order the classes
    appear in the YAML file — first match wins, so more specific classes
    (e.g. ong_product_line) must be listed before generic ones.

    match: vendor_only                    substring match against Vendor only
    match: vendor_or_product               substring match against Vendor +
                                            Product + Products_Affected +
                                            ICS-CERT_Advisory_Title
    match: vendor_or_product_and_context   BOTH a vendors_products hit AND a
                                            context_keywords hit are required
    """
    vendor_text = str(row.get("Vendor", "") or "").strip().lower()
    product_text = _text_fields(row, ["Vendor", "Product", "Products_Affected", "ICS-CERT_Advisory_Title"])

    for class_name, spec in taxonomy.get("classes", {}).items():
        match_type = spec.get("match", "vendor_only")
        candidates = [c.lower() for c in spec.get("vendors_products", spec.get("vendors", [])) if c]

        if match_type == "vendor_only":
            if any(c in vendor_text for c in candidates):
                return class_name, spec.get("weight", 0.0)

        elif match_type == "vendor_or_product":
            if any(c in product_text for c in candidates):
                return class_name, spec.get("weight", 0.0)

        elif match_type == "vendor_or_product_and_context":
            context_keywords = [k.lower() for k in spec.get("context_keywords", []) if k]
            if any(c in product_text for c in candidates) and any(k in product_text for k in context_keywords):
                return class_name, spec.get("weight", 0.0)

    return "unmapped", taxonomy.get("unmapped_default_weight", 0.0)


def apply_no_patch_flag(row: pd.Series, rules: dict) -> tuple[bool, str]:
    """Evaluate the no_patch rule list against real Vulnrichment CNA
    solutions/workarounds text (see no_patch_rules.yaml for why v1.0's
    column-based triggers never fired on real data).

    Returns (no_patch_available, no_patch_basis):
      - (True,  "cna_text_match:<phrase>")   a configured phrase matched
      - (False, "cna_text_no_match")         text was present, no phrase matched
      - (False, "no_remediation_text_captured")  Vulnrichment had no
        solutions/workarounds text for this CVE at all — absence of
        evidence, not evidence of a patch; kept visible rather than folded
        silently into False (see no_patch_rules.yaml, LIMITATIONS.md).
    """
    text_present = bool(row.get("vulnrichment_remediation_text_present", False))
    text = str(row.get("vulnrichment_remediation_text", "") or "").lower()

    if not text_present:
        return False, "no_remediation_text_captured"

    for trigger in rules.get("no_patch", []):
        for phrase in trigger.get("cna_text_contains", []):
            if phrase.lower() in text:
                return True, f"cna_text_match:{phrase}"

    return False, "cna_text_no_match"


def apply_compensating_control(row: pd.Series, controls: dict) -> tuple[str, float]:
    """Return every control whose applies_to includes this row's product
    class, plus the combined risk reduction (stacked multiplicatively:
    two controls each cutting risk by 0.2 combine to 1 - (0.8 * 0.8) = 0.36).
    """
    product_class = row.get("ong_product_class")
    matched_ids = []
    surviving_fraction = 1.0
    for control in controls.get("controls", []):
        if product_class in control.get("applies_to", []):
            matched_ids.append(control["id"])
            surviving_fraction *= (1 - control.get("reduces_risk_by", 0.0))
    if not matched_ids:
        return "unmapped — needs review", 0.0
    combined_reduction = round(1 - surviving_fraction, 4)
    return ", ".join(matched_ids), combined_reduction


def _attack_entity_index(groups_software: pd.DataFrame) -> list[tuple[str, str, str, str]]:
    """Precompute (description_lower, name, entity_type, technique_ids) once
    per build, instead of once per row — with ~28k dataset rows and ~300+
    ATT&CK for ICS group/software entries, matching row-by-row against a
    freshly lower-cased DataFrame would be ~8M string ops for no reason."""
    if groups_software is None or groups_software.empty:
        return []
    index = []
    for _, entity in groups_software.iterrows():
        description = str(entity.get("description", "") or "").lower()
        if description:
            index.append((description, entity.get("name", ""), entity.get("entity_type", ""), entity.get("technique_ids", "")))
    return index


# Generic ICS/OT/corporate words stripped before matching a product string
# against an ATT&CK for ICS group/software description — without this, a
# product field like "SEL-451 Protection Relay" would match on the word
# "protection" or "relay" alone, which appear in dozens of unrelated ATT&CK
# entries. Only genuinely distinctive tokens (product/model names like
# "triconex", "sel-451", "controlwave") should drive a match.
#
# Round 2 (2026-09-11, real --full run #2): the first real run matched
# 31.4% of rows -- LIMITATIONS.md item 6 expected "rare". attack_ics_
# matched_token showed exactly why: Dragonfly and APT38 were matching
# almost entirely on bare 4-digit numbers (2010, 2014, 2017, 2019-2022 --
# years from the entities' own activity history, not product identifiers),
# and REvil/FIN7/Conficker/OilRig were matching on ordinary English/IT
# words ("family", "food", "cloud", "carbon", "drives", "plant", "power",
# "computers", "ability", "comm", "communication", "agent", "advisor")
# that a long STIX description will contain somewhere almost by chance.
#
# Round 3 (2026-09-11, real --full run #3, same day): fixing round 2
# dropped the rate to 26.7% -- still far from "rare" -- because the same
# failure mode just promoted the NEXT generic-word collision into the top
# 10: FIN7 (including/link/malware/medical/multiple), CyberAv3ngers
# (asset/engage/health/healthcare/human), APT38 again (active/cisa/
# endpoint/fire/general), FIN6 (card/data/hospital/mark/sold), and
# Stuxnet's tokens (component/components/large/micro/micros) turned out to
# be the SAME noise as round 2 despite being left alone as "possibly
# legitimate" -- real data showed no sign of a genuine Stuxnet-specific
# token ever surfacing, so that leniency was wrong and is corrected here.
#
# THIS IS STRUCTURALLY A WHACK-A-MOLE PROBLEM, not a bug that "gets fixed":
# any curated blocklist of generic words is finite, and STIX descriptions
# are long enough that some ordinary English word will eventually collide
# with some row's Product field. Each round narrows it further and
# confirmed-genuine matches (PLC-Blaster: siemens/plcs; VPNFilter: modbus;
# INCONTROLLER: codesys/omron; Triton: schneider/tricon/triconex) have
# survived every round untouched -- but do not expect this list to reach
# zero false positives. See NEXT_STEPS.md for a real structural fix
# (requiring 2+ independently-informative tokens per match, or scoring by
# token rarity) that was NOT implemented here because it couldn't be
# validated against the real bundle from this environment without risking
# silently breaking a true positive like TRITON matching on "triconex"
# alone. **[VERIFY]** treat every remaining match in qa_report.txt's top 10
# as a hypothesis to spot-check, not a settled fact, however many rounds
# of this list have run.
_GENERIC_TOKENS = {
    "system", "systems", "safety", "instrumented", "controller", "controllers",
    "control", "series", "product", "products", "device", "devices", "module",
    "modules", "unit", "units", "firmware", "software", "version", "versions",
    "protection", "relay", "relays", "station", "stations", "substation",
    "substations", "interconnection", "point", "compressor", "pipeline", "gas",
    "oil", "interface", "network", "networks", "remote", "connect", "connected",
    "paired", "with", "used", "for", "the", "and", "before", "after", "all",
    "affected", "electric", "electronic", "electronics", "engineering",
    "laboratories", "automation", "technologies", "industries", "incorporated",
    "company", "corp", "corporation", "international", "field", "process",
    # added 2026-09-11, round 2:
    "family", "food", "cloud", "carbon", "drives", "drive", "plant", "power",
    "computers", "computer", "ability", "comm", "communication", "communications",
    "agent", "advisor", "equip", "equipment", "base", "based",
    # added 2026-09-11, round 3:
    "including", "link", "links", "malware", "medical", "multiple", "asset",
    "assets", "engage", "engaged", "engagement", "health", "healthcare",
    "human", "active", "cisa", "endpoint", "endpoints", "fire", "general",
    "card", "cards", "data", "hospital", "hospitals", "mark", "marked",
    "sold", "component", "components", "large", "micro", "micros", "center",
    "centers", "cure", "facts", "industrial", "infrastructure", "credential",
    "credentials", "monitor", "monitoring", "custom", "dream", "sector",
    "sectors", "energy", "several", "various", "related", "additional",
    "known", "public", "publicly", "threat", "threats", "actor", "actors",
    "campaign", "campaigns", "operation", "operations", "capability",
    "capabilities", "target", "targets", "targeted", "targeting", "victim",
    "victims", "report", "reported", "reports", "research", "researchers",
    "group", "groups", "tool", "tools", "access", "exploit", "exploited",
    "exploitation", "vulnerability", "vulnerabilities", "observed",
    "identified", "believed", "likely", "possible", "potential", "other",
    "others", "first", "since", "later", "early", "recent", "uses", "using",
    "employ", "employed", "deploy", "deployed", "deployment", "information",
    "technology", "government",
}

# Standard English function words (articles, conjunctions, prepositions,
# pronouns, auxiliary verbs), kept separate from _GENERIC_TOKENS above
# because that list is reactive/domain-specific -- built by hand-adding
# whatever ICS/product/corporate word caused a collision in a real run --
# while this one is a plain stopword list that should have been here from
# the start. Added 2026-09-12 after a real --full run (post the 2+-token
# fix below) still matched GOLD SOUTHFIELD on "trend + that": "that" is an
# ordinary function word no domain-specific blocklist would ever think to
# add on its own. Only 4+ character words matter here since
# _distinctive_tokens already drops anything shorter via the regex.
_STOPWORDS = {
    "that", "this", "these", "those", "than", "then", "when", "where",
    "which", "while", "from", "into", "onto", "upon", "such", "same",
    "both", "each", "either", "neither", "only", "very", "just", "also",
    "still", "indeed", "however", "moreover", "furthermore", "thus",
    "hence", "therefore", "although", "though", "unless", "until",
    "since", "about", "above", "below", "again", "further", "once",
    "here", "there", "does", "doing", "have", "having", "will", "would",
    "could", "should", "shall", "must", "cannot", "your", "yours",
    "their", "theirs", "them", "they", "what", "whom", "whose", "some",
    "more", "most", "less", "many", "much", "over", "under", "between",
    "during", "before", "against", "among", "amongst", "around",
    "toward", "towards", "within", "without", "throughout", "along",
    "across", "behind", "beside", "besides", "beyond", "except",
    "inside", "outside", "near", "itself", "himself", "herself",
    "themselves", "ourselves", "yourself", "yourselves", "myself",
    "whatever", "whenever", "wherever", "whichever", "whoever",
}


def _distinctive_tokens(text: str) -> list[str]:
    tokens = re.findall(r"[a-z0-9\-]{4,}", str(text or "").lower())
    return [
        t for t in tokens
        if t not in _GENERIC_TOKENS
        and t not in _STOPWORDS
        # A bare number (e.g. a year like "2019", or a generic quantity)
        # carries no real distinguishing power on its own -- real product
        # identifiers mix letters and digits ("sel-451", "s7-1500") or are
        # pure letters ("triconex", "modbus"). Added 2026-09-11 after real
        # data showed Dragonfly/APT38 matching almost entirely on years.
        and not t.isdigit()
    ]


def apply_attack_ics_match(product: str, entity_index: list[tuple[str, str, str, str]]) -> tuple[str, str, str, str]:
    """Tag with any ATT&CK for ICS group/software whose own STIX description
    contains at least TWO distinct, independently-matching distinctive
    tokens from this row's Product text.

    Deliberately matches on Product only, not Vendor, and only on tokens
    that survive _GENERIC_TOKENS filtering: an early version of this
    function matched on the raw vendor name, which caused false positives
    like tagging every Schneider Electric row (including unrelated Modicon
    PLCs) with TRITON just because TRITON's description happens to mention
    "Schneider Electric" — TRITON actually targeted one specific product
    line (Triconex), not the vendor's whole catalog. A version that matched
    on the whole raw product string had the opposite problem: a long,
    natural-language product field almost never appears verbatim inside a
    STIX description. Token-level matching on distinctive words only (both
    issues caught in --demo testing — see docs/VERIFY_CHECKLIST.md) is the
    middle ground.

    Round 4 (2026-09-12, after the word-boundary fix below was validated
    against a real --full run): fixing the substring bug dropped the match
    rate only 17.47% -> 15.92% and simply promoted the next tier of
    ordinary whole words into the top 10 -- Industroyer2 (impact, initial,
    over, protocol, voltage) and Bad Rabbit (secure) joined FIN7
    (services, utilities) and Dragonfly (service), none of which carry any
    real ICS-threat-actor signal. This is the whack-a-mole NEXT_STEPS.md
    item 7 predicted: single-token matching against a long free-text
    description will always eventually collide with *some* ordinary word.
    Requiring 2+ *distinct* tokens from the same Product string to each
    independently appear in the same entity's description is the
    structural fix chosen there over TF-IDF rarity scoring, on the theory
    that two unrelated common words both landing in the same description
    by chance is far rarer than one. Validated against --demo: TRITON
    still matches (schneider + triconex, or schneider + tricon +
    triconex depending on the row) because its true-positive rows always
    carry multiple distinctive tokens; PLC-Blaster (plcs + siemens),
    VPNFilter (modbus + scada), and INCONTROLLER (codesys + omron) survive
    the same way. The known risk flagged in NEXT_STEPS.md -- a row whose
    Product field carries only ONE very strong, unambiguous token (e.g.
    just "Triconex" with nothing else distinctive) would now be missed
    entirely -- was checked against the real bundle available in this
    environment and not observed to affect any of the four confirmed
    true positives above; re-check if a future source refresh changes
    that.

    This stays intentionally conservative even so: ATT&CK for ICS techniques
    describe tradecraft against asset classes, not specific CVEs, so the
    only defensible per-row join is a literal name match against a group's
    or software's own published description. Most rows will not match —
    that reflects the real, narrow overlap between named ATT&CK for ICS
    group/software profiles and the ONG OT product landscape, not a
    pipeline defect (see LIMITATIONS.md).

    Returns (attack_matched_entity, attack_entity_type, attack_technique_ids,
    attack_matched_token), or ("", "", "", "") when nothing matches.
    attack_matched_token is now every matching token for that entity,
    joined with " + " (e.g. "schneider + triconex") rather than just the
    first one, specifically so a run's QA report shows the *combination*
    of evidence behind a match, not just one word of it — see the 2026-09
    finding in LIMITATIONS.md: real full-run output surfaced non-ICS
    entities (FIN7, REvil, Conficker, Bad Rabbit) in the top matches, which
    the 7-row demo fixture is too small to ever catch, and which cannot be
    diagnosed from the entity name alone. Callers should memoize by
    product — see build_dataset — since the same value repeats across many
    rows.
    """
    tokens = _distinctive_tokens(product)
    if not tokens or not entity_index:
        return "", "", "", ""
    # Word-boundary match, not substring containment: `token in description`
    # let short tokens match as fragments inside unrelated longer words in
    # the entity's free-text STIX description (e.g. "opera" inside
    # "operator/operation", "lion" inside "million/billion", "incl" inside
    # "include/including", "over" inside "however/moreover/recover", "http"
    # inside a literal URL) -- see the 2026-09-12 real --full run's QA
    # report, where this is exactly what produced APT38's nonsense matched
    # tokens (http/incl/lion/opera/over). Anchoring on word boundaries fixes
    # that whole class of false positive without touching genuine whole-word
    # hits (siemens, plcs, modbus, scada, schneider, tricon, triconex,
    # codesys, omron), which is why this and _GENERIC_TOKENS are separate,
    # complementary fixes.
    #
    # On top of that: require 2+ distinct matching tokens per entity (see
    # "Round 4" above) -- a single whole-word match is still too easy to
    # come by via chance in a long STIX description.
    unique_tokens = list(dict.fromkeys(tokens))  # dedupe, preserve order
    for description, name, entity_type, technique_ids in entity_index:
        matched = [
            t for t in unique_tokens
            if re.search(r"\b" + re.escape(t) + r"\b", description)
        ]
        if len(matched) >= 2:
            return name, entity_type, technique_ids, " + ".join(matched)
    return "", "", "", ""


def build_dataset(
    advisories: pd.DataFrame,
    kev: pd.DataFrame,
    epss: pd.DataFrame,
    vulnrichment: pd.DataFrame,
    taxonomy: dict,
    no_patch_rules: dict,
    compensating_controls: dict,
    groups_software: pd.DataFrame | None = None,
) -> pd.DataFrame:
    df = advisories.copy()

    kev_slim = kev[["cve_id"]].drop_duplicates().assign(known_exploited=True) if "cve_id" in kev.columns else pd.DataFrame(columns=["cve_id", "known_exploited"])
    df = df.merge(kev_slim, on="cve_id", how="left")
    df["known_exploited"] = df["known_exploited"].fillna(False)

    if "cve_id" in epss.columns:
        df = df.merge(epss[["cve_id", "epss", "percentile"]], on="cve_id", how="left")

    if "cve_id" in vulnrichment.columns:
        df = df.merge(vulnrichment, on="cve_id", how="left")
    if "vulnrichment_remediation_text_present" not in df.columns:
        df["vulnrichment_remediation_text_present"] = False
    df["vulnrichment_remediation_text_present"] = df["vulnrichment_remediation_text_present"].fillna(False)

    product_classes, weights = [], []
    for _, row in df.iterrows():
        cls, w = apply_product_class(row, taxonomy)
        product_classes.append(cls)
        weights.append(w)
    df["ong_product_class"] = product_classes
    df["ong_product_weight"] = weights

    no_patch_flags, no_patch_bases = [], []
    for _, row in df.iterrows():
        flag, basis = apply_no_patch_flag(row, no_patch_rules)
        no_patch_flags.append(flag)
        no_patch_bases.append(basis)
    df["no_patch_available"] = no_patch_flags
    df["no_patch_basis"] = no_patch_bases

    controls, reductions = [], []
    for _, row in df.iterrows():
        c, r = apply_compensating_control(row, compensating_controls)
        controls.append(c)
        reductions.append(r)
    df["cpg2_applicable_controls"] = controls
    df["cpg2_combined_risk_reduction"] = reductions

    entity_index = _attack_entity_index(groups_software)
    match_cache: dict[str, tuple[str, str, str, str]] = {}
    attack_entities, attack_types, attack_techniques, attack_tokens = [], [], [], []
    for _, row in df.iterrows():
        key = str(row.get("Product", "") or "")
        if key not in match_cache:
            match_cache[key] = apply_attack_ics_match(key, entity_index)
        entity, etype, techniques, token = match_cache[key]
        attack_entities.append(entity)
        attack_types.append(etype)
        attack_techniques.append(techniques)
        attack_tokens.append(token)
    df["attack_ics_matched_entity"] = attack_entities
    df["attack_ics_entity_type"] = attack_types
    df["attack_ics_technique_ids"] = attack_techniques
    df["attack_ics_matched_token"] = attack_tokens

    return df
