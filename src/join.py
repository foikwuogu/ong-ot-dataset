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
}


def _distinctive_tokens(text: str) -> list[str]:
    tokens = re.findall(r"[a-z0-9\-]{4,}", str(text or "").lower())
    return [t for t in tokens if t not in _GENERIC_TOKENS]


def apply_attack_ics_match(product: str, entity_index: list[tuple[str, str, str, str]]) -> tuple[str, str, str, str]:
    """Tag with any ATT&CK for ICS group/software whose own STIX description
    contains a distinctive token from this row's Product text.

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

    This stays intentionally conservative even so: ATT&CK for ICS techniques
    describe tradecraft against asset classes, not specific CVEs, so the
    only defensible per-row join is a literal name match against a group's
    or software's own published description. Most rows will not match —
    that reflects the real, narrow overlap between named ATT&CK for ICS
    group/software profiles and the ONG OT product landscape, not a
    pipeline defect (see LIMITATIONS.md).

    Returns (attack_matched_entity, attack_entity_type, attack_technique_ids,
    attack_matched_token), or ("", "", "", "") when nothing matches. The
    matched token is returned specifically so a run's QA report can show
    *why* a match fired instead of just *that* it fired — see the
    2026-09 finding in LIMITATIONS.md: real full-run output surfaced
    non-ICS entities (FIN7, REvil, Conficker) in the top matches, which the
    7-row demo fixture was too small to ever catch, and which cannot be
    diagnosed from the entity name alone. Callers should memoize by
    product — see build_dataset — since the same value repeats across many
    rows.
    """
    tokens = _distinctive_tokens(product)
    if not tokens or not entity_index:
        return "", "", "", ""
    for description, name, entity_type, technique_ids in entity_index:
        for token in tokens:
            if token in description:
                return name, entity_type, technique_ids, token
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
