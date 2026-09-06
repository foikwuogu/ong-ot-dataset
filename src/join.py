"""
Join ICS advisories with KEV, EPSS, and Vulnrichment on cve_id, then apply the
three client-owned config files (product class, no-patch rule, compensating
controls) to produce the final ONG-OT Vulnerability Prioritization row set.

This module is deliberately dumb about the three config-driven fields: it
applies whatever is in config/*.yaml literally, and leaves a column
'unmapped' / weight 0.0 / "unmapped — needs review" wherever the config
doesn't cover a row. It does not invent taxonomy, no-patch judgment, or
control mappings — see README.md, "Division of labor."
"""
from __future__ import annotations
import re
import yaml
import pandas as pd


def load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def apply_product_class(row: pd.Series, taxonomy: dict) -> tuple[str, float]:
    """Match the advisory's Vendor field against each class's vendor list.

    Case-insensitive substring match, so a taxonomy entry of "Schneider"
    matches an advisory Vendor value of "Schneider Electric SE" as well as
    an exact "Schneider".
    """
    vendor = str(row.get("Vendor", "")).strip().lower()
    for class_name, spec in taxonomy.get("classes", {}).items():
        vendor_list = spec.get("vendors", spec.get("vendors_products", []))
        for candidate in vendor_list:
            if candidate and candidate.lower() in vendor:
                return class_name, spec.get("weight", 0.0)
    return "unmapped", taxonomy.get("unmapped_default_weight", 0.0)


def apply_no_patch_flag(row: pd.Series, rules: dict) -> bool:
    """Evaluate the no_patch rule list. Any single trigger firing = True.

    - advisory_contains: substring match (case-insensitive) against the
      advisory's Mitigation + Remediation text.
    - vendor_status / cve_status: substring match against a 'Vendor Status' /
      'CVE Status' column if the advisory data provides one. Both are absent
      from the ICS Advisory Project CSV as of this pipeline version, so these
      two triggers are evaluated but will simply never fire until such a
      column is joined in — they are not silently skipped, just inert on
      today's source data.
    """
    text = (str(row.get("Mitigation", "")) + " " + str(row.get("Remediation", ""))).lower()
    vendor_status = str(row.get("Vendor Status", "")).lower()
    cve_status = str(row.get("CVE Status", "")).lower()

    for trigger in rules.get("no_patch", []):
        if "advisory_contains" in trigger:
            if any(p.lower() in text for p in trigger["advisory_contains"]):
                return True
        if "vendor_status" in trigger:
            if any(p.lower() in vendor_status for p in trigger["vendor_status"]):
                return True
        if "cve_status" in trigger:
            if any(p.lower() in cve_status for p in trigger["cve_status"]):
                return True
    return False


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


def build_dataset(
    advisories: pd.DataFrame,
    kev: pd.DataFrame,
    epss: pd.DataFrame,
    vulnrichment: pd.DataFrame,
    taxonomy: dict,
    no_patch_rules: dict,
    compensating_controls: dict,
) -> pd.DataFrame:
    df = advisories.copy()

    kev_slim = kev[["cve_id"]].drop_duplicates().assign(known_exploited=True) if "cve_id" in kev.columns else pd.DataFrame(columns=["cve_id", "known_exploited"])
    df = df.merge(kev_slim, on="cve_id", how="left")
    df["known_exploited"] = df["known_exploited"].fillna(False)

    if "cve_id" in epss.columns:
        df = df.merge(epss[["cve_id", "epss", "percentile"]], on="cve_id", how="left")

    if "cve_id" in vulnrichment.columns:
        df = df.merge(vulnrichment, on="cve_id", how="left")

    product_classes, weights = [], []
    for _, row in df.iterrows():
        cls, w = apply_product_class(row, taxonomy)
        product_classes.append(cls)
        weights.append(w)
    df["ong_product_class"] = product_classes
    df["ong_product_weight"] = weights

    df["no_patch_available"] = [apply_no_patch_flag(row, no_patch_rules) for _, row in df.iterrows()]

    controls, reductions = [], []
    for _, row in df.iterrows():
        c, r = apply_compensating_control(row, compensating_controls)
        controls.append(c)
        reductions.append(r)
    df["cpg2_applicable_controls"] = controls
    df["cpg2_combined_risk_reduction"] = reductions

    return df
