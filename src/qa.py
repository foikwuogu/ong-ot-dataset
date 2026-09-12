"""
Compute QA report + stats.json for a built ONG-OT dataset.

NEW IN v1.1: v1.0 shipped no QA report and no stats file at all — every
number in the README or Zenodo description had to be hand-typed and could
silently drift from the actual data. This module writes both, from the
dataset alone, so no number downstream can disagree with what the pipeline
actually computed (see docs/BUILD_SPEC.md, "the stats-file rule").
"""
from __future__ import annotations
import json
from datetime import datetime, timezone

import pandas as pd


def _rate(numerator: int, denominator: int) -> float:
    return round(100.0 * numerator / denominator, 2) if denominator else 0.0


def build_qa_report(df: pd.DataFrame, source_counts: dict) -> str:
    lines = [f"QA report generated {datetime.now(timezone.utc).date().isoformat()}"]
    for name, count in source_counts.items():
        lines.append(f"Source rows: {name} = {count}")

    n = len(df)
    lines.append(f"\nTotal joined rows (one row = one CVE-advisory pair): {n}")

    epss_matched = int(df["epss"].notna().sum()) if "epss" in df.columns else 0
    lines.append(f"EPSS join: {epss_matched} of {n} rows matched a current EPSS score ({_rate(epss_matched, n)}%)")

    kev_matched = int(df["known_exploited"].sum()) if "known_exploited" in df.columns else 0
    lines.append(f"KEV join: {kev_matched} of {n} rows are in the CISA KEV catalog ({_rate(kev_matched, n)}%)")

    remediation_present = int(df["vulnrichment_remediation_text_present"].sum()) if "vulnrichment_remediation_text_present" in df.columns else 0
    remediation_pct = _rate(remediation_present, n)
    lines.append(
        f"Vulnrichment CNA solutions/workarounds text present: {remediation_present} of {n} rows "
        f"({remediation_pct}%) — the rest are coded no_patch_basis="
        "'no_remediation_text_captured', not assumed patched (see LIMITATIONS.md)"
    )
    if n and remediation_pct < 5.0:
        lines.append(
            f"  *** QA FLAG: {remediation_pct}% is implausibly low for a real --full run "
            "(a near-zero rate on real data usually means every fetch request failed, e.g. "
            "an unwanted auth header or blocked host, not that enrichment is genuinely absent "
            "for nearly every CVE — check src/fetch_vulnrichment.py's stderr output for this run "
            "before trusting no_patch_available on this dataset)."
        )

    lines.append("\nProduct class distribution:")
    if "ong_product_class" in df.columns:
        for cls, count in df["ong_product_class"].value_counts().items():
            lines.append(f"  {cls}: {count}")

    lines.append("\nNo-patch determination basis:")
    if "no_patch_basis" in df.columns:
        for basis, count in df["no_patch_basis"].value_counts().items():
            lines.append(f"  {basis}: {count}")
    if "no_patch_available" in df.columns:
        lines.append(f"no_patch_available = True: {int(df['no_patch_available'].sum())} of {n} rows")

    lines.append("\nCPG 2.0 compensating-control coverage:")
    if "cpg2_applicable_controls" in df.columns:
        mapped = int((df["cpg2_applicable_controls"] != "unmapped — needs review").sum())
        lines.append(f"  rows with at least one applicable control: {mapped} of {n} ({_rate(mapped, n)}%)")

    lines.append("\nATT&CK for ICS group/software matches:")
    if "attack_ics_matched_entity" in df.columns:
        matched_mask = df["attack_ics_matched_entity"] != ""
        matched = int(matched_mask.sum())
        match_pct = _rate(matched, n)
        lines.append(f"  rows matched to a named group/software: {matched} of {n} ({match_pct}%)")
        if n and match_pct > 15.0:
            lines.append(
                f"  *** QA FLAG: {match_pct}% is far above what a literal name-in-description "
                "match against ICS-specific threat profiles should produce (see LIMITATIONS.md, "
                "which expected this to be rare). Check the matched-token column below for each "
                "top entity before trusting this — a short, coincidentally-shared word (e.g. "
                "'card' matching a payment-fraud group's description) is a likelier explanation "
                "than genuine ICS threat-actor overlap."
            )
        if matched:
            lines.append("  matched entities (top 10, with an example triggering token):")
            has_token_col = "attack_ics_matched_token" in df.columns
            for name, count in df.loc[matched_mask, "attack_ics_matched_entity"].value_counts().head(10).items():
                token_note = ""
                if has_token_col:
                    tokens = df.loc[matched_mask & (df["attack_ics_matched_entity"] == name), "attack_ics_matched_token"].unique()
                    token_note = f" — matched token(s): {', '.join(sorted(t for t in tokens if t)[:5])}"
                lines.append(f"    {name}: {count}{token_note}")

    if "cvss_v3_base" in df.columns or "Cumulative_CVSS" in df.columns:
        cvss_col = "cvss_v3_base" if "cvss_v3_base" in df.columns else "Cumulative_CVSS"
        cvss = pd.to_numeric(df[cvss_col], errors="coerce")
        violations = int(((cvss < 0) | (cvss > 10)).sum())
        lines.append(f"\nRange check CVSS in [0,10]: {violations} violations")
    if "epss" in df.columns:
        epss = pd.to_numeric(df["epss"], errors="coerce")
        violations = int(((epss < 0) | (epss > 1)).sum())
        lines.append(f"Range check EPSS in [0,1]: {violations} violations")

    lines.append("\nNamed spot checks (verify against the ICSA number's page on cisa.gov):")
    spot_cols = [c for c in ["cve_id", "ICS-CERT_Number", "Vendor", "Product", "ong_product_class", "no_patch_available", "known_exploited"] if c in df.columns]
    if spot_cols and n:
        sample_n = min(5, n)
        for _, row in df.sample(n=sample_n, random_state=42).iterrows():
            lines.append("  " + " | ".join(f"{c}={row.get(c)}" for c in spot_cols))

    return "\n".join(lines) + "\n"


def build_stats(df: pd.DataFrame, version: str, source_meta: dict) -> dict:
    n = len(df)
    stats = {
        "dataset_version": version,
        "build_date_utc": datetime.now(timezone.utc).isoformat(),
        "row_count": n,
        "epss_match_rate_pct": _rate(int(df["epss"].notna().sum()), n) if "epss" in df.columns and n else 0.0,
        "kev_match_count": int(df["known_exploited"].sum()) if "known_exploited" in df.columns else 0,
        "vulnrichment_remediation_text_present_pct": _rate(
            int(df["vulnrichment_remediation_text_present"].sum()), n
        ) if "vulnrichment_remediation_text_present" in df.columns and n else 0.0,
        "no_patch_available_count": int(df["no_patch_available"].sum()) if "no_patch_available" in df.columns else 0,
        "ong_product_class_counts": df["ong_product_class"].value_counts().to_dict() if "ong_product_class" in df.columns else {},
        "attack_ics_matched_row_count": int((df["attack_ics_matched_entity"] != "").sum()) if "attack_ics_matched_entity" in df.columns else 0,
        "source_meta": source_meta,
    }
    return stats


def write_qa_and_stats(df: pd.DataFrame, source_counts: dict, version: str, source_meta: dict,
                        qa_path: str, stats_path: str) -> None:
    with open(qa_path, "w", encoding="utf-8") as f:
        f.write(build_qa_report(df, source_counts))
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(build_stats(df, version, source_meta), f, indent=2, default=str)
