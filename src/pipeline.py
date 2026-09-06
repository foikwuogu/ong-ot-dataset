"""
Orchestrates: fetch all sources -> join -> write versioned output + manifest.

Usage:
    python src/pipeline.py --full --version v1.0
    python src/pipeline.py --demo            # uses data/raw/sample_* fixtures only
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))

import pandas as pd
import fetch_ics_advisories
import fetch_kev
import fetch_epss
import fetch_vulnrichment
import fetch_attack_ics
import join as join_mod


def run_full(version: str) -> None:
    print("Fetching ICS advisories (ICS Advisory Project)...")
    advisories = fetch_ics_advisories.fetch_all()

    print("Fetching CISA KEV catalog...")
    kev = fetch_kev.fetch_all()

    cve_ids = advisories["cve_id"].dropna().unique().tolist() if "cve_id" in advisories.columns else []

    print(f"Fetching EPSS scores for {len(cve_ids)} CVEs...")
    epss = fetch_epss.fetch_for_cves(cve_ids)

    print(f"Fetching Vulnrichment enrichment for {len(cve_ids)} CVEs...")
    vulnrichment = fetch_vulnrichment.fetch_for_cves(cve_ids)

    print("Fetching MITRE ATT&CK for ICS technique list...")
    attack_ics = fetch_attack_ics.fetch_techniques()
    attack_ics.to_csv("data/raw/attack_ics_techniques.csv", index=False)

    _finish(advisories, kev, epss, vulnrichment, version, mode="full")


def run_demo(version: str) -> None:
    print("Running in --demo mode: using fixtures in data/raw/sample_*, no network calls.")
    advisories = pd.read_csv("data/raw/sample_advisories.csv")
    kev = pd.read_csv("data/raw/sample_kev.csv")
    epss = pd.read_csv("data/raw/sample_epss.csv")
    vulnrichment = pd.read_csv("data/raw/sample_vulnrichment.csv")
    _finish(advisories, kev, epss, vulnrichment, version, mode="demo")


def _finish(advisories, kev, epss, vulnrichment, version, mode):
    taxonomy = join_mod.load_yaml("config/product_class_taxonomy.yaml")
    no_patch_rules = join_mod.load_yaml("config/no_patch_rules.yaml")
    compensating_controls = join_mod.load_yaml("config/compensating_controls_cpg2.yaml")

    dataset = join_mod.build_dataset(
        advisories, kev, epss, vulnrichment, taxonomy, no_patch_rules, compensating_controls
    )

    os.makedirs("data/processed", exist_ok=True)
    out_csv = f"data/processed/ong_ot_dataset_{version}.csv"
    dataset.to_csv(out_csv, index=False)

    manifest = {
        "dataset_version": version,
        "run_mode": mode,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "row_count": len(dataset),
        "sources": {
            "ics_advisories": "https://github.com/icsadvprj/ICS-Advisory-Project (ODbL v1.0)",
            "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "epss": "https://api.first.org/data/v1/epss",
            "vulnrichment": "https://github.com/cisagov/vulnrichment",
            "attack_ics": "https://github.com/mitre-attack/attack-stix-data/tree/master/ics-attack",
        },
        "author": "Friday Ogochukwu Ikwuogu (ORCID 0009-0009-2222-1318)",
        "license": "ODbL v1.0, attribution to ICS Advisory Project required",
        "note_if_demo": "Fixture-only run — NOT the real dataset. Re-run with --full on a networked machine." if mode == "demo" else None,
    }
    manifest_path = f"data/processed/ong_ot_dataset_{version}_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"Wrote {out_csv} ({len(dataset)} rows)")
    print(f"Wrote {manifest_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", action="store_true", help="Fetch live data from all sources")
    parser.add_argument("--demo", action="store_true", help="Use bundled fixtures only, no network")
    parser.add_argument("--version", default="v1.0")
    args = parser.parse_args()

    if args.full:
        run_full(args.version)
    elif args.demo:
        run_demo(args.version)
    else:
        parser.error("Pass --full (live fetch) or --demo (fixtures only).")
