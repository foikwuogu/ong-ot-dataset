"""
Orchestrates: fetch all sources -> save raw + provenance -> join -> write
versioned output + manifest + QA report + stats.

Usage:
    python src/pipeline.py --full --version v1.1
    python src/pipeline.py --demo            # uses data/raw/sample_* fixtures only

CHANGED IN v1.1: v1.0's --full run never wrote its raw fetches to disk (only
the ATT&CK technique list was saved) and never logged provenance beyond a
single fixed PROVENANCE.txt for the demo fixtures — so a v1.0 --full run was
not actually reproducible from a committed record of what was fetched, only
from re-running the fetch again on a later day against whatever the sources
say then. v1.1 saves every raw fetch to data/raw/ and appends a provenance
line (filename, bytes, SHA-256, source URL, access date) for each, and writes
data/processed/qa_report.txt + report/stats.json (see src/qa.py).
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
import qa as qa_mod

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import provenance as provenance_mod

SOURCE_URLS = {
    "ics_advisories": "https://github.com/icsadvprj/ICS-Advisory-Project (ODbL v1.0)",
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "vulnrichment": "https://github.com/cisagov/vulnrichment",
    "attack_ics": "https://github.com/mitre-attack/attack-stix-data/tree/master/ics-attack",
}


def _save_and_log(df: pd.DataFrame, path: str, source_key: str, provenance_log: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    df.to_csv(path, index=False)
    provenance_mod_note = f"source={source_key}"
    line = " | ".join([
        datetime.now(timezone.utc).date().isoformat(),
        os.path.basename(path),
        f"{os.path.getsize(path)} bytes",
        f"sha256:{provenance_mod.sha256(path)}",
        SOURCE_URLS.get(source_key, ""),
        provenance_mod_note,
    ])
    with open(provenance_log, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def run_full(version: str) -> None:
    os.makedirs("data/raw", exist_ok=True)
    provenance_log = "data/raw/PROVENANCE.txt"

    print("Fetching ICS advisories (ICS Advisory Project)...")
    advisories = fetch_ics_advisories.fetch_all()
    _save_and_log(advisories, f"data/raw/ics_advisories_{version}.csv", "ics_advisories", provenance_log)

    print("Fetching CISA KEV catalog...")
    kev = fetch_kev.fetch_all()
    _save_and_log(kev, f"data/raw/kev_{version}.csv", "kev", provenance_log)

    cve_ids = advisories["cve_id"].dropna().unique().tolist() if "cve_id" in advisories.columns else []

    print(f"Fetching EPSS scores for {len(cve_ids)} CVEs...")
    epss = fetch_epss.fetch_for_cves(cve_ids)
    _save_and_log(epss, f"data/raw/epss_{version}.csv", "epss", provenance_log)

    print(f"Fetching Vulnrichment enrichment for {len(cve_ids)} CVEs...")
    vulnrichment = fetch_vulnrichment.fetch_for_cves(cve_ids)
    _save_and_log(vulnrichment, f"data/raw/vulnrichment_{version}.csv", "vulnrichment", provenance_log)

    print("Fetching MITRE ATT&CK for ICS technique list and group/software profiles...")
    stix_bundle = fetch_attack_ics._fetch_bundle()
    attack_techniques = fetch_attack_ics.fetch_techniques(stix_bundle)
    groups_software = fetch_attack_ics.fetch_groups_and_software(stix_bundle)
    _save_and_log(attack_techniques, "data/raw/attack_ics_techniques.csv", "attack_ics", provenance_log)
    _save_and_log(groups_software, "data/raw/attack_ics_groups_software.csv", "attack_ics", provenance_log)

    source_counts = {
        "ics_advisories": len(advisories),
        "kev": len(kev),
        "epss": len(epss),
        "vulnrichment": len(vulnrichment),
        "attack_ics_techniques": len(attack_techniques),
        "attack_ics_groups_software": len(groups_software),
    }
    _finish(advisories, kev, epss, vulnrichment, groups_software, version, mode="full", source_counts=source_counts)


def run_demo(version: str) -> None:
    print("Running in --demo mode: using fixtures in data/raw/sample_*, no network calls.")
    advisories = pd.read_csv("data/raw/sample_advisories.csv")
    kev = pd.read_csv("data/raw/sample_kev.csv")
    epss = pd.read_csv("data/raw/sample_epss.csv")
    vulnrichment = pd.read_csv("data/raw/sample_vulnrichment.csv")
    groups_software = pd.read_csv("data/raw/sample_attack_groups_software.csv")
    source_counts = {
        "ics_advisories": len(advisories),
        "kev": len(kev),
        "epss": len(epss),
        "vulnrichment": len(vulnrichment),
        "attack_ics_groups_software": len(groups_software),
    }
    _finish(advisories, kev, epss, vulnrichment, groups_software, version, mode="demo", source_counts=source_counts)


def _finish(advisories, kev, epss, vulnrichment, groups_software, version, mode, source_counts):
    taxonomy = join_mod.load_yaml("config/product_class_taxonomy.yaml")
    no_patch_rules = join_mod.load_yaml("config/no_patch_rules.yaml")
    compensating_controls = join_mod.load_yaml("config/compensating_controls_cpg2.yaml")

    dataset = join_mod.build_dataset(
        advisories, kev, epss, vulnrichment, taxonomy, no_patch_rules, compensating_controls,
        groups_software=groups_software,
    )

    os.makedirs("data/processed", exist_ok=True)
    os.makedirs("report", exist_ok=True)
    out_csv = f"data/processed/ong_ot_dataset_{version}.csv"
    dataset.to_csv(out_csv, index=False)

    qa_path = "data/processed/qa_report.txt"
    stats_path = "report/stats.json"
    qa_mod.write_qa_and_stats(
        dataset, source_counts, version,
        source_meta={"mode": mode, "sources": SOURCE_URLS},
        qa_path=qa_path, stats_path=stats_path,
    )

    manifest = {
        "dataset_version": version,
        "run_mode": mode,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "row_count": len(dataset),
        "sources": SOURCE_URLS,
        "author": "Friday Ogochukwu Ikwuogu (ORCID 0009-0009-2222-1318)",
        "collaborators": ["Silas Abutu (Petroleum Training Institute)", "Abidemi Orimogunje (Redeemer's University)"],
        "license": "ODbL v1.0, attribution to ICS Advisory Project required",
        "note_if_demo": "Fixture-only run — NOT the real dataset. Re-run with --full on a networked machine." if mode == "demo" else None,
    }
    manifest_path = f"data/processed/ong_ot_dataset_{version}_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"Wrote {out_csv} ({len(dataset)} rows)")
    print(f"Wrote {manifest_path}")
    print(f"Wrote {qa_path}")
    print(f"Wrote {stats_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", action="store_true", help="Fetch live data from all sources")
    parser.add_argument("--demo", action="store_true", help="Use bundled fixtures only, no network")
    parser.add_argument("--version", default="v1.1")
    args = parser.parse_args()

    if args.full:
        run_full(args.version)
    elif args.demo:
        run_demo(args.version)
    else:
        parser.error("Pass --full (live fetch) or --demo (fixtures only).")
