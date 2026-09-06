"""
Fetch the MITRE ATT&CK for ICS technique matrix (STIX 2.1 bundle).

Source: https://github.com/mitre-attack/attack-stix-data/tree/master/ics-attack
License: MITRE ATT&CK content is released for public use under the Terms of
Use at https://attack.mitre.org/resources/terms-of-use/ (attribution required).

This dataset doesn't join to CVEs directly — ATT&CK for ICS techniques are
mapped in by CWE or by the compensating-control YAML you author (see
config/compensating_controls_cpg2.yaml). This script just pulls the technique
list so that mapping has something to point at.
"""
from __future__ import annotations
import requests
import pandas as pd

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/ics-attack/ics-attack.json"
)


def fetch_techniques(session: requests.Session | None = None) -> pd.DataFrame:
    session = session or requests.Session()
    session.headers.update({"User-Agent": "ong-ot-dataset-pipeline/1.0"})
    resp = session.get(STIX_URL, timeout=60)
    resp.raise_for_status()
    bundle = resp.json()

    rows = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext_id = next(
            (r["external_id"] for r in obj.get("external_references", [])
             if r.get("source_name") == "mitre-attack"),
            None,
        )
        rows.append(
            {
                "technique_id": ext_id,
                "name": obj.get("name"),
                "description": obj.get("description"),
                "tactic_phases": ", ".join(p["phase_name"] for p in obj.get("kill_chain_phases", [])),
            }
        )
    return pd.DataFrame(rows)


if __name__ == "__main__":
    df = fetch_techniques()
    print(df.shape, "rows x cols")
    df.to_csv("data/raw/attack_ics_techniques.csv", index=False)
