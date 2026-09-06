"""
Fetch CISA ICS advisories via the ICS Advisory Project (ODbL v1.0).

Source: https://github.com/icsadvprj/ICS-Advisory-Project
The project publishes one CSV per advisory batch under ICS-CERT_ADV/. We pull
the GitHub repo file listing via the API, download every CSV, and concatenate.

Attribution requirement (ODbL v1.0): any release built from this data must
credit "ICS Advisory Project (https://github.com/icsadvprj/ICS-Advisory-Project)".
"""
from __future__ import annotations
import io
import re
import requests
import pandas as pd

API_LIST_URL = (
    "https://api.github.com/repos/icsadvprj/ICS-Advisory-Project/contents/ICS-CERT_ADV"
)
RAW_BASE = "https://raw.githubusercontent.com/icsadvprj/ICS-Advisory-Project/main/ICS-CERT_ADV/"


def list_advisory_csv_files(session: requests.Session) -> list[str]:
    resp = session.get(API_LIST_URL, timeout=30)
    resp.raise_for_status()
    return [item["name"] for item in resp.json() if item["name"].endswith(".csv")]


def fetch_all(session: requests.Session | None = None) -> pd.DataFrame:
    session = session or requests.Session()
    session.headers.update({"User-Agent": "ong-ot-dataset-pipeline/1.0"})

    frames = []
    for name in list_advisory_csv_files(session):
        resp = session.get(RAW_BASE + name, timeout=30)
        resp.raise_for_status()
        try:
            df = pd.read_csv(io.StringIO(resp.text))
            df["__source_file"] = name
            frames.append(df)
        except Exception as e:  # noqa: BLE001 - log and continue, one bad file shouldn't kill the run
            print(f"WARN: could not parse {name}: {e}")

    if not frames:
        raise RuntimeError("No advisory CSVs fetched — check network access and repo path.")

    combined = pd.concat(frames, ignore_index=True)
    # Normalize the CVE column name if it varies across file versions.
    for candidate in ("CVE", "CVE ID", "CVE_ID", "CVE_Number", "CVEs"):
        if candidate in combined.columns:
            combined = combined.rename(columns={candidate: "cve_id"})
            break
    if "cve_id" not in combined.columns:
        raise RuntimeError("Advisory CSVs do not contain a recognized CVE column.")

    def extract_cve_ids(value: object) -> list[object]:
        matches = re.findall(r"CVE[-\s]+(\d{4})[-\s]+(\d{4,})", str(value), re.IGNORECASE)
        return [f"CVE-{year}-{number}" for year, number in matches] or [pd.NA]

    combined["cve_id"] = combined["cve_id"].map(extract_cve_ids)
    return combined.explode("cve_id", ignore_index=True)


if __name__ == "__main__":
    df = fetch_all()
    print(df.shape, "rows x cols")
    df.to_csv("data/raw/ics_advisories.csv", index=False)
