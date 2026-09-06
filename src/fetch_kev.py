"""
Fetch the CISA Known Exploited Vulnerabilities (KEV) catalog.

Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
License: public domain (US government work).
"""
from __future__ import annotations
import requests
import pandas as pd

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_all(session: requests.Session | None = None) -> pd.DataFrame:
    session = session or requests.Session()
    session.headers.update({"User-Agent": "ong-ot-dataset-pipeline/1.0"})
    resp = session.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    payload = resp.json()
    df = pd.DataFrame(payload["vulnerabilities"])
    df = df.rename(columns={"cveID": "cve_id"})
    df["kev_catalog_version"] = payload.get("catalogVersion")
    df["kev_date_released"] = payload.get("dateReleased")
    return df


if __name__ == "__main__":
    df = fetch_all()
    print(df.shape, "rows x cols")
    df.to_csv("data/raw/kev.csv", index=False)
