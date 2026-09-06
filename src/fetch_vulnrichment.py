"""
Fetch CISA Vulnrichment (ADP enrichment: CVSS, CWE, SSVC) per CVE.

Source: https://github.com/cisagov/vulnrichment
Layout: one JSON file per CVE, path-sharded by CVE year and the first digits
of the number, e.g. cves/2024/21xxx/CVE-2024-21762.json.

Because this repo is large, we only pull records for the CVE IDs the advisory
join already needs, using the GitHub API's "get contents" endpoint per file.
Unauthenticated GitHub API calls are rate-limited (60/hour); for a full run,
set a GITHUB_TOKEN environment variable to raise that to 5,000/hour.
"""
from __future__ import annotations
import os
import re
import requests
import pandas as pd

RAW_BASE = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/"


def _shard_path(cve_id: str) -> str | None:
    m = re.match(r"CVE-(\d{4})-(\d+)$", cve_id.strip().upper())
    if not m:
        return None
    year, number = m.groups()
    shard = number[:-3] + "xxx" if len(number) > 3 else "0xxx"
    return f"cves/{year}/{shard}/{cve_id.upper()}.json"


def fetch_for_cves(cve_ids: list[str], session: requests.Session | None = None) -> pd.DataFrame:
    session = session or requests.Session()
    headers = {"User-Agent": "ong-ot-dataset-pipeline/1.0"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    session.headers.update(headers)

    rows = []
    for cve_id in cve_ids:
        path = _shard_path(cve_id)
        if path is None:
            continue
        resp = session.get(RAW_BASE + path, timeout=20)
        if resp.status_code != 200:
            continue  # no ADP enrichment published for this CVE yet
        try:
            record = resp.json()
        except ValueError:
            continue
        adp = record.get("containers", {}).get("adp", [])
        cvss = None
        ssvc = None
        for entry in adp:
            for metric in entry.get("metrics", []):
                if "cvssV3_1" in metric:
                    cvss = metric["cvssV3_1"].get("baseScore")
                if "other" in metric and metric["other"].get("type") == "ssvc":
                    ssvc = metric["other"].get("content", {}).get("options")
        rows.append({"cve_id": cve_id, "vulnrichment_cvss": cvss, "vulnrichment_ssvc": ssvc})

    return pd.DataFrame(rows)


if __name__ == "__main__":
    import sys
    cve_list = sys.argv[1:] or ["CVE-2024-21762"]
    df = fetch_for_cves(cve_list)
    print(df)
