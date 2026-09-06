"""
Fetch EPSS (Exploit Prediction Scoring System) scores from FIRST.org.

Source: https://api.first.org/data/v1/epss
No auth required. The API paginates; we page through with `offset`/`limit`,
or (more efficiently) fetch the full daily CSV snapshot at
https://epss.empiricalsecurity.com/epss_scores-current.csv.gz when the CVE
list to score is large. This script supports both modes.
"""
from __future__ import annotations
import gzip
import io
import requests
import pandas as pd

BULK_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
API_URL = "https://api.first.org/data/v1/epss"


def fetch_bulk(session: requests.Session | None = None) -> pd.DataFrame:
    """Full daily snapshot — use this when scoring the whole advisory set."""
    session = session or requests.Session()
    session.headers.update({"User-Agent": "ong-ot-dataset-pipeline/1.0"})
    resp = session.get(BULK_URL, timeout=60)
    resp.raise_for_status()
    raw = gzip.decompress(resp.content).decode("utf-8")
    # First line is a comment with the snapshot date; pandas needs it skipped.
    lines = raw.splitlines()
    header_idx = next(i for i, l in enumerate(lines) if l.startswith("cve,"))
    df = pd.read_csv(io.StringIO("\n".join(lines[header_idx:])))
    df = df.rename(columns={"cve": "cve_id"})
    return df


def fetch_for_cves(cve_ids: list[str], session: requests.Session | None = None) -> pd.DataFrame:
    """Targeted lookup — use this for a short, known CVE list."""
    session = session or requests.Session()
    session.headers.update({"User-Agent": "ong-ot-dataset-pipeline/1.0"})
    frames = []
    batch_size = 100
    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i : i + batch_size]
        resp = session.get(API_URL, params={"cve": ",".join(batch)}, timeout=30)
        resp.raise_for_status()
        data = resp.json().get("data", [])
        if data:
            frames.append(pd.DataFrame(data))
    if not frames:
        return pd.DataFrame(columns=["cve_id", "epss", "percentile"])
    df = pd.concat(frames, ignore_index=True)
    return df.rename(columns={"cve": "cve_id"})


if __name__ == "__main__":
    df = fetch_bulk()
    print(df.shape, "rows x cols")
    df.to_csv("data/raw/epss.csv", index=False)
