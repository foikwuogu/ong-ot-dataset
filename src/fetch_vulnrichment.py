"""
Fetch CISA Vulnrichment (ADP enrichment: CVSS, CWE, SSVC) per CVE.

Source: https://github.com/cisagov/vulnrichment
Layout: one JSON file per CVE, path-sharded by CVE year and the first digits
of the number, e.g. cves/2024/21xxx/CVE-2024-21762.json.

Because this repo is large, we only pull records for the CVE IDs the advisory
join already needs, using the GitHub API's "get contents" endpoint per file.
Unauthenticated GitHub API calls are rate-limited (60/hour); for a full run,
set a GITHUB_TOKEN environment variable to raise that to 5,000/hour.

CHANGED IN v1.1: the file served at this path is the FULL CVE Record (CNA
container as originally submitted, plus CISA's own ADP container appended) —
not just CISA's enrichment. v1.0 only read the `adp` container. v1.1 also
reads `containers.cna.solutions` and `containers.cna.workarounds` — the
vendor/CNA's own published remediation text, when one was supplied — because
no_patch_rules.yaml v1.1 needs real text to match against (v1.0's
`Mitigation`/`Remediation` columns never existed in the real ICS Advisory
Project source; see no_patch_rules.yaml for the full explanation). Coverage
is real but partial: many CVE records carry no `solutions`/`workarounds`
field at all. That is recorded as missing, not coerced into a patched/
unpatched guess — see `vulnrichment_remediation_text_present` below and
LIMITATIONS.md.
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


def _join_texts(entries: list) -> str:
    """CVE 5.0 solutions/workarounds are lists of {lang, value} objects."""
    if not entries:
        return ""
    return " / ".join(str(e.get("value", "")) for e in entries if isinstance(e, dict) and e.get("value"))


def fetch_for_cves(cve_ids: list[str], session: requests.Session | None = None) -> pd.DataFrame:
    session = session or requests.Session()
    headers = {"User-Agent": "ong-ot-dataset-pipeline/1.1"}
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

        containers = record.get("containers", {})
        adp = containers.get("adp", [])
        cvss = None
        ssvc = None
        for entry in adp:
            for metric in entry.get("metrics", []):
                if "cvssV3_1" in metric:
                    cvss = metric["cvssV3_1"].get("baseScore")
                if "other" in metric and metric["other"].get("type") == "ssvc":
                    ssvc = metric["other"].get("content", {}).get("options")

        cna = containers.get("cna", {})
        solutions_text = _join_texts(cna.get("solutions", []))
        workarounds_text = _join_texts(cna.get("workarounds", []))
        remediation_text = " / ".join(t for t in (solutions_text, workarounds_text) if t)

        rows.append({
            "cve_id": cve_id,
            "vulnrichment_cvss": cvss,
            "vulnrichment_ssvc": ssvc,
            "vulnrichment_cna_solutions": solutions_text,
            "vulnrichment_cna_workarounds": workarounds_text,
            "vulnrichment_remediation_text": remediation_text,
            "vulnrichment_remediation_text_present": bool(remediation_text),
        })

    if not rows:
        return pd.DataFrame(columns=[
            "cve_id", "vulnrichment_cvss", "vulnrichment_ssvc",
            "vulnrichment_cna_solutions", "vulnrichment_cna_workarounds",
            "vulnrichment_remediation_text", "vulnrichment_remediation_text_present",
        ])
    return pd.DataFrame(rows)


if __name__ == "__main__":
    import sys
    cve_list = sys.argv[1:] or ["CVE-2024-21762"]
    df = fetch_for_cves(cve_list)
    print(df)
