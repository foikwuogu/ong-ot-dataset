"""
Fetch CISA Vulnrichment (ADP enrichment: CVSS, CWE, SSVC) per CVE.

Source: https://github.com/cisagov/vulnrichment
Layout: one JSON file per CVE, path-sharded by CVE year and the first digits
of the number, sitting directly at the repo root — e.g.
2024/3xxx/CVE-2024-3400.json. Confirmed 2026-09-11 by fetching that exact
path and inspecting its contents (containers.cna.solutions/workarounds
present, as expected for a KEV-listed CVE).

Because this repo is large, we only pull records for the CVE IDs the advisory
join already needs, fetched directly from the raw content CDN
(raw.githubusercontent.com) rather than the GitHub REST API. This matters:
raw.githubusercontent.com is NOT the api.github.com "get contents" endpoint
and is not subject to the 60/hour (unauthenticated) or 5,000/hour
(authenticated) GitHub API rate limits, and does not need or reliably accept
a GitHub API Bearer token — never send an Authorization header on these
requests.

TWO REAL BUGS, ONE SYMPTOM — both produced `vulnrichment_remediation_text_
present_pct = 0.0` across all 27,924 rows on real `--full` runs, and had to
be found one at a time because fixing the first didn't change the symptom:

1. (Fixed 2026-09-10.) The GitHub Actions job token was sent as an
   `Authorization: Bearer` header to raw.githubusercontent.com (inherited
   from code written for the api.github.com contents endpoint, then pointed
   at RAW_BASE without removing the header) — that host doesn't want it.
   Removed. This did NOT fix the 0.0% result on the next real run, because:

2. (Fixed 2026-09-11.) `_shard_path()` built paths with an extra `cves/`
   prefix — `cves/2024/3xxx/CVE-2024-3400.json` — that does not exist in the
   real repository; every single request 404'd regardless of the header.
   The correct path has no `cves/` segment. This was never caught in
   `--demo` testing (which reads a local fixture, no HTTP involved) and
   wasn't verified against the live repo before the first real `--full` run
   — see LIMITATIONS.md item 2 for the full incident writeup and the lesson
   (verify the *exact* real URL against the live source before trusting a
   fetch module, not just its response schema).

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
    # NOTE: no "cves/" prefix -- the real repo shards directly at the root,
    # e.g. 2024/3xxx/CVE-2024-3400.json, NOT cves/2024/3xxx/CVE-2024-3400.json.
    # See the module docstring for how this was confirmed and why the
    # 2026-09-10/11 fix attempts (removing the Authorization header) didn't
    # actually fix the 0-row result on their own.
    return f"{year}/{shard}/{cve_id.upper()}.json"


def _join_texts(entries: list) -> str:
    """CVE 5.0 solutions/workarounds are lists of {lang, value} objects."""
    if not entries:
        return ""
    return " / ".join(str(e.get("value", "")) for e in entries if isinstance(e, dict) and e.get("value"))


def fetch_for_cves(cve_ids: list[str], session: requests.Session | None = None) -> pd.DataFrame:
    session = session or requests.Session()
    # Deliberately NO Authorization header: this hits raw.githubusercontent.com
    # (public CDN, no auth needed or wanted) not the api.github.com contents
    # endpoint. Sending a GitHub API token here previously broke every fetch
    # silently — see the module docstring for the 2026-09-10 incident.
    session.headers.update({"User-Agent": "ong-ot-dataset-pipeline/1.1"})

    rows = []
    non_200_count = 0
    for cve_id in cve_ids:
        path = _shard_path(cve_id)
        if path is None:
            continue
        resp = session.get(RAW_BASE + path, timeout=20)
        if resp.status_code != 200:
            non_200_count += 1
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

    total = len(cve_ids)
    if total:
        import sys
        fetched_pct = 100.0 * len(rows) / total
        print(
            f"[fetch_vulnrichment] {len(rows)}/{total} CVE records fetched "
            f"({fetched_pct:.1f}%), {non_200_count} non-200 responses.",
            file=sys.stderr,
        )
        if fetched_pct < 20.0:
            print(
                "[fetch_vulnrichment] WARNING: fetch success rate is very low. "
                "This usually means requests are being rejected outright (e.g. "
                "an unwanted Authorization header, a changed branch name, or a "
                "network block) rather than genuinely-missing enrichment for "
                "each CVE. Do not trust a near-zero remediation_text_present "
                "rate until this is investigated.",
                file=sys.stderr,
            )

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
