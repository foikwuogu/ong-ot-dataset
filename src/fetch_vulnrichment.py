"""
Fetch CISA Vulnrichment (ADP enrichment: CVSS, CWE, SSVC) per CVE.

Source: https://github.com/cisagov/vulnrichment
Layout: one JSON file per CVE, path-sharded by CVE year and the first digits
of the number, e.g. cves/2024/21xxx/CVE-2024-21762.json.

Because this repo is large, we only pull records for the CVE IDs the advisory
join already needs, fetched directly from the raw content CDN
(raw.githubusercontent.com) rather than the GitHub REST API. This matters:
raw.githubusercontent.com is NOT the api.github.com "get contents" endpoint,
is not subject to the 60/hour (unauthenticated) or 5,000/hour (authenticated)
GitHub API rate limits, and — this is the bug fixed here — does not reliably
accept a GitHub API Bearer token the way api.github.com does. A real v1.1
`--full` run on 2026-09-10 sent the GitHub Actions job token
(`${{ github.token }}`) as an `Authorization: Bearer` header on every one of
these requests (inherited from code written for the api.github.com contents
endpoint, then pointed at RAW_BASE without removing the header), and got
`vulnrichment_remediation_text_present_pct = 0.0` across all 27,924 rows —
i.e. every single fetch silently failed non-200 and was swallowed by the
`continue` below. raw.githubusercontent.com serves public-repo content with
no authentication required at all, so the header was pure downside. FIX:
never send an Authorization header on these requests. If GitHub ever
rate-limits this CDN path in practice, the real fix is to switch to the
actual api.github.com contents endpoint (base64-decode the response) — not
to keep sending a token this endpoint doesn't want.

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
    return f"cves/{year}/{shard}/{cve_id.upper()}.json"


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
