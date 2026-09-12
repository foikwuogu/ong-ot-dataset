#!/usr/bin/env python3
"""Python reimplementation of test_zenodo_sandbox.sh's API sequence -- avoids
a Windows-specific jq.exe bug (native Windows jq writes stdout in text mode,
which silently inserts \r before every \n, corrupting the JSON payload sent
to Zenodo). Makes the identical API calls, in the identical order, as
.github/workflows/publish-zenodo.yml's "Create or version Zenodo deposition"
and "Upload files to Zenodo" steps. See docs/PUBLISH_GUIDE.md.

IMPORTANT: Zenodo's `newversion` action only works on an ALREADY-PUBLISHED
record (it needs a persistent identifier to version). So the first run here
also PUBLISHES the fresh sandbox draft it creates -- safe, because this is
the sandbox: it mints a throwaway sandbox DOI with no connection to the real
production record 22503185. The script still refuses to run at all against
a non-sandbox ZENODO_API_URL (see the check below).

Usage:
  export ZENODO_ACCESS_TOKEN=...
  python scripts/test_zenodo_sandbox.py                  # first run: creates + publishes a draft
  python scripts/test_zenodo_sandbox.py <deposition_id>  # second run: tests newversion against it
"""
import json, os, sys, urllib.request, urllib.error

ZENODO_API_URL = os.environ.get("ZENODO_API_URL", "https://sandbox.zenodo.org/api")
if "sandbox" not in ZENODO_API_URL:
    print(f"REFUSING TO RUN: ZENODO_API_URL ({ZENODO_API_URL}) does not look like a sandbox host.", file=sys.stderr)
    sys.exit(1)

TOKEN = os.environ.get("ZENODO_ACCESS_TOKEN")
if not TOKEN:
    print("Set ZENODO_ACCESS_TOKEN to your sandbox token first (see docs/PUBLISH_GUIDE.md)", file=sys.stderr)
    sys.exit(1)

VERSION = os.environ.get("VERSION", "v1.1-sandbox-test")
EXISTING_RECORD_ID = sys.argv[1] if len(sys.argv) > 1 else None

REQUIRED_FILES = [
    "data/processed/ong_ot_dataset_v1.1.csv",
    "data/processed/ong_ot_dataset_v1.1_manifest.json",
    "data/processed/qa_report.txt",
    "report/stats.json",
]
for f in REQUIRED_FILES:
    if not os.path.isfile(f):
        print(f"Missing {f} -- run this from the repo root after a --full pipeline run.", file=sys.stderr)
        sys.exit(1)

print(f"== Zenodo API: {ZENODO_API_URL} ==")

def api_call(method, url, body_bytes=None, content_type=None, expect_json=True):
    headers = {"Authorization": f"Bearer {TOKEN}"}
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code} from {method} {url}:", file=sys.stderr)
        print(e.read().decode("utf-8", errors="replace"), file=sys.stderr)
        sys.exit(1)
    if not expect_json or not raw:
        return None
    return json.loads(raw)

if EXISTING_RECORD_ID:
    print(f"Creating a new version of sandbox record {EXISTING_RECORD_ID}...")
    newversion = api_call("POST", f"{ZENODO_API_URL}/deposit/depositions/{EXISTING_RECORD_ID}/actions/newversion")
    draft = api_call("GET", newversion["links"]["latest_draft"])
    deposition_id = draft["id"]
    bucket_url = draft["links"]["bucket"]
    carried_over = draft.get("files") or []
    print(f"New draft {deposition_id} carried over {len(carried_over)} file(s) from the previous version.")
    if carried_over:
        print("Removing carried-over files (this is the exact behavior under test)...")
        for file in carried_over:
            print(f"  removing {file['filename']} ({file['id']})")
            api_call("DELETE", f"{ZENODO_API_URL}/deposit/depositions/{deposition_id}/files/{file['id']}", expect_json=False)
else:
    print("No deposition id given -- creating a brand-new sandbox draft (this run's output")
    print("id becomes the argument for your second, newversion-testing run).")
    create_response = api_call("POST", f"{ZENODO_API_URL}/deposit/depositions", body_bytes=b"{}", content_type="application/json")
    deposition_id = create_response["id"]
    bucket_url = create_response["links"]["bucket"]

with open(".zenodo/description.html", "r", encoding="utf-8") as fh:
    description = fh.read()

metadata = {"metadata": {
    "title": f"ONG-OT Vulnerability Prioritization Dataset {VERSION} (SANDBOX TEST -- not for real use)",
    "upload_type": "dataset",
    "description": description,
    "creators": [{"name": "Friday Ogochukwu Ikwuogu", "orcid": "0009-0009-2222-1318",
                  "affiliation": "Independent Researcher, Odessa, Texas, USA"}],
    "access_right": "open",
    "license": "odbl-1.0",
    "version": VERSION,
}}
api_call("PUT", f"{ZENODO_API_URL}/deposit/depositions/{deposition_id}",
         body_bytes=json.dumps(metadata).encode("utf-8"), content_type="application/json")
print("Metadata set.")

print("Uploading files...")
for path in REQUIRED_FILES:
    name = os.path.basename(path)
    with open(path, "rb") as fh:
        data = fh.read()
    api_call("PUT", f"{bucket_url}/{name}", body_bytes=data, content_type="application/octet-stream")
    print(f"  uploaded {name}")

final = api_call("GET", f"{ZENODO_API_URL}/deposit/depositions/{deposition_id}")
n_files = len(final.get("files", []))

print()
print("== Result ==")
print(f"Sandbox deposition id: {deposition_id}")
print(f"Files now attached: {n_files} (should be exactly 4 -- this version's files only,")
print("  not this version's 4 plus any carried-over ones)")
print(f"View it at: https://sandbox.zenodo.org/deposit/{deposition_id}")
print()

if not EXISTING_RECORD_ID:
    print("Publishing this sandbox draft so it has a persistent identifier to version")
    print("(safe -- sandbox only; mints a throwaway sandbox DOI, not a real one)...")
    published = api_call("POST", final["links"]["publish"])
    print(f"Published. Sandbox DOI: {published.get('doi')}")
    print()
    print("Re-run with this id as the argument to test the newversion logic:")
    print(f"  python scripts/test_zenodo_sandbox.py {deposition_id}")
else:
    print(f"This was a NEWVERSION run against {EXISTING_RECORD_ID}. Check the counts above,")
    print("then delete both sandbox drafts/records from the sandbox UI.")
