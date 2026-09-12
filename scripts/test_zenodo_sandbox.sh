#!/usr/bin/env bash
# Standalone reproduction of .github/workflows/publish-zenodo.yml's Zenodo
# API calls, for testing the "newversion" logic against the Zenodo SANDBOX
# before ever pointing it at the production record (10.5281/zenodo.22503185).
# See docs/PUBLISH_GUIDE.md for the full runbook.
#
# WHY THIS SCRIPT EXISTS (not just "dispatch the GitHub Actions workflow"):
# running it here needs neither a push to GitHub nor a repository secret --
# just your own sandbox token, in your own shell, never seen by anyone else.
# It makes exactly the same API calls in exactly the same order as the
# workflow's "Create or version Zenodo deposition" and "Upload files to
# Zenodo" steps, so a clean run here is real evidence the workflow's logic
# is correct, not merely a facsimile of it.
#
# WHAT IT NEVER DOES: publish anything. The publish step is deliberately
# left out of this script -- the whole point of a sandbox test is files
# safely stuck in draft state that you delete afterward, not a live record.
#
# USAGE:
#   export ZENODO_ACCESS_TOKEN=...        # your sandbox token -- see PUBLISH_GUIDE.md
#                                          # for how to create one; never pass it as a
#                                          # command-line argument (shell history) or
#                                          # paste it into chat with anyone, Claude included.
#   ./scripts/test_zenodo_sandbox.sh                  # first run: creates a brand-new draft
#   ./scripts/test_zenodo_sandbox.sh <deposition_id>  # second run: tests newversion against it
#
# The first run has no record to version yet, so it creates a fresh draft
# (mirroring the workflow's "no existing_record_id" branch). It prints the
# deposition id at the end -- pass THAT id as this script's one argument on
# a second run to exercise the actual thing that needs testing: the
# newversion action, and that carried-over files from the prior version get
# removed before this version's files are uploaded (the exact bug v1.0's
# workflow had against the production record).

set -euo pipefail

ZENODO_API_URL="${ZENODO_API_URL:-https://sandbox.zenodo.org/api}"
: "${ZENODO_ACCESS_TOKEN:?Set ZENODO_ACCESS_TOKEN to your sandbox token first (see docs/PUBLISH_GUIDE.md)}"

if [[ "$ZENODO_API_URL" == *"sandbox"* ]]; then
  :
else
  echo "REFUSING TO RUN: ZENODO_API_URL ($ZENODO_API_URL) does not look like a sandbox host." >&2
  echo "This script is for sandbox testing only. Set ZENODO_API_URL explicitly to" >&2
  echo "https://sandbox.zenodo.org/api, or unset it to use that default." >&2
  exit 1
fi

VERSION="${VERSION:-v1.1-sandbox-test}"
EXISTING_RECORD_ID="${1:-}"

for f in \
  "data/processed/ong_ot_dataset_v1.1.csv" \
  "data/processed/ong_ot_dataset_v1.1_manifest.json" \
  "data/processed/qa_report.txt" \
  "report/stats.json"; do
  if [[ ! -f "$f" ]]; then
    echo "Missing $f -- run this from the repo root after a --full pipeline run." >&2
    exit 1
  fi
done

echo "== Zenodo API: $ZENODO_API_URL =="

if [[ -n "$EXISTING_RECORD_ID" ]]; then
  echo "Creating a new version of sandbox record $EXISTING_RECORD_ID..."
  newversion_response=$(curl --fail-with-body --silent --show-error \
    --request POST \
    --header "Authorization: Bearer $ZENODO_ACCESS_TOKEN" \
    "$ZENODO_API_URL/deposit/depositions/$EXISTING_RECORD_ID/actions/newversion")
  draft_url=$(jq -er '.links.latest_draft' <<< "$newversion_response")

  draft=$(curl --fail-with-body --silent --show-error \
    --header "Authorization: Bearer $ZENODO_ACCESS_TOKEN" \
    "$draft_url")
  deposition_id=$(jq -er '.id' <<< "$draft")
  bucket_url=$(jq -er '.links.bucket' <<< "$draft")

  carried_over=$(jq -c '.files[]? // empty' <<< "$draft")
  n_carried=$(jq -c '[.files[]? // empty] | length' <<< "$draft")
  echo "New draft $deposition_id carried over $n_carried file(s) from the previous version."
  if [[ -n "$carried_over" ]]; then
    echo "Removing carried-over files (this is the exact behavior under test)..."
    jq -c '.files[]? // empty' <<< "$draft" | while read -r file; do
      file_id=$(jq -r '.id' <<< "$file")
      file_name=$(jq -r '.filename' <<< "$file")
      echo "  removing $file_name ($file_id)"
      curl --fail-with-body --silent --show-error \
        --request DELETE \
        --header "Authorization: Bearer $ZENODO_ACCESS_TOKEN" \
        "$ZENODO_API_URL/deposit/depositions/$deposition_id/files/$file_id"
    done
  fi
else
  echo "No deposition id given -- creating a brand-new sandbox draft (this run's output"
  echo "id becomes the argument for your second, newversion-testing run)."
  create_response=$(curl --fail-with-body --silent --show-error \
    --request POST \
    --header "Authorization: Bearer $ZENODO_ACCESS_TOKEN" \
    --header "Content-Type: application/json" \
    --data '{}' \
    "$ZENODO_API_URL/deposit/depositions")
  deposition_id=$(jq -er '.id' <<< "$create_response")
  bucket_url=$(jq -er '.links.bucket' <<< "$create_response")
fi

metadata=$(jq -n \
  --arg title "ONG-OT Vulnerability Prioritization Dataset $VERSION (SANDBOX TEST -- not for real use)" \
  --rawfile description .zenodo/description.html \
  --arg name "Friday Ogochukwu Ikwuogu" \
  --arg orcid "0009-0009-2222-1318" \
  --arg affiliation "Independent Researcher, Odessa, Texas, USA" \
  '{metadata: {
    title: $title,
    upload_type: "dataset",
    description: $description,
    creators: [{name: $name, orcid: $orcid, affiliation: $affiliation}],
    access_right: "open",
    license: "odbl-1.0",
    version: env.VERSION
  }}')
curl --fail-with-body --silent --show-error \
  --request PUT \
  --header "Authorization: Bearer $ZENODO_ACCESS_TOKEN" \
  --header "Content-Type: application/json" \
  --data "$metadata" \
  "$ZENODO_API_URL/deposit/depositions/$deposition_id" > /dev/null
echo "Metadata set."

echo "Uploading files..."
for file in \
  "data/processed/ong_ot_dataset_v1.1.csv" \
  "data/processed/ong_ot_dataset_v1.1_manifest.json" \
  "data/processed/qa_report.txt" \
  "report/stats.json"; do
  curl --fail-with-body --silent --show-error \
    --request PUT \
    --header "Authorization: Bearer $ZENODO_ACCESS_TOKEN" \
    --upload-file "$file" \
    "$bucket_url/$(basename "$file")" > /dev/null
  echo "  uploaded $(basename "$file")"
done

final=$(curl --fail-with-body --silent --show-error \
  --header "Authorization: Bearer $ZENODO_ACCESS_TOKEN" \
  "$ZENODO_API_URL/deposit/depositions/$deposition_id")
n_files=$(jq '.files | length' <<< "$final")

echo
echo "== Result =="
echo "Sandbox deposition id: $deposition_id"
echo "Files now attached: $n_files (should be exactly 4 -- this version's files only,"
echo "  not this version's 4 plus any carried-over ones)"
echo "View it at: https://sandbox.zenodo.org/deposit/$deposition_id"
echo
if [[ -z "$EXISTING_RECORD_ID" ]]; then
  echo "This was the FIRST run (fresh draft). Re-run with this id as the argument to"
  echo "test the actual newversion logic:"
  echo "  ./scripts/test_zenodo_sandbox.sh $deposition_id"
else
  echo "This was a NEWVERSION run against $EXISTING_RECORD_ID. Check above that the"
  echo "carried-over-file count and the final file count both look right, then delete"
  echo "both sandbox drafts from the sandbox UI -- nothing here should be published."
fi
