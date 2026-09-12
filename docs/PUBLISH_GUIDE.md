# Publish guide — Zenodo sandbox test, then the real thing

This is the item `docs/VERIFY_CHECKLIST.md` calls "test against the Zenodo
**sandbox** first, not directly against record 22503185." It exists because
v1.0's `.github/workflows/publish-zenodo.yml` created a brand-new deposition
on every run (a bug — it would have minted an unrelated second DOI for v1.1
instead of a new version of the existing one). That's fixed, but a fix to
code that talks to a real, external, hard-to-undo record deserves proof
before it ever touches record 22503185, not just a read of the diff.

**Why this is a runbook, not something already done for you:** it needs a
Zenodo sandbox account and a personal access token — a credential that
belongs only in your hands. Nothing in this repo, and no assistant working
on it, should ever see that token; the steps below are written so it never
has to leave your own shell.

## 1. Get a sandbox token (a few minutes, one-time)

1. Create an account at [sandbox.zenodo.org](https://sandbox.zenodo.org) if
   you don't have one — it's a fully separate system from real zenodo.org,
   nothing here can touch your production DOI or the real record.
2. Go to Applications → Personal access tokens → New token.
3. Scopes: `deposit:write` and `deposit:actions`.
4. Copy the token somewhere private (a password manager, not a chat, not a
   file in this repo).

## 2. Run the test

In a terminal, from the repo root, on a machine with normal internet access
(this needs the same kind of network the `--full` pipeline run needed):

```bash
export ZENODO_ACCESS_TOKEN=paste-your-sandbox-token-here
./scripts/test_zenodo_sandbox.sh
```

This first run has no existing record to version, so it creates a fresh
sandbox draft and uploads this repo's real v1.1 output to it (harmless —
it's the sandbox, and the script never publishes anything). It prints a
deposition id at the end, e.g. `Sandbox deposition id: 123456`.

Now run it again, passing that id, to test the actual thing this exists to
verify — the `newversion` action, and that files carried over from the
"previous" version get removed before this version's files are attached:

```bash
./scripts/test_zenodo_sandbox.sh 123456
```

## 3. What a pass looks like

Read the script's own output — it tells you what to check:

- The second run should print `New draft ... carried over 4 file(s) from
  the previous version` (the 4 files the first run uploaded), followed by
  each one being removed.
- The final `Files now attached:` count on the second run should be
  **exactly 4** — this run's 4 files, not 8 (this run's + the first run's
  carried-over ones still sitting there). Eight would mean the file-removal
  step silently failed and the bug this workflow was supposed to fix is
  still live.
- Open `https://sandbox.zenodo.org/deposit/<id>` for both drafts and
  eyeball them: title, description (rendered from `.zenodo/description.html`
  — check it actually rendered as HTML, not literal tags), creators, and
  that exactly the 4 expected files are attached with sane sizes.

If both checks pass: the workflow's core logic is proven correct. This
script makes the identical API calls in the identical order as
`.github/workflows/publish-zenodo.yml`'s "Create or version Zenodo
deposition" and "Upload files to Zenodo" steps — a clean run here is real
evidence about that workflow, not a facsimile of it.

## 4. Clean up

Delete both sandbox drafts from the sandbox UI (a draft deposition, unlike
a published one, can just be deleted — no DOI was ever minted). Nothing
from this test should be left behind, published, or referenced anywhere.

## 5. Only after that: the real GitHub Actions run

Once the sandbox test passes, `.github/workflows/publish-zenodo.yml` itself
still needs to actually run once for real, which needs:

1. This repo pushed to GitHub (blocked from the cloud sandbox that built
   most of v1.1 — see the commit history; push it from your own machine
   instead, where your own git credentials work).
2. Repository secret `ZENODO_ACCESS_TOKEN` set to your **production**
   Zenodo token (a separate token from the sandbox one above — create it at
   real zenodo.org the same way).
3. Dispatch the workflow manually (Actions tab → "Build and publish dataset
   to Zenodo" → Run workflow) with `publish: false` and
   `existing_record_id: 22503185` (the default) first — this uploads a new
   draft version of the real record without publishing it, so you can
   review it on zenodo.org before it goes live, exactly like the sandbox
   test did. Only re-run with `publish: true` (or publish it from the
   Zenodo UI directly) once you're satisfied.

This step needs your own eyes on the real record either way — a real DOI
version, once published, cannot be unpublished the way a sandbox draft can
just be deleted.
