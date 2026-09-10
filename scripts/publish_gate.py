#!/usr/bin/env python3
"""Pre-publication gate: refuse to publish while draft markers or secrets remain.

Scans a project directory for:
  - DRAFT stamps and banners in text-bearing files (md, txt, html, py, js, csv, json, tex, cff)
  - [VERIFY ...] and [ASK ...] tags, and bracketed placeholders like [insert], [DOI], [journal]
  - likely secrets: tokens, private keys, .env files
  - a missing LICENSE, README, or CITATION.cff (warning, not failure)

Exit code 0 means clear to publish; 1 means blocked. The human half of the gate
(the author's own verification) cannot be scripted; this enforces the mechanical half.

Usage:
  python publish_gate.py <project_dir> [--allow-draft-in path/prefix ...]
"""

import argparse
import os
import re
import sys

TEXT_EXT = {".md", ".txt", ".html", ".py", ".js", ".csv", ".json", ".tex", ".cff", ".yml", ".yaml", ".rst", ".bib"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}

DRAFT_PATTERNS = [
    (re.compile(r"\bDRAFT\b"), "DRAFT stamp or banner"),
    (re.compile(r"\[VERIFY[^\]]*\]"), "[VERIFY] tag"),
    (re.compile(r"\[ASK[^\]]*\]"), "[ASK] tag"),
    (re.compile(r"\[TARGET\]"), "[TARGET] tag (planning artifact, not publishable)"),
    (re.compile(r"\[(insert|DOI|journal|tracking number|repository URL|n|date|name)[^\]]*\]", re.I),
     "bracketed placeholder"),
    (re.compile(r"XXXX-XXXX|zenodo\.XXXX+"), "placeholder identifier"),
]
SECRET_PATTERNS = [
    (re.compile(r"ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"), "GitHub token"),
    (re.compile(r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"(?i)(api[_-]?key|secret|token)\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"), "hardcoded credential"),
]
REQUIRED = ["README.md", "LICENSE"]
RECOMMENDED = ["CITATION.cff", ".gitignore"]


def scan(root, allow_prefixes):
    blockers, warnings = [], []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            if fn == ".env" or fn.endswith(".pem"):
                blockers.append((rel, "secrets file present"))
                continue
            if os.path.splitext(fn)[1].lower() not in TEXT_EXT:
                continue
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except OSError:
                continue
            for pat, label in SECRET_PATTERNS:
                if pat.search(text):
                    blockers.append((rel, label))
            allowed = any(rel.startswith(p) for p in allow_prefixes)
            for pat, label in DRAFT_PATTERNS:
                m = pat.search(text)
                if m:
                    line = text.count("\n", 0, m.start()) + 1
                    (warnings if allowed else blockers).append((f"{rel}:{line}", label))
    for req in REQUIRED:
        if not os.path.exists(os.path.join(root, req)):
            blockers.append((req, "required file missing"))
    for rec in RECOMMENDED:
        if not os.path.exists(os.path.join(root, rec)):
            warnings.append((rec, "recommended file missing"))
    return blockers, warnings


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project_dir")
    ap.add_argument("--allow-draft-in", nargs="*", default=[],
                    help="relative path prefixes where draft markers are tolerated (e.g. docs/planning)")
    a = ap.parse_args()
    root = os.path.abspath(a.project_dir)
    blockers, warnings = scan(root, a.allow_draft_in)
    for rel, label in warnings:
        print(f"warning  {label}: {rel}")
    for rel, label in blockers:
        print(f"BLOCKED  {label}: {rel}")
    if blockers:
        print(f"\n{len(blockers)} blocker(s). Resolve every one, then re-run. "
              "Draft markers come off only after the author has verified the work.")
        sys.exit(1)
    print("gate: clear (mechanical checks passed; the author's own verification is still required)")


if __name__ == "__main__":
    main()
