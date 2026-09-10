#!/usr/bin/env python3
"""Append a provenance record for a fetched file: name, bytes, SHA-256, source URL, access date.

Usage:
  python provenance.py <file> <source_url> [--log data/raw/PROVENANCE.txt] [--note "how the URL was found"]

Call it once per raw file, right after the download. The log is committed with
the repository so a stranger (or an adjudicator) can see exactly what was used.
"""

import argparse
import datetime
import hashlib
import os


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("source_url")
    ap.add_argument("--log", default="PROVENANCE.txt",
                    help="log file to append to (default: PROVENANCE.txt in the current directory)")
    ap.add_argument("--note", default="")
    a = ap.parse_args()
    line = " | ".join([
        datetime.date.today().isoformat(),
        os.path.basename(a.file),
        f"{os.path.getsize(a.file)} bytes",
        f"sha256:{sha256(a.file)}",
        a.source_url,
        a.note,
    ]).rstrip(" |")
    with open(a.log, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line)


if __name__ == "__main__":
    main()
