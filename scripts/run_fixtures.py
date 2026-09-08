#!/usr/bin/env python3
"""
Regression check: run merge.py over the corpus and assert each fixture lands
on the outcome the README's "correct handling" column requires.

  python3 run_fixtures.py [--fixtures /path/to/patch-merger-fixtures]

Exit 0 if every fixture matches, 1 otherwise.
"""
import argparse
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import merge as pm

def _default_fixtures():
    env = os.environ.get("PATCH_MERGER_FIXTURES")
    if env:
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    for c in (os.path.join(os.path.dirname(here), "fixtures"),       # <repo>/fixtures
              "/Users/md.khan/CVE/files/patch-merger-fixtures"):
        if os.path.isdir(os.path.join(c, "patches")):
            return c
    return os.path.join(os.path.dirname(here), "fixtures")


DEFAULT = _default_fixtures()

# id -> (expected overall_status, note)
EXPECTED = {
    "0001": ("applied", "clean exact apply (T1)"),
    "0002": ("applied", "offset drift tolerated"),
    "0003": ("applied", "whitespace dialect, lands fuzzy-clean (T3, fuzz 0)"),
    "0004": ("no-op", "already backported — must not double-apply"),
    "0005": ("applied", "2+1 hunks, all-or-nothing"),
    "0006": ("applied", "relocated file resolved, then applied"),
    "0007": ("needs-review", "refactored region — fuzzy landing is WRONG"),
    "0008": ("applied", "new file + header + deletion, CRLF preserved"),
    "0009": ("rejected", "context absent at every tier — confident reject"),
    "0010": ("rejected", "malformed/hostile — rejected in safety scan"),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixtures", default=DEFAULT)
    args = ap.parse_args()
    pdir = os.path.join(args.fixtures, "patches")
    src = os.path.join(args.fixtures, "src")
    if not os.path.isdir(pdir):
        print(f"fixtures not found at {args.fixtures}", file=sys.stderr)
        return 2

    ok = True
    for name in sorted(os.listdir(pdir)):
        if not name.endswith(".patch"):
            continue
        fid = name.split("-", 1)[0]
        want, note = EXPECTED.get(fid, ("?", ""))
        with open(os.path.join(pdir, name), encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        work = tempfile.mkdtemp(prefix="pm_test_")
        try:
            root = os.path.join(work, "src")
            shutil.copytree(src, root)
            report, _ = pm.merge_patch(text, root)
            got = report["overall_status"]
        finally:
            shutil.rmtree(work, ignore_errors=True)
        mark = "PASS" if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  [{mark}] {fid}  want={want:<13} got={got:<13} {note}")
    print("\nALL PASS" if ok else "\nSOME FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
