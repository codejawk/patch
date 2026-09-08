#!/usr/bin/env python3
"""
batch.py — merge a whole folder of patches against a tree in one pass.

For each patch it runs the same safe merge as merge.py and then, WITHOUT asking:

  * applied  -> writes the merged files into the working tree (the job is done)
  * no-op    -> already present, nothing to write
  * needs-review -> a real conflict: left unwritten, flagged for a human
  * rejected -> unsafe/unresolvable: left unwritten, flagged

By default it works on a COPY of the tree (so the original stays intact) and
writes one HTML report per patch plus an index summarising which merged easily
and which need you. Point --in-place at the real tree to apply for real.

  python3 batch.py --patches <dir> --tree <tree>
  python3 batch.py --patches <dir> --tree <tree> --apply-to <dir> --reports <dir>
  python3 batch.py --patches <dir> --tree <tree> --in-place        # modify tree

Stdlib only; needs git + GNU patch (same as merge.py).
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import merge as pm      # noqa: E402
import review           # noqa: E402

ACTION = {
    "applied":      "merged — written to the tree",
    "no-op":        "already in the tree — skipped",
    "needs-review": "CONFLICT — left for you to resolve",
    "rejected":     "rejected — not applied",
}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--patches", required=True, help="folder of .patch files")
    ap.add_argument("--tree", required=True, help="source tree to merge into")
    ap.add_argument("--apply-to", help="working copy to write into "
                    "(default: <tree>__merged next to the tree)")
    ap.add_argument("--in-place", action="store_true",
                    help="apply to --tree itself instead of a copy")
    ap.add_argument("--reports", help="folder for the HTML reports "
                    "(default: <apply-to>/../patch-reports)")
    ap.add_argument("--open", action="store_true", dest="open_index",
                    help="open the summary report when done")
    args = ap.parse_args(argv)

    tree = os.path.abspath(args.tree)
    patches_dir = os.path.abspath(args.patches)
    if not os.path.isdir(patches_dir):
        ap.error(f"no such patches folder: {patches_dir}")

    if args.in_place:
        working = tree
    else:
        working = os.path.abspath(args.apply_to) if args.apply_to \
            else tree.rstrip("/") + "__merged"
        if os.path.exists(working):
            shutil.rmtree(working)
        shutil.copytree(tree, working)

    reports = os.path.abspath(args.reports) if args.reports \
        else os.path.join(os.path.dirname(working), "patch-reports")
    os.makedirs(reports, exist_ok=True)

    patch_files = sorted(f for f in os.listdir(patches_dir) if f.endswith(".patch"))
    rows = []
    print(f"\nmerging {len(patch_files)} patches into {working}\n")

    for name in patch_files:
        pid = name.split("-", 1)[0]
        with open(os.path.join(patches_dir, name), encoding="utf-8",
                  errors="replace") as fh:
            text = fh.read()

        report, writes = pm.merge_patch(text, working)
        report["patch_filename"] = name
        status = report["overall_status"]
        md = report["metadata"]

        # render BEFORE writing so the "Before" side is the pre-patch file
        page = pm.render_review(report, writes, text, working)
        report_name = f"{pid}.html"
        with open(os.path.join(reports, report_name), "w", encoding="utf-8") as fh:
            fh.write(page)

        wrote = []
        if status == "applied":
            for rp, data in writes.items():
                dst = os.path.join(working, rp)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with open(dst, "wb") as fh:
                    fh.write(data)
                wrote.append(rp)
        report["written"] = wrote

        files = [e["resolved_path"] or e["vendor_path"] for e in report["files"]]
        rows.append({
            "id": pid, "patch": name, "cve": md.get("cve"),
            "severity": md.get("severity"), "dialect": report.get("dialect"),
            "status": status, "action": ACTION.get(status, status),
            "files": [f for f in files if f], "report": report_name,
        })

        mark = {"applied": "✓", "no-op": "·", "needs-review": "!",
                "rejected": "✗"}.get(status, "?")
        print(f"  {mark} {name:<52} {status:<13} {ACTION.get(status,'')}")

    # summary index
    index = os.path.join(reports, "index.html")
    with open(index, "w", encoding="utf-8") as fh:
        fh.write(review.render_summary(rows, tree=working))

    merged = sum(1 for r in rows if r["status"] == "applied")
    noop = sum(1 for r in rows if r["status"] == "no-op")
    conflict = sum(1 for r in rows if r["status"] == "needs-review")
    rej = sum(1 for r in rows if r["status"] == "rejected")
    print(f"\n  merged: {merged}   already-present: {noop}   "
          f"conflicts (need you): {conflict}   rejected: {rej}")
    print(f"\n  merged tree : {working}")
    print(f"  reports     : {reports}")
    print(f"  summary     : {index}")
    if conflict:
        print("\n  conflicts that need your decision:")
        for r in rows:
            if r["status"] == "needs-review":
                print(f"    - {r['patch']}  ->  open {r['id']}.html")

    if args.open_index:
        import webbrowser
        webbrowser.open("file://" + index)
    return 0


if __name__ == "__main__":
    sys.exit(main())
