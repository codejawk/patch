#!/usr/bin/env python3
"""
patch-merger web UI — a local, stdlib-only server around merge.py.

Paste a source file and a vendor patch, get back the merged file, the tier it
landed at, a coloured diff, and the full JSON audit report. A dropdown loads
any of the ten corpus fixtures and runs them against the bundled source tree so
you can watch every edge case (relocation, CRLF, the dangerous fuzzy refactor,
the malformed/hostile reject) end to end.

Run:
  python3 server.py                      # http://127.0.0.1:8765
  python3 server.py --port 9000
  python3 server.py --fixtures /path/to/patch-merger-fixtures

No pip installs. Requires `git` and GNU `patch` on PATH (same as merge.py).
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import shutil
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import merge as pm  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(HERE, "index.html")

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


DEFAULT_FIXTURES = _default_fixtures()
FIXTURES_DIR = DEFAULT_FIXTURES


# --------------------------------------------------------------------------- #
# merge helpers used by the API
# --------------------------------------------------------------------------- #


def _unified(original: str, merged: str, path: str) -> str:
    diff = difflib.unified_diff(
        original.splitlines(keepends=False),
        merged.splitlines(keepends=False),
        fromfile=f"a/{path}", tofile=f"b/{path}", lineterm="")
    return "\n".join(diff)


def merge_single(patch_text: str, file_name: str, file_content: str) -> dict:
    """Single-file merge: one pasted file + one patch."""
    tmp = tempfile.mkdtemp(prefix="pm_web_")
    try:
        base = os.path.basename(file_name) or "target.txt"
        target = os.path.join(tmp, base)
        with open(target, "w", encoding="utf-8", newline="") as fh:
            fh.write(file_content)
        report, writes = pm.merge_patch(patch_text, tmp, forced_target=target)
        files_out = []
        for e in report["files"]:
            rp = e["resolved_path"]
            merged_bytes = writes.get(rp) if rp else None
            merged = merged_bytes.decode("utf-8", "replace") if merged_bytes else None
            original = file_content if rp else None
            files_out.append({
                **e,
                "original": original,
                "merged": merged,
                "diff": _unified(original, merged, rp) if merged is not None
                        and original is not None else None,
            })
        report["files"] = files_out
        return report
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def list_fixtures() -> list:
    out = []
    pdir = os.path.join(FIXTURES_DIR, "patches")
    if not os.path.isdir(pdir):
        return out
    for name in sorted(os.listdir(pdir)):
        if not name.endswith(".patch"):
            continue
        fid = name.split("-", 1)[0]
        with open(os.path.join(pdir, name), encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        dialect = pm.detect_dialect(text)
        md = pm.extract_metadata(text, dialect)
        out.append({
            "id": fid,
            "filename": name,
            "dialect": dialect,
            "cve": md.get("cve"),
            "severity": md.get("severity"),
        })
    return out


def run_fixture(fid: str) -> dict:
    """Run one corpus fixture against a throwaway copy of the bundled src tree."""
    pdir = os.path.join(FIXTURES_DIR, "patches")
    src = os.path.join(FIXTURES_DIR, "src")
    patch_name = None
    for name in os.listdir(pdir):
        if name.startswith(fid) and name.endswith(".patch"):
            patch_name = name
            break
    if not patch_name:
        return {"error": f"fixture {fid} not found"}
    with open(os.path.join(pdir, patch_name), encoding="utf-8",
              errors="replace") as fh:
        patch_text = fh.read()

    work = tempfile.mkdtemp(prefix="pm_fix_")
    try:
        root = os.path.join(work, "src")
        shutil.copytree(src, root)
        report, writes = pm.merge_patch(patch_text, root)
        files_out = []
        for e in report["files"]:
            rp = e["resolved_path"]
            original = None
            if rp and os.path.isfile(os.path.join(root, rp)):
                original = pm._read(os.path.join(root, rp)).decode("utf-8", "replace")
            merged_bytes = writes.get(rp) if rp else None
            merged = merged_bytes.decode("utf-8", "replace") if merged_bytes else None
            diff = None
            if merged is not None:
                diff = _unified(original or "", merged, rp)
            files_out.append({**e, "original": original, "merged": merged,
                              "diff": diff})
        report["files"] = files_out
        report["patch_text"] = patch_text
        report["patch_filename"] = patch_name
        return report
    finally:
        shutil.rmtree(work, ignore_errors=True)


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # quieter console
        pass

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            try:
                with open(INDEX, "rb") as fh:
                    self._send(200, fh.read(), "text/html; charset=utf-8")
            except OSError:
                self._send(500, {"error": "index.html missing"})
            return
        if self.path == "/api/fixtures":
            self._send(200, {"fixtures": list_fixtures(),
                             "dir": FIXTURES_DIR,
                             "present": os.path.isdir(
                                 os.path.join(FIXTURES_DIR, "patches"))})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except ValueError:
            self._send(400, {"error": "invalid JSON"})
            return

        try:
            if self.path == "/api/merge":
                report = merge_single(
                    data.get("patch", ""),
                    data.get("file_name", "target.c"),
                    data.get("file_content", ""))
                self._send(200, report)
            elif self.path == "/api/run_fixture":
                self._send(200, run_fixture(data.get("id", "")))
            else:
                self._send(404, {"error": "not found"})
        except Exception as exc:  # surface tool errors to the UI
            self._send(500, {"error": f"{type(exc).__name__}: {exc}"})


def main(argv=None):
    global FIXTURES_DIR
    ap = argparse.ArgumentParser(description="patch-merger web UI")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--fixtures", default=DEFAULT_FIXTURES,
                    help="path to the patch-merger-fixtures directory")
    args = ap.parse_args(argv)
    FIXTURES_DIR = args.fixtures

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"patch-merger web UI  ->  {url}")
    print(f"fixtures: {FIXTURES_DIR} "
          f"({'found' if os.path.isdir(os.path.join(FIXTURES_DIR, 'patches')) else 'not found'})")
    print("Ctrl-C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
        srv.shutdown()


if __name__ == "__main__":
    main()
