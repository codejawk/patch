#!/usr/bin/env python3
"""
patch-merger app — a local web UI around merge.py / claude_merge.py.

Launch it, open the page, point it at a source tree and a folder of patches,
and drive the whole thing by clicking: see every patch with its CVE/severity,
Preview a merge (dry-run) or Apply it in place, toggle Claude AI-assist for
conflicts, and read the full P4-style report inline. "Run all" gives the batch
summary.

  python3 server.py                 # http://127.0.0.1:8765
  python3 server.py --port 9000
  python3 server.py --tree <dir> --patches <dir>   # prefill the paths

Stdlib only. Needs git + GNU patch (and the `claude` CLI for AI-assist).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import merge as pm          # noqa: E402
import claude_merge as cm   # noqa: E402
import review               # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(HERE, "index.html")

_FIX = "/Users/md.khan/CVE/files/patch-merger-fixtures"
DEF_TREE = _FIX + "/src"
DEF_PATCHES = _FIX + "/patches"
DEF_FILE = "/Users/md.khan/CVE/level2/validate.c"
DEF_PATCH = "/Users/md.khan/CVE/level2/validate_id.patch"


def list_patches(pdir):
    out = []
    if not os.path.isdir(pdir):
        return out
    for name in sorted(os.listdir(pdir)):
        if not name.endswith(".patch"):
            continue
        with open(os.path.join(pdir, name), encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        dialect = pm.detect_dialect(text)
        md = pm.extract_metadata(text, dialect)
        out.append({"id": name.split("-", 1)[0], "filename": name,
                    "cve": md.get("cve"), "severity": md.get("severity"),
                    "dialect": dialect})
    return out


def run_one(patch_path, tree=None, file_path=None, apply=False, assist=False,
            p4=False):
    with open(patch_path, encoding="utf-8", errors="replace") as fh:
        patch_text = fh.read()
    if file_path:                       # single-file mode
        file_path = _p4_resolve(file_path, p4)
        tree = os.path.dirname(os.path.abspath(file_path))
        forced = os.path.abspath(file_path)
    else:
        forced = None
    report, writes = pm.merge_patch(patch_text, tree, forced)
    report["patch_filename"] = os.path.basename(patch_path)
    status = report["overall_status"]

    findings, assist_obj = None, None
    if assist and status in ("needs-review", "rejected"):
        rp = cm._primary_file(report, tree)
        cur = ""
        p = os.path.join(tree, rp) if rp else None
        if p and os.path.isfile(p):
            cur = pm.to_lf(pm._read(p)).decode("utf-8", "replace")
        ai = cm.claude_findings(cur, patch_text, rp or "file", None)
        auto = pm._auto_findings(report, patch_text, tree)
        findings = (ai + [a for a in auto
                          if a["title"] not in {x["title"] for x in ai}]) or None
        if cur:
            assist_obj = cm.claude_rebase(cur, patch_text, rp, tree, None)

    html = pm.render_review(report, writes, patch_text, tree,
                            findings=findings, assist=assist_obj)

    wrote, p4_msgs = [], []
    if apply and status == "applied":
        for rp, data in writes.items():
            dst = os.path.join(tree, rp)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if p4 and _which("p4"):
                ok, msg = _p4_edit(dst)
                p4_msgs.append(("✓ " if ok else "✗ ") + msg)
            with open(dst, "wb") as fh:
                fh.write(data)
            wrote.append(rp)

    f0 = report["files"][0] if report["files"] else {}
    return {"status": status, "tier": f0.get("tier"), "fuzz": f0.get("fuzz", 0),
            "cve": report["metadata"].get("cve"),
            "assisted": bool(assist_obj),
            "rebase_verified": assist_obj.get("verified") if assist_obj else None,
            "written": wrote, "p4": p4_msgs or None, "report_html": html}


def run_batch(patches_dir, tree, apply=False, assist=False):
    rows, reports = [], {}
    for p in list_patches(patches_dir):
        res = run_one(os.path.join(patches_dir, p["filename"]), tree,
                      apply=apply, assist=assist)
        action = {"applied": "merged", "no-op": "already in tree",
                  "needs-review": "needs you", "rejected": "rejected"}.get(
                      res["status"], res["status"])
        rows.append({**p, "status": res["status"], "action": action,
                     "files": []})
        reports[p["id"]] = res["report_html"]
    summary = review.render_summary(rows, tree=tree)
    return {"rows": rows, "summary_html": summary, "reports": reports}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/run_stream":
            self._run_stream(parse_qs(urlparse(self.path).query))
            return
        if self.path in ("/", "/index.html"):
            try:
                with open(INDEX, "rb") as fh:
                    self._send(200, fh.read(), "text/html; charset=utf-8")
            except OSError:
                self._send(500, {"error": "index.html missing"})
        elif path == "/api/config":
            self._send(200, {"tree": DEF_TREE, "patches": DEF_PATCHES,
                             "file": DEF_FILE, "patch": DEF_PATCH,
                             "claude": bool(_which("claude")),
                             "p4": bool(_which("p4"))})
        else:
            self._send(404, {"error": "not found"})

    def _run_stream(self, qs):
        g = lambda k, d="": qs.get(k, [d])[0]
        patch_path = g("patch_path")
        file_path = g("file_path") or None
        tree = g("tree") or None
        apply = g("apply") == "1"
        assist = g("assist") == "1"
        p4 = g("p4") == "1"
        if file_path:
            file_path = _p4_resolve(file_path, p4)

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        def emit(o):
            self.wfile.write(("data: " + json.dumps(o) + "\n\n").encode())
            self.wfile.flush()

        try:
            with open(patch_path, encoding="utf-8", errors="replace") as fh:
                patch_text = fh.read()
            if file_path:
                root = os.path.dirname(os.path.abspath(file_path))
                forced = os.path.abspath(file_path)
            else:
                root, forced = tree, None
            report, writes = pm.merge_patch(patch_text, root, forced)
            report["patch_filename"] = os.path.basename(patch_path)
            status = report["overall_status"]
            emit({"phase": "merged", "status": status})

            findings, assist_obj = None, None
            if assist and status in ("needs-review", "rejected") and _which("claude"):
                rp = cm._primary_file(report, root)
                cur = ""
                p = os.path.join(root, rp) if rp else None
                if p and os.path.isfile(p):
                    cur = pm.to_lf(pm._read(p)).decode("utf-8", "replace")

                fprompt = cm.FINDINGS_PROMPT.format(
                    relpath=rp or "file", current=cur[:16000], patch=patch_text[:8000])
                emit({"phase": "analyse", "start": True, "prompt": fprompt})
                ftext = cm.stream_claude(
                    fprompt, lambda t: emit({"phase": "analyse", "delta": t}))
                ai = []
                for f in (cm._extract_json_array(ftext) or []):
                    if isinstance(f, dict) and f.get("title"):
                        ai.append({"severity": f.get("severity", "warn"),
                                   "title": str(f.get("title"))[:200],
                                   "body": str(f.get("body", ""))[:600],
                                   "evidence": str(f.get("evidence", ""))[:300]})
                auto = pm._auto_findings(report, patch_text, root)
                findings = (ai + [a for a in auto
                                  if a["title"] not in {x["title"] for x in ai}]) or None
                emit({"phase": "analyse", "done": True, "count": len(findings or [])})

                if cur:
                    rprompt = cm.REBASE_PROMPT.format(
                        relpath=rp or "file", current=cur[:16000], patch=patch_text[:8000])
                    emit({"phase": "rebase", "start": True, "prompt": rprompt})
                    rtext = cm.stream_claude(
                        rprompt, lambda t: emit({"phase": "rebase", "delta": t}))
                    diff = cm._extract_diff(rtext)
                    if diff:
                        verified, tier = cm._verify_diff(diff, root, rp)
                        note = (f"Re-verified: applies cleanly (tier {tier}, no discarded "
                                "context). Still a proposal — a human signs off first.") \
                            if verified else ("Did not apply cleanly on re-check — treat "
                                              "as a draft to edit, not a fix.")
                        assist_obj = {"diff": diff, "verified": verified,
                                      "tier": tier or 1, "fuzz": 0, "note": note}
                        emit({"phase": "rebase", "done": True, "verified": bool(verified)})
                    else:
                        emit({"phase": "rebase", "done": True, "verified": False})

            # render BEFORE write-back, so the "Before" column reads the
            # pre-patch file even when --write is about to overwrite it
            html = pm.render_review(report, writes, patch_text, root,
                                    findings=findings, assist=assist_obj)
            wrote = []
            if apply and status == "applied":
                for rpn, data in writes.items():
                    dst = os.path.join(root, rpn)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    if p4 and _which("p4"):
                        ok, msg = _p4_edit(dst)
                        emit({"phase": "p4", "ok": ok, "msg": msg})
                    with open(dst, "wb") as fh:
                        fh.write(data)
                    wrote.append(rpn)
            report["written"] = wrote
            emit({"phase": "done", "status": status, "report_html": html})
        except Exception as exc:  # noqa: BLE001
            try:
                emit({"phase": "error", "error": f"{type(exc).__name__}: {exc}"})
            except Exception:
                pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            self._send(400, {"error": "bad json"}); return
        try:
            if self.path == "/api/patches":
                self._send(200, {"patches": list_patches(data.get("patches", "")),
                                 "tree_ok": os.path.isdir(data.get("tree", ""))})
            elif self.path == "/api/run":
                self._send(200, run_one(
                    data["patch_path"], tree=data.get("tree"),
                    file_path=data.get("file_path"),
                    apply=data.get("apply", False),
                    assist=data.get("assist", False),
                    p4=data.get("p4", False)))
            elif self.path == "/api/batch":
                self._send(200, run_batch(data["patches"], data["tree"],
                                          data.get("apply", False),
                                          data.get("assist", False)))
            else:
                self._send(404, {"error": "not found"})
        except Exception as exc:  # noqa: BLE001
            self._send(500, {"error": f"{type(exc).__name__}: {exc}"})


def _which(cmd):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if os.path.isfile(os.path.join(d, cmd)):
            return True
    return False


# --------------------------------------------------------------------------- #
# Perforce (p4) — resolve a depot path to a local file and open it for edit.
# All guarded: if p4 is missing or a call fails, we fall back to plain files
# and never break the merge. Never runs `p4 submit`.
# --------------------------------------------------------------------------- #


def _p4_where(depot):
    """Map //depot/path -> local workspace path via `p4 where`."""
    try:
        r = subprocess.run(["p4", "where", depot], capture_output=True,
                           text=True, timeout=30)
    except Exception:  # noqa: BLE001
        return None
    if r.returncode == 0 and r.stdout.strip():
        # last line, last whitespace-separated field is the local path
        return r.stdout.strip().splitlines()[-1].split()[-1]
    return None


def _p4_edit(local):
    """`p4 edit` a file so the change is tracked in the client. Returns
    (ok, message)."""
    try:
        r = subprocess.run(["p4", "edit", local], capture_output=True,
                           text=True, timeout=30)
        return (r.returncode == 0, (r.stdout or r.stderr).strip())
    except Exception as exc:  # noqa: BLE001
        return (False, str(exc))


def _p4_resolve(file_path, p4):
    """If p4 mode and the path is a depot path, resolve it to a local file."""
    if p4 and file_path and file_path.startswith("//") and _which("p4"):
        loc = _p4_where(file_path)
        if loc:
            return loc
    return file_path


def main(argv=None):
    global DEF_TREE, DEF_PATCHES
    ap = argparse.ArgumentParser(description="patch-merger web app")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--tree", default=DEF_TREE)
    ap.add_argument("--patches", default=DEF_PATCHES)
    args = ap.parse_args(argv)
    DEF_TREE, DEF_PATCHES = args.tree, args.patches
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"patch-merger app  ->  {url}")
    print(f"tree:    {DEF_TREE}")
    print(f"patches: {DEF_PATCHES}")
    print(f"claude CLI: {'found' if _which('claude') else 'NOT found (AI-assist disabled)'}")
    print("Ctrl-C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
        srv.shutdown()


if __name__ == "__main__":
    main()
