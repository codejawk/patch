#!/usr/bin/env python3
"""
claude_merge.py — patch merger with the Claude CLI wired in for the judgment
calls the deterministic tiers can't make.

Same job and same safety as merge.py: given a file (or tree) and a diff patch,
merge it. Applied / no-op results are handled purely deterministically — no
model is ever invoked (deterministic by default: fast, free, reproducible).

But when the deterministic merge comes back **needs-review** (the hunk only
landed fuzzily, on refactored code) or **rejected** (it doesn't land at all),
this tool shells out to the local `claude` CLI to:

  1. ANALYSE — read the current code + the vendor hunk and list the concrete
     defects that make applying it as-is unsafe (won't compile, resource leak,
     missing helper, wrong error path). These render as cards on the report.
  2. REBASE — propose a corrected unified diff against the *current* code that
     achieves the same intent using the tree's own mechanisms. The proposal is
     then **re-verified with the deterministic applier** — Claude's diff must
     actually apply, or it is shown as an unverified draft. It is never applied
     automatically; it is a review request.

Requires the `claude` CLI on PATH (`claude -p`), plus git + GNU patch.

Usage:
  claude_merge.py <patch> --file <target>
  claude_merge.py <patch> --root <tree>
  claude_merge.py <patch> --file <target> --in-place     # write clean results
  claude_merge.py <patch> --file <target> --no-assist    # skip the Claude steps
  claude_merge.py <patch> --file <target> --model <name>  # pick a model
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import merge as pm  # noqa: E402


# --------------------------------------------------------------------------- #
# Claude CLI
# --------------------------------------------------------------------------- #


def ask_claude(prompt, model=None):
    """Run one headless Claude turn and return its text, or None on failure."""
    cmd = ["claude", "-p", prompt]
    if model:
        cmd += ["--model", model]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print("  ! claude CLI not found on PATH — skipping AI steps",
              file=sys.stderr)
        return None
    if r.returncode != 0:
        print(f"  ! claude CLI failed (rc={r.returncode}): "
              f"{r.stderr.strip()[:200]}", file=sys.stderr)
        return None
    return r.stdout.strip()


def stream_claude(prompt, on_text, model=None):
    """Run one headless Claude turn with token streaming. Calls on_text(delta)
    for each text chunk as it arrives; returns the full assembled text."""
    cmd = ["claude", "-p", prompt, "--output-format", "stream-json",
           "--verbose", "--include-partial-messages"]
    if model:
        cmd += ["--model", model]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, bufsize=1)
    except FileNotFoundError:
        return None
    final = ""
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if o.get("type") == "stream_event":
            ev = o.get("event", {})
            if ev.get("type") == "content_block_delta":
                d = ev.get("delta", {})
                if d.get("type") == "text_delta":
                    txt = d.get("text", "")
                    final += txt
                    on_text(txt)
        elif o.get("type") == "result":
            final = o.get("result", final) or final
    proc.wait()
    return final


def _strip_fences(text):
    text = text.strip()
    # drop a leading ```lang and trailing ```
    text = re.sub(r"^```[a-zA-Z0-9]*\s*\n", "", text)
    text = re.sub(r"\n```\s*$", "", text)
    return text.strip()


def _extract_json_array(text):
    if not text:
        return None
    text = _strip_fences(text)
    m = re.search(r"\[.*\]", text, re.S)
    if not m:
        return None
    try:
        data = json.loads(m.group(0))
        return data if isinstance(data, list) else None
    except ValueError:
        return None


def _extract_diff(text):
    if not text:
        return None
    text = _strip_fences(text)
    if "NO-REBASE" in text and "@@" not in text:
        return None
    # take from the first diff/--- header to the end
    m = re.search(r"(?m)^(diff --git |--- )", text)
    if not m:
        return None
    return text[m.start():].rstrip() + "\n"


# --------------------------------------------------------------------------- #
# prompts
# --------------------------------------------------------------------------- #


FINDINGS_PROMPT = """\
You are a Linux kernel security reviewer. A mechanical patch merger could only \
land this vendor patch under fuzzy matching (the target file was refactored), or \
could not land it at all. List the concrete defects that make applying this patch \
AS-IS unsafe against the CURRENT code. Look for: symbols or struct members the \
added code uses that no longer exist (won't compile); resource leaks (locks, \
power rails, memory released on the wrong path); helper functions the hunk calls \
that are not defined in this file/tree; and error/cleanup mechanisms the vendor \
used that the current code replaced.

Output ONLY a JSON array — no prose, no markdown fences:
[{{"severity":"compile|leak|dep|danger|warn","title":"short title",\
"body":"1-3 factual sentences","evidence":"a short grep/observation"}}]
If there is genuinely no defect, output [].

=== CURRENT FILE ({relpath}) ===
{current}

=== VENDOR PATCH (its context may be obsolete) ===
{patch}
"""

REBASE_PROMPT = """\
The vendor patch below was written against an older version of this file and \
does not apply cleanly, because the target file was refactored. Produce a \
corrected unified diff that:
- applies to the CURRENT file exactly as shown,
- achieves the SAME security intent as the vendor patch,
- reuses the CURRENT file's own mechanisms (its existing error/cleanup labels, \
its data structures and helpers) rather than the vendor's obsolete ones.

Output ONLY the unified diff, starting with these exact header lines:
--- a/{relpath}
+++ b/{relpath}
then the @@ hunks. No prose, no explanation, no markdown fences. \
If a correct rebase is not possible, output exactly: NO-REBASE

=== CURRENT FILE (a/{relpath}) ===
{current}

=== VENDOR PATCH (obsolete context) ===
{patch}
"""


# --------------------------------------------------------------------------- #
# AI steps
# --------------------------------------------------------------------------- #


def _primary_file(report, root):
    """The file the AI should reason about: the first resolved one, else the
    first with a vendor path."""
    for e in report["files"]:
        rp = e.get("resolved_path")
        if rp and os.path.isfile(os.path.join(root, rp)):
            return rp
    for e in report["files"]:
        if e.get("vendor_path"):
            return e["vendor_path"]
    return None


def claude_findings(current, patch_text, relpath, model):
    out = ask_claude(FINDINGS_PROMPT.format(
        relpath=relpath, current=current[:16000], patch=patch_text[:8000]), model)
    found = _extract_json_array(out)
    if not found:
        return []
    clean = []
    for f in found:
        if isinstance(f, dict) and f.get("title"):
            clean.append({
                "severity": f.get("severity", "warn"),
                "title": str(f.get("title", ""))[:200],
                "body": str(f.get("body", ""))[:600],
                "evidence": str(f.get("evidence", ""))[:300],
            })
    return clean


def claude_rebase(current, patch_text, relpath, root, model):
    """Ask Claude for a rebased diff, then re-verify it deterministically.
    Returns an `assist` dict or None."""
    out = ask_claude(REBASE_PROMPT.format(
        relpath=relpath, current=current[:16000], patch=patch_text[:8000]), model)
    diff = _extract_diff(out)
    if not diff:
        return None

    # re-verify: does Claude's diff actually apply to the current file? Use a
    # direct git-apply / patch check — NOT merge_patch, whose vendor-safety scan
    # would reject a bare rebase diff for lacking a CVE/CR.
    verified, tier = _verify_diff(diff, root, relpath)
    if verified:
        note = ("Re-verified: this rebase applies cleanly to the current file "
                f"(tier {tier}, no discarded context). Still a proposal — a human "
                "signs off before it ships.")
    else:
        note = ("This rebase did NOT apply cleanly when re-checked against the "
                "current file — treat it as a draft to edit, not a fix.")
    return {"diff": diff, "verified": verified, "tier": tier or 1, "fuzz": 0,
            "note": note}


def _verify_diff(diff, root, relpath):
    """Does `diff` apply to the current file? Returns (verified, tier)."""
    import shutil
    import tempfile
    src = os.path.join(root, relpath)
    if not os.path.isfile(src):
        return (False, None)
    tmp = tempfile.mkdtemp(prefix="pm_verify_")
    try:
        dst = os.path.join(tmp, relpath)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as fh:
            fh.write(pm.to_lf(pm._read(src)))
        pf = os.path.join(tmp, "rebase.patch")
        with open(pf, "w", newline="\n") as fh:
            fh.write(diff)
        r = subprocess.run(["git", "apply", "-p1", "--check", "--whitespace=nowarn",
                            pf], cwd=tmp, capture_output=True, text=True)
        if r.returncode == 0:
            return (True, 1)
        r = subprocess.run(["patch", "-p1", "-F0", "--dry-run", "-i", pf],
                           cwd=tmp, capture_output=True, text=True, input="")
        if r.returncode == 0:
            return (True, 2)
        return (False, None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Merge a patch; call the Claude CLI when a human judgment "
                    "is needed (needs-review / rejected).")
    ap.add_argument("patch")
    ap.add_argument("--file", help="target file (single-file patch)")
    ap.add_argument("--root", help="source tree root")
    ap.add_argument("--in-place", action="store_true",
                    help="write merged files back (only when status is applied)")
    ap.add_argument("--no-assist", action="store_true",
                    help="skip the Claude analyse/rebase steps")
    ap.add_argument("--model", help="model for the Claude CLI (e.g. opus, sonnet)")
    ap.add_argument("--html", help="report path (default: patch-reports/<patch>.html)")
    ap.add_argument("--no-open", action="store_true")
    args = ap.parse_args(argv)

    with open(args.patch, encoding="utf-8", errors="replace") as fh:
        patch_text = fh.read()

    forced_target = None
    if args.file:
        forced_target = os.path.abspath(args.file)
        root = os.path.abspath(args.root) if args.root \
            else os.path.dirname(forced_target)
    elif args.root:
        root = os.path.abspath(args.root)
    else:
        ap.error("provide --file <target> or --root <tree>")

    # ---- deterministic merge (same as merge.py) ----
    report, writes = pm.merge_patch(patch_text, root, forced_target)
    report["patch_filename"] = os.path.basename(args.patch)
    status = report["overall_status"]

    findings = None
    assist = None
    if status in ("needs-review", "rejected") and not args.no_assist:
        rp = _primary_file(report, root)
        cur_path = os.path.join(root, rp) if rp else None
        current = ""
        if cur_path and os.path.isfile(cur_path):
            current = pm.to_lf(pm._read(cur_path)).decode("utf-8", "replace")
        print(f"  status is {status} — asking Claude to analyse and rebase…",
              file=sys.stderr)
        # analyse (combine Claude's semantic findings with the deterministic ones)
        ai = claude_findings(current, patch_text, rp or "file", args.model)
        auto = pm._auto_findings(report, patch_text, root)
        findings = (ai + [a for a in auto
                          if a["title"] not in {x["title"] for x in ai}]) or None
        # rebase (only meaningful when we have a current file to rebase against)
        if current:
            assist = claude_rebase(current, patch_text, rp, root, args.model)

    # ---- render + write the report (always, for every outcome) ----
    page = pm.render_review(report, writes, patch_text, root,
                            findings=findings, assist=assist)
    html_path = args.html
    if not html_path:
        base = os.path.dirname(root) if args.root else root
        rdir = os.path.join(base or ".", "patch-reports")
        os.makedirs(rdir, exist_ok=True)
        stem = os.path.splitext(os.path.basename(args.patch))[0]
        html_path = os.path.join(rdir, stem + ".html")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(page)

    # ---- write-back (clean results only) ----
    wrote = []
    if writes and args.in_place and status == "applied":
        for rp, data in writes.items():
            dst = os.path.join(root, rp)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as fh:
                fh.write(data)
            wrote.append(dst)
    report["written"] = wrote

    if not args.no_open:
        import webbrowser
        webbrowser.open("file://" + os.path.abspath(html_path))

    # ---- human summary ----
    md = report["metadata"]
    print(f"\nstatus : {status.upper()}", file=sys.stderr)
    print(f"cve    : {md.get('cve') or '(none)'}", file=sys.stderr)
    if findings:
        print(f"blockers: {len(findings)} (from Claude + auto-detect)",
              file=sys.stderr)
    if assist:
        print(f"rebase : {'VERIFIED (applies cleanly)' if assist['verified'] else 'draft (did not verify)'}",
              file=sys.stderr)
    if wrote:
        print("wrote  : " + ", ".join(wrote), file=sys.stderr)
    print(f"report : {html_path}", file=sys.stderr)

    print(json.dumps(report, indent=2))
    return {"applied": 0, "no-op": 0, "needs-review": 2,
            "rejected": 3}.get(status, 1)


if __name__ == "__main__":
    sys.exit(main())
