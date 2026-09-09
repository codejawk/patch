#!/usr/bin/env python3
"""
p4_merge.py — a Perforce-native patch merger that works the way a person does.

This is a SEPARATE tool from merge.py / claude_merge.py. Those run a ladder of
mechanical appliers (git apply, patch -F0, patch -F2) that lean on the patch's
line numbers. This one does not. In a real p4 tree the vendor patch was written
against a different revision, so its @@ line numbers are almost always wrong —
so we ignore them completely and merge like an engineer at a desk:

  1. Put the file(s) in your workspace and in a changelist:
       p4 where   -> is this path mapped to your client? if not, stop and say so
       p4 revert  -> throw away any pending edits so we start from a clean file
       p4 sync    -> pull the latest revision
       p4 edit    -> open it for edit so the change lands in your CL
     (We NEVER run `p4 submit`. The change is yours to review and submit.)

  2. Find the spot by CONTENT, not line number:
     each hunk carries a few context lines above/below the change plus the lines
     it removes. We match that block against the current file (whitespace-
     insensitive) to locate exactly where the edit belongs, even if it moved.

  3. Let the Claude CLI make the edit, given the current file, the located
     region, and the vendor hunk — the same judgment a person applies when the
     old context no longer matches byte-for-byte.

  4. Show the result as a P4-style before|after diff (and `p4 diff` when p4 is
     present). Nothing is submitted; you review, then submit yourself.

Usage:
  p4_merge.py <patch> --path //depot/proj/npu/npu_auth.c   # one mapped file
  p4_merge.py <patch> --path /local/abs/path/npu_auth.c    # a local file
  p4_merge.py <patch> --dir  //depot/proj/npu/...          # folder: files from the patch
  p4_merge.py <patch> --path <f> --model sonnet            # pick a model
  p4_merge.py <patch> --path <f> --no-p4                   # skip p4, merge locally
  p4_merge.py <patch> --path <f> --no-open                 # don't open the report
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import merge as pm            # noqa: E402  parse_patch, to_lf, _read, path helpers
import review as rv           # noqa: E402  _head, _sxs, _patch_html, _esc, _SCRIPT
from claude_merge import ask_claude, stream_claude, _strip_fences  # noqa: E402


# --------------------------------------------------------------------------- #
# shell / p4 helpers  (all guarded — p4 missing or failing never crashes us)
# --------------------------------------------------------------------------- #


def _run(cmd, stdin=""):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           input=stdin, timeout=60)
        return r.returncode, r.stdout, r.stderr
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)


def _which(cmd):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if d and os.path.isfile(os.path.join(d, cmd)):
            return True
    return False


def _first(out, err):
    """First non-empty line of p4 output, for a compact status message."""
    for blob in (out, err):
        for line in (blob or "").splitlines():
            if line.strip():
                return line.strip()
    return ""


def p4_where(depot):
    """Map a depot path to a local workspace path. None => not mapped."""
    rc, out, _ = _run(["p4", "where", depot])
    if rc == 0 and out.strip():
        # "//depot/f.c //client/f.c /Users/.../f.c" — local path is the last field
        return out.strip().splitlines()[-1].split()[-1]
    return None


def p4_prepare(target, use_p4):
    """Get `target` clean, latest, and open for edit in the current CL.
    Returns (local_path, messages, mapped_ok)."""
    msgs = []
    if not (use_p4 and _which("p4")):
        # local-only mode: the target must already be a real file on disk
        local = target
        if not os.path.isfile(local):
            return None, [f"✗ {target} is not a local file (and p4 is off)"], False
        msgs.append("· p4 disabled — merging the local file in place")
        return local, msgs, True

    is_depot = target.startswith("//")
    local = p4_where(target) if is_depot else target
    if is_depot and not local:
        return None, [f"✗ {target} is NOT mapped in your client — nothing to merge. "
                      "Check your workspace View."], False
    if is_depot:
        msgs.append(f"✓ mapped  {target}  →  {local}")

    p4target = target  # p4 commands take the depot path (or local — both work)
    # revert first so pending edits don't poison the sync, then pull latest,
    # then open for edit. Never submit.
    for verb, ok_word in (("revert", "reverted"), ("sync", "synced"),
                          ("edit", "opened for edit")):
        rc, out, err = _run(["p4", verb, p4target])
        line = _first(out, err) or f"{verb}: (no output)"
        mark = "✓" if rc == 0 else "·"
        msgs.append(f"{mark} {ok_word:16s} {line}")

    if not local or not os.path.isfile(local):
        return None, msgs + [f"✗ local file not found after sync: {local}"], False
    return local, msgs, True


def p4_diff(target):
    """`p4 diff` text for the opened file (review only). '' if unavailable."""
    if not _which("p4"):
        return ""
    rc, out, _ = _run(["p4", "diff", "-du", target])
    return out if rc == 0 else ""


# --------------------------------------------------------------------------- #
# locate the change by content — anchor line first, then confirm
#
# The patch's @@ line numbers are unreliable, so we don't trust them to place
# the change. Instead we work the way a person scanning the file does:
#
#   1. pick the most DISTINCTIVE single line from the hunk's old side (context or
#      removed) — trimmed of leading/trailing whitespace — usually a function
#      signature or a specific `if (...)`. Find every place it occurs.
#   2. each occurrence implies a block start; CONFIRM each candidate with the
#      rest of the hunk's context/removed lines (how many line up).
#   3. break ties by the declared line number — the candidate nearest to where
#      the patch *said* it was is, with equal context, the more likely one.
# --------------------------------------------------------------------------- #


def old_block(hunk):
    """Lines the hunk expects to ALREADY be in the file: context + removed
    (the '+' added lines and '\\ No newline' markers are not part of it)."""
    out = []
    for ln in hunk.lines:
        if ln == "":
            out.append("")
        elif ln[0] == " ":
            out.append(ln[1:])
        elif ln[0] == "-":
            out.append(ln[1:])
    return out


def _distinctiveness(trimmed):
    """How usable a line is as an anchor. Bare braces / very short lines are poor
    anchors (they occur everywhere); long specific lines are strong ones."""
    if len(trimmed) < 4:
        return 0
    if trimmed in ("{", "}", "};", "*/", "/*", "return;", "break;", "continue;"):
        return 0
    return len(trimmed)


def locate(cur_lines, block, declared_line=None):
    """Locate `block` (a hunk's old side) inside `cur_lines`.
    Returns a note dict, or None if nothing plausible was found."""
    file_trim = [c.strip() for c in cur_lines]
    btrim = [b.strip() for b in block]
    m = len(btrim)
    if m == 0:
        return None

    # the lines that carry signal (non-blank), with their offset inside the block
    signal = [(r, t) for r, t in enumerate(btrim) if t]
    if not signal:
        return None

    # rank candidate anchor lines: most distinctive first, but only ones that
    # actually occur in the file
    ranked = []
    for r, t in signal:
        d = _distinctiveness(t)
        if d:
            hits = [i for i, ft in enumerate(file_trim) if ft == t]
            if hits:
                ranked.append((len(hits), -d, r, t, hits))
    if not ranked:
        return None
    ranked.sort()  # fewest occurrences first, then most distinctive

    # gather candidate block-start positions from the strongest few anchors
    starts = {}
    for _n, _d, r, t, hits in ranked[:3]:
        for f in hits:
            s = f - r                       # implied block start
            if 0 <= s and s + m <= len(cur_lines):
                starts.setdefault(s, (t, f))  # remember which anchor pinned it

    if not starts:
        return None

    def confirm(s):
        return sum(1 for r, t in signal if file_trim[s + r] == t)

    scored = []
    for s, (anchor_t, anchor_f) in starts.items():
        got = confirm(s)
        gap = abs((s + 1) - declared_line) if declared_line else 0
        scored.append({
            "start": s, "confirmed": got, "signal": len(signal),
            "score": round(got / len(signal), 3), "gap": gap,
            "anchor": anchor_t, "anchor_line": anchor_f + 1,
        })

    # best: most context confirmed; on a tie, the one nearest the declared line
    best = max(scored, key=lambda c: (c["score"], -c["gap"]))
    if best["score"] < 0.5:
        return None

    s = best["start"]
    # is the runner-up close? if two candidates tie on context, we relied on the
    # line number to choose — flag that as lower certainty
    ties = [c for c in scored if c["score"] == best["score"]]
    best["ambiguous"] = len(ties) > 1
    best["confident"] = best["score"] >= 0.75 and not best["ambiguous"]
    best["end"] = s + m
    best["start_1"] = s + 1
    best["snippet"] = "\n".join(cur_lines[s:best["end"]][:24])
    return best


def locate_hints(cur_lines, section):
    """A note dict per hunk describing where it lands (for prompt + report)."""
    notes = []
    for idx, h in enumerate(section.hunks, 1):
        note = locate(cur_lines, old_block(h), declared_line=h.old_start)
        if note is None:
            note = {"idx": idx, "start_1": None, "found": False}
        else:
            note["idx"] = idx
            note["found"] = True
        notes.append(note)
    return notes


# --------------------------------------------------------------------------- #
# the merge — Claude does the edit, like a person would
# --------------------------------------------------------------------------- #


MERGE_PROMPT = """\
You are integrating a vendor security patch into a source file that has DRIFTED \
from the revision the patch was written against. The patch's @@ line numbers are \
unreliable — IGNORE them. Use each hunk's surrounding context lines and its \
removed ('-') lines to find the right place in the CURRENT file, then make the \
change the way a careful engineer would when the old context no longer matches \
exactly.

Hard rules:
- Output the COMPLETE merged file and NOTHING else. No prose, no explanation, no \
markdown fences.
- Change ONLY what the patch requires. Every other line stays byte-for-byte \
identical — indentation, comments, and blank lines included.
- Match the current file's own indentation and brace/style for any lines you add.
- If the patch's change is already present in the current file, leave it as-is; \
do not duplicate it.

=== CURRENT FILE ({relpath}) ===
{current}

=== VENDOR PATCH (its context and line numbers may be stale) ===
{patch}

=== WHERE THE CHANGES LIKELY GO (located by matching each hunk against the current file) ===
{hints}
"""


def build_hints_text(notes):
    out = []
    for n in notes:
        idx = n["idx"]
        if not n.get("found"):
            out.append(f"Hunk {idx} → no confident location found; place it from "
                       "the surrounding code.")
            continue
        cert = ("high confidence" if n["confident"]
                else "LOW confidence — verify" if n.get("ambiguous")
                else "medium confidence")
        out.append(
            f"Hunk {idx} → current lines {n['start_1']}-{n['end']} "
            f"({n['confirmed']}/{n['signal']} context lines confirmed, {cert}). "
            f"Anchored on `{n['anchor']}` at line {n['anchor_line']}.\n"
            + n["snippet"])
    return "\n\n".join(out)


def merge_file(current_text, patch_text, relpath, notes, model, on_text=None):
    """Ask the Claude CLI for the merged file. Returns merged text or None."""
    prompt = MERGE_PROMPT.format(relpath=relpath, current=current_text,
                                 patch=patch_text[:8000],
                                 hints=build_hints_text(notes))
    if on_text:
        out = stream_claude(prompt, on_text, model)
    else:
        out = ask_claude(prompt, model)
    if not out:
        return None
    merged = _strip_fences(out)
    # sanity: a real merge is not empty and not wildly shorter than the input
    if not merged.strip() or len(merged) < len(current_text) * 0.5:
        return None
    if not merged.endswith("\n"):
        merged += "\n"
    return merged


# --------------------------------------------------------------------------- #
# resolve which local file each patch section targets
# --------------------------------------------------------------------------- #


def section_paths(patch_text):
    """(relpath, FileSection) for each real file section in the patch."""
    _pre, sections = pm.parse_patch(patch_text)
    strip = pm.detect_strip(sections)
    out = []
    for s in sections:
        raw = s.new_path_raw or s.old_path_raw
        if not raw:
            continue
        rel = pm._strip_prefix(pm._clean_path_label(raw), strip)
        if rel in ("/dev/null", ""):
            rel = pm._strip_prefix(pm._clean_path_label(s.old_path_raw or ""), strip)
        out.append((rel, s))
    return out


def resolve_target(rel, path_arg, dir_arg, use_p4):
    """Depot-or-local target for a patch section, given --path or --dir."""
    if path_arg:                      # explicit single file wins
        return path_arg
    base = dir_arg.rstrip("/")
    if base.endswith("..."):          # //depot/npu/...  -> //depot/npu/<rel>
        base = base[:-3].rstrip("/")
    cand = base + "/" + rel
    if not cand.startswith("//") and not os.path.isfile(cand):
        # fall back to basename inside the dir
        alt = os.path.join(base, os.path.basename(rel))
        if os.path.isfile(alt):
            return alt
    return cand


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #


def _status_block(msgs):
    lines = "".join(f'<div class="p4line">{rv._esc(m)}</div>' for m in msgs)
    return f'<div class="p4box">{lines}</div>'


def render_report(patch_name, results, patch_text):
    merged_n = sum(1 for r in results if r["merged"] and r["changed"])
    noop_n = sum(1 for r in results if r["merged"] and not r["changed"])
    fail_n = sum(1 for r in results if not r["merged"])

    if fail_n and not merged_n:
        role, stamp, head = "danger", "COULD NOT MERGE", \
            "No file could be prepared or merged — see the p4 status below."
    elif fail_n:
        role, stamp, head = "warn", f"{merged_n} MERGED · {fail_n} FAILED", \
            "Some files merged; others could not be mapped or edited."
    elif noop_n and not merged_n:
        role, stamp, head = "accent", "NO CHANGE NEEDED", \
            "The patch is already present in every target file."
    else:
        role, stamp, head = "good", f"{merged_n} FILE(S) MERGED", \
            "Opened for edit and merged in your workspace. Review, then submit yourself."

    parts = [rv._head(patch_name)]
    parts.append('<div class="wrap">')
    parts.append('<span class="eyebrow">p4 patch merge</span>')
    parts.append(f'<div class="verdict {role}"><div class="stamp">{rv._esc(stamp)}</div>'
                 f'<div><h1>{rv._esc(head)}</h1>'
                 f'<div class="patchname">{rv._esc(patch_name)} · never submitted — '
                 f'your changelist is left open for review</div></div></div>')

    for r in results:
        parts.append('<section>')
        title = r["rel"]
        badge = ("merged" if r["merged"] and r["changed"]
                 else "no change" if r["merged"] else "failed")
        bcls = ("good" if badge == "merged" else "accent" if badge == "no change"
                else "danger")
        parts.append(f'<h2>{rv._esc(title)} '
                     f'<span class="pill {bcls}">{badge}</span></h2>')
        parts.append(f'<div class="sub mono">{rv._esc(r["target"])}</div>')
        parts.append(_status_block(r["p4"]))

        if r["hints"]:
            hint_rows = []
            for n in r["hints"]:
                idx = n["idx"]
                if not n.get("found"):
                    hint_rows.append(f"hunk {idx}: located from surrounding code")
                    continue
                cert = ("✓ high" if n["confident"]
                        else "⚠ low (tie)" if n.get("ambiguous") else "medium")
                hint_rows.append(
                    f"hunk {idx}: lines {n['start_1']}–{n['end']} · "
                    f"{n['confirmed']}/{n['signal']} confirmed · anchor "
                    f"`{n['anchor']}` @ {n['anchor_line']} · {cert}")
            parts.append('<div class="locbox"><b>Located by content</b> '
                         '(patch line numbers used only as a tiebreak):<br>'
                         + rv._esc("  |  ".join(hint_rows)) + "</div>")

        if r["merged"] and r["changed"]:
            parts.append(rv._sxs(r["before"], r["after"]))
            if r.get("p4diff"):
                parts.append('<details class="whyblock"><summary>Raw '
                             '<code>p4 diff</code></summary>'
                             + rv._patch_html(r["p4diff"]) + "</details>")
        elif r["merged"]:
            parts.append('<div class="banner accent">No change — the patch is '
                         'already present in this file.</div>')
        else:
            parts.append('<div class="banner danger">This file was not merged. '
                         'The p4 status above shows why (usually: not mapped in '
                         'your client workspace).</div>')

        parts.append('<details class="whyblock"><summary>Vendor patch</summary>'
                     + rv._patch_html(patch_text) + "</details>")
        parts.append('</section>')

    parts.append('<div id="toast" class="toast"></div>')
    parts.append("</div>")
    parts.append(f'<script>{rv._SCRIPT}</script></body></html>')
    return "".join(parts)


_EXTRA_CSS = """
<style>
.p4box{margin-top:12px;background:var(--code-bg);border:1px solid var(--line);
  border-radius:9px;padding:12px 14px;font-family:var(--mono);font-size:12.5px}
.p4line{padding:2px 0;color:var(--muted)} .p4line:first-child{color:var(--ink)}
.sub{color:var(--faint);font-size:12px;margin:4px 0 2px}
.pill{font-family:var(--mono);font-size:11px;font-weight:600;border-radius:999px;
  padding:3px 10px;vertical-align:middle}
.pill.good{color:var(--good);background:var(--good-bg);border:1px solid var(--good-line)}
.pill.accent{color:var(--accent);background:var(--accent-bg);border:1px solid var(--accent-line)}
.pill.danger{color:var(--danger);background:var(--danger-bg);border:1px solid var(--danger-line)}
.locbox{margin:12px 0;background:var(--surface-2);border:1px solid var(--line);
  border-radius:8px;padding:10px 12px;font-size:12.5px;color:var(--muted)}
.locbox b{color:var(--ink)}
</style>
"""


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Perforce-native patch merger: map + revert + sync + edit, "
                    "then merge by content with the Claude CLI. Never submits.")
    ap.add_argument("patch")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--path", help="one file: a depot path (//...) or a local path")
    g.add_argument("--dir", help="a folder (//depot/npu/... or a local dir); the "
                                 "files come from the patch")
    ap.add_argument("--model", help="model for the Claude CLI (e.g. sonnet, opus)")
    ap.add_argument("--no-p4", action="store_true",
                    help="skip all p4 steps and merge the local file in place")
    ap.add_argument("--html", help="report path (default: patch-reports/<patch>.p4.html)")
    ap.add_argument("--no-open", action="store_true")
    args = ap.parse_args(argv)

    with open(args.patch, encoding="utf-8", errors="replace") as fh:
        patch_text = fh.read()
    use_p4 = not args.no_p4

    secs = section_paths(patch_text)
    if not secs:
        print("no file sections found in the patch", file=sys.stderr)
        return 1

    results = []
    for rel, section in secs:
        target = resolve_target(rel, args.path, args.dir, use_p4)
        print(f"\n=== {rel}  ({target}) ===", file=sys.stderr)

        local, msgs, ok = p4_prepare(target, use_p4)
        rec = {"rel": rel, "target": target, "p4": msgs, "merged": False,
               "changed": False, "before": "", "after": "", "hints": None,
               "p4diff": ""}
        if not ok or not local:
            for m in msgs:
                print("  " + m, file=sys.stderr)
            results.append(rec)
            continue
        for m in msgs:
            print("  " + m, file=sys.stderr)

        before = pm.to_lf(pm._read(local)).decode("utf-8", "replace")
        cur_lines = before.split("\n")
        notes = locate_hints(cur_lines, section)
        rec["hints"] = notes
        for n in notes:
            if n.get("found"):
                cert = ("high" if n["confident"]
                        else "low/tie" if n.get("ambiguous") else "medium")
                where = (f"lines {n['start_1']}-{n['end']} "
                         f"({n['confirmed']}/{n['signal']} confirmed, {cert}; "
                         f"anchor `{n['anchor']}` @ {n['anchor_line']})")
            else:
                where = "from surrounding code (no anchor matched)"
            print(f"  · hunk {n['idx']} located: {where}", file=sys.stderr)

        # single-file section patch: pass just this file's patch text if we can
        print("  · asking Claude to merge…", file=sys.stderr)

        def _tick(t):
            sys.stderr.write(t)
            sys.stderr.flush()

        merged = merge_file(before, patch_text, rel, notes, args.model,
                            on_text=_tick if sys.stderr.isatty() else None)
        sys.stderr.write("\n")
        if not merged:
            rec["p4"].append("✗ Claude did not return a usable merge")
            results.append(rec)
            continue

        rec["merged"] = True
        rec["before"] = before
        rec["after"] = merged
        rec["changed"] = (merged.strip() != before.strip())
        if rec["changed"]:
            # preserve the file's original line ending, then write it back
            ending = pm.detect_line_ending(pm._read(local))
            with open(local, "wb") as fh:
                fh.write(pm.apply_line_ending(merged.encode("utf-8"), ending))
            print(f"  ✓ wrote merged file: {local}", file=sys.stderr)
            rec["p4diff"] = p4_diff(target)
        else:
            print("  · no change (patch already present)", file=sys.stderr)
        results.append(rec)

    # ---- report ----
    page = render_report(os.path.basename(args.patch), results, patch_text)
    page = page.replace("</head>", _EXTRA_CSS + "</head>", 1)
    html_path = args.html
    if not html_path:
        rdir = os.path.join(os.path.dirname(os.path.abspath(args.patch)),
                            "patch-reports")
        os.makedirs(rdir, exist_ok=True)
        stem = os.path.splitext(os.path.basename(args.patch))[0]
        html_path = os.path.join(rdir, stem + ".p4.html")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    print(f"\nreport: {html_path}", file=sys.stderr)

    if not args.no_open:
        import webbrowser
        webbrowser.open("file://" + os.path.abspath(html_path))

    merged_n = sum(1 for r in results if r["merged"] and r["changed"])
    fail_n = sum(1 for r in results if not r["merged"])
    return 0 if merged_n and not fail_n else (1 if fail_n and not merged_n else 0)


if __name__ == "__main__":
    sys.exit(main())
