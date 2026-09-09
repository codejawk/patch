#!/usr/bin/env python3
"""
patch-merger — apply a vendor CVE patch to a target file or source tree.

Given a patch (Qualcomm / MediaTek / LSI dialect) and a file path (or a source
tree root), this:

  1. parses the patch, detecting vendor dialect + strip level,
  2. runs a safety scan (rejects path traversal, absolute paths, binary
     payloads, malformed hunks, and metadata-less patches) BEFORE touching
     any file,
  3. resolves the vendor path to the real path in the tree (exact -> basename
     search -> content/anchor search),
  4. detects an already-applied patch as a no-op (idempotency),
  5. applies at escalating tolerance tiers:
        T1  git apply        (strict, exact context)
        T2  patch -F0        (offsets may slide)
        T3  patch -F2 -l     (fuzzy context + whitespace-insensitive)
  6. preserves the target file's line endings (LF / CRLF) on write-back,
  7. verifies the result: a hunk that only lands with fuzz > 0 means the
     region was structurally altered -> status "needs-review", verified=false.
     (This is what catches the dangerous "every tier succeeds and is wrong"
     refactor case.)

It emits a per-file JSON report and, with --in-place / --out, writes results.

Stdlib only. Requires `git` and GNU `patch` on PATH for the apply tiers.

Usage:
  merge.py <patch> --file <target>            # single-file patch onto one file
  merge.py <patch> --root <tree>              # multi-file patch onto a tree
  merge.py <patch> --root <tree> --in-place   # write results back into the tree
  merge.py <patch> --root <tree> --out <dir>  # write merged files under <dir>
  merge.py <patch> --file <target> --json     # JSON report only
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


class Hunk:
    def __init__(self, header, old_start, old_len, new_start, new_len, lines):
        self.header = header
        self.old_start = old_start
        self.old_len = old_len
        self.new_start = new_start
        self.new_len = new_len
        self.lines = lines  # list of raw hunk body lines incl. leading ' ','+','-'

    def counts(self):
        ctx = add = rem = 0
        for ln in self.lines:
            if not ln:
                ctx += 1  # a bare empty line counts as context
                continue
            c = ln[0]
            if c == " ":
                ctx += 1
            elif c == "+":
                add += 1
            elif c == "-":
                rem += 1
            elif c == "\\":  # "\ No newline at end of file"
                pass
            else:
                ctx += 1
        return ctx, add, rem


class FileSection:
    def __init__(self):
        self.old_path_raw = None   # raw text after '--- '
        self.new_path_raw = None   # raw text after '+++ '
        self.diff_git_line = None  # 'diff --git a/... b/...' if present
        self.is_new_file = False
        self.is_delete_file = False
        self.is_binary = False
        self.hunks = []
        # filled in during resolution:
        self.vendor_path = None
        self.resolved_path = None
        self.resolution_lane = None


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def detect_dialect(text: str) -> str:
    if "diff --git" in text or re.search(r"^From [0-9a-f]{7,40} ", text, re.M):
        return "qualcomm"
    if "MediaTek Security Patch" in text or "CR Number" in text:
        return "mediatek"
    if re.search(r"^Index:", text, re.M) or "(working copy)" in text:
        return "lsi"
    return "unknown"


def _clean_path_label(raw: str) -> str:
    """Strip trailing tab-metadata and SVN/LSI '(revision N)' / '(working copy)'
    suffixes from a --- / +++ path label."""
    if raw is None:
        return None
    s = raw.strip()
    # tab-separated timestamp/metadata (unified diff convention)
    if "\t" in s:
        s = s.split("\t", 1)[0].strip()
    # LSI / SVN style suffixes:  "npu/core/foo.c  (working copy)"
    s = re.sub(r"\s+\((?:working copy|revision\s+\d+|nonexistent|date[^)]*)\)\s*$",
               "", s)
    return s.strip()


def _strip_prefix(path: str, strip: int) -> str:
    if path in ("/dev/null", "dev/null"):
        return "/dev/null"
    parts = path.split("/")
    if strip > 0:
        parts = parts[strip:]
    return "/".join(parts)


def detect_strip(sections) -> int:
    """git-style a/ b/ prefixes => strip 1, bare paths => strip 0."""
    for s in sections:
        for raw in (s.old_path_raw, s.new_path_raw):
            if not raw:
                continue
            p = _clean_path_label(raw)
            if p == "/dev/null":
                continue
            if p.startswith("a/") or p.startswith("b/"):
                return 1
            return 0
    return 0


def parse_patch(text: str):
    """Split a patch into a preamble + a list of FileSections with hunks."""
    lines = text.splitlines()
    sections = []
    cur = None
    cur_hunk = None
    i = 0
    n = len(lines)
    preamble_end = None

    def close_hunk():
        nonlocal cur_hunk
        if cur is not None and cur_hunk is not None:
            cur.hunks.append(cur_hunk)
            cur_hunk = None

    while i < n:
        ln = lines[i]

        if ln.startswith("diff --git "):
            close_hunk()
            cur = FileSection()
            cur.diff_git_line = ln
            sections.append(cur)
            if preamble_end is None:
                preamble_end = i
            i += 1
            continue

        if ln.startswith("Index: "):
            # LSI section marker; a --- / +++ pair follows.
            close_hunk()
            cur = FileSection()
            sections.append(cur)
            if preamble_end is None:
                preamble_end = i
            i += 1
            continue

        if ln.startswith("new file mode"):
            if cur is not None:
                cur.is_new_file = True
            i += 1
            continue
        if ln.startswith("deleted file mode"):
            if cur is not None:
                cur.is_delete_file = True
            i += 1
            continue

        if ln.startswith("GIT binary patch") or re.match(r"^literal \d+", ln):
            if cur is None:
                cur = FileSection()
                sections.append(cur)
            cur.is_binary = True
            i += 1
            continue

        if ln.startswith("--- "):
            # start of a file section if not already inside one with a +++ set,
            # or the driver of a new section for bare-diff dialects.
            if cur is None or cur.new_path_raw is not None:
                close_hunk()
                cur = FileSection()
                sections.append(cur)
                if preamble_end is None:
                    preamble_end = i
            cur.old_path_raw = ln[4:]
            if cur.old_path_raw.strip() in ("/dev/null", "dev/null"):
                cur.is_new_file = True
            i += 1
            continue

        if ln.startswith("+++ "):
            if cur is None:
                cur = FileSection()
                sections.append(cur)
            cur.new_path_raw = ln[4:]
            if cur.new_path_raw.strip() in ("/dev/null", "dev/null"):
                cur.is_delete_file = True
            i += 1
            continue

        m = HUNK_RE.match(ln)
        if m and cur is not None:
            close_hunk()
            old_start = int(m.group(1))
            old_len = int(m.group(2)) if m.group(2) is not None else 1
            new_start = int(m.group(3))
            new_len = int(m.group(4)) if m.group(4) is not None else 1
            cur_hunk = Hunk(ln, old_start, old_len, new_start, new_len, [])
            i += 1
            # Collect the body bounded by the line counts the header declares:
            # a hunk holds exactly old_len old-side lines and new_len new-side
            # lines. Bounding this way stops us swallowing the "-- " git
            # signature or free text that trails the diff.
            old_seen = new_seen = 0
            while i < n and (old_seen < old_len or new_seen < new_len):
                b = lines[i]
                if (b.startswith("@@ ") or b.startswith("diff --git ")
                        or b.startswith("Index: ")
                        or (b.startswith("--- ") and i + 1 < n
                            and lines[i + 1].startswith("+++ "))):
                    break
                if b.startswith("\\"):  # "\ No newline at end of file"
                    cur_hunk.lines.append(b)
                    i += 1
                    continue
                c = b[0] if b else " "
                if c == " " or b == "":
                    old_seen += 1
                    new_seen += 1
                elif c == "-":
                    old_seen += 1
                elif c == "+":
                    new_seen += 1
                else:
                    break  # a non-body line ends the hunk
                cur_hunk.lines.append(b)
                i += 1
            close_hunk()
            continue

        i += 1

    preamble = "\n".join(lines[: preamble_end if preamble_end is not None else n])
    # drop sections that are pure noise (no paths, no hunks, not binary)
    sections = [s for s in sections
                if s.old_path_raw or s.new_path_raw or s.hunks or s.is_binary]
    return preamble, sections


# --------------------------------------------------------------------------- #
# Metadata
# --------------------------------------------------------------------------- #


def extract_metadata(text: str, dialect: str) -> dict:
    def find(*patterns):
        for pat in patterns:
            m = re.search(pat, text, re.I | re.M)
            if m:
                return m.group(1).strip()
        return None

    cve = find(r"\b(CVE-\d{4}-\d{4,7})\b")
    cr = find(
        r"^\s*CR-Id\s*:\s*(.+)$",         # qualcomm
        r"^\s*CR\s*Number\s*:\s*(.+)$",   # mediatek
        r"^\s*CR\s*:\s*(.+)$",            # lsi
    )
    if cr and re.fullmatch(r"\(?none\)?", cr, re.I):
        cr = None
    severity = find(r"^\s*Severity\s*:\s*(.+)$")
    component = find(
        r"^\s*Component\s*:\s*(.+)$",     # qualcomm
        r"^\s*Module\s*:\s*(.+)$",        # mediatek
    )
    return {"cve": cve, "cr": cr, "severity": severity, "component": component}


# --------------------------------------------------------------------------- #
# Safety scan
# --------------------------------------------------------------------------- #


def safety_scan(sections, metadata, text: str) -> list:
    findings = []

    for s in sections:
        for raw in (s.old_path_raw, s.new_path_raw):
            if not raw:
                continue
            p = _clean_path_label(raw)
            if p == "/dev/null":
                continue
            # strip a/ b/ leaders for the traversal check
            probe = re.sub(r"^[ab]/", "", p)
            if os.path.isabs(probe) or probe.startswith("/"):
                findings.append(f"absolute path in patch: {p!r}")
            # any parent-traversal segment
            segs = probe.split("/")
            if ".." in segs:
                findings.append(f"path traversal outside workspace: {p!r}")

    for s in sections:
        if s.is_binary:
            findings.append("binary payload (GIT binary patch) — refused")

    # hunk header line-count must match the body it carries
    for s in sections:
        for h in s.hunks:
            ctx, add, rem = h.counts()
            old_body, new_body = ctx + rem, ctx + add
            if old_body != h.old_len:
                findings.append(
                    f"malformed hunk {h.header!r}: header claims {h.old_len} "
                    f"old lines, body has {old_body}")
            if new_body != h.new_len:
                findings.append(
                    f"malformed hunk {h.header!r}: header claims {h.new_len} "
                    f"new lines, body has {new_body}")

    # a patch with neither a CVE nor a CR is itself a rejection signal
    if not metadata.get("cve") and not metadata.get("cr"):
        findings.append("no CVE and no CR — untraceable, refused")

    # de-dup preserving order
    seen = set()
    out = []
    for f in findings:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


# --------------------------------------------------------------------------- #
# Path resolution
# --------------------------------------------------------------------------- #


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


def resolve_path(section, root, strip, forced_target=None):
    """Return (resolved_relpath, lane) or (None, 'unresolved')."""
    if forced_target is not None:
        rel = os.path.relpath(forced_target, root)
        return rel, "forced"

    if section.is_new_file:
        # target is the +++ path; it should not exist yet.
        vp = _strip_prefix(_clean_path_label(section.new_path_raw), strip)
        return vp, "new-file"

    vp = section.vendor_path
    # Lane A: exact path under root
    cand = os.path.join(root, vp)
    if os.path.isfile(cand):
        return vp, "exact"

    # Lane B: basename search across the tree
    base = os.path.basename(vp)
    matches = []
    for dp, _dn, fns in os.walk(root):
        if ".git" in dp.split(os.sep):
            continue
        for fn in fns:
            if fn == base:
                matches.append(os.path.relpath(os.path.join(dp, fn), root))
    if len(matches) == 1:
        return matches[0], "filename-search"
    if len(matches) > 1:
        # rank by directory-path similarity to the vendor path
        matches.sort(key=lambda m: difflib.SequenceMatcher(
            None, os.path.dirname(m), os.path.dirname(vp)).ratio(), reverse=True)
        return matches[0], "filename-search"

    # Lane C: content/anchor search — find the file that contains this hunk's
    # context lines (handles renamed files whose basename also changed).
    anchor = _anchor_lines(section)
    if anchor:
        best = None
        best_score = 0.0
        for dp, _dn, fns in os.walk(root):
            if ".git" in dp.split(os.sep):
                continue
            for fn in fns:
                fp = os.path.join(dp, fn)
                try:
                    txt = _read(fp).decode("utf-8", "replace")
                except OSError:
                    continue
                score = _anchor_score(anchor, txt)
                if score > best_score:
                    best_score = score
                    best = os.path.relpath(fp, root)
        if best is not None and best_score >= 0.8:
            return best, "content-search"

    return None, "unresolved"


def _anchor_lines(section):
    """Longest run of context lines from the section's hunks — a fingerprint of
    the surrounding code."""
    ctx = []
    for h in section.hunks:
        for ln in h.lines:
            if ln.startswith(" ") and ln.strip():
                ctx.append(ln[1:].strip())
    return ctx


def _anchor_score(anchor, text):
    norm = {re.sub(r"\s+", " ", a) for a in anchor if a}
    if not norm:
        return 0.0
    body = {re.sub(r"\s+", " ", l.strip()) for l in text.splitlines()}
    hit = sum(1 for a in norm if a in body)
    return hit / len(norm)


# --------------------------------------------------------------------------- #
# Line endings
# --------------------------------------------------------------------------- #


def detect_line_ending(data: bytes) -> str:
    if b"\r\n" in data:
        return "CRLF"
    return "LF"


def to_lf(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def apply_line_ending(data: bytes, ending: str) -> bytes:
    lf = to_lf(data)
    if ending == "CRLF":
        return lf.replace(b"\n", b"\r\n")
    return lf


# --------------------------------------------------------------------------- #
# Normalized patch (real paths, strip 1, LF) for the apply engine
# --------------------------------------------------------------------------- #


def build_normalized_patch(sections, resolved):
    """Emit a git-style, -p1, LF patch whose paths are the resolved real paths."""
    out = []
    for s in sections:
        rp = resolved[id(s)]
        if rp is None:
            continue
        a = "/dev/null" if s.is_new_file else f"a/{rp}"
        b = "/dev/null" if s.is_delete_file else f"b/{rp}"
        out.append(f"diff --git a/{rp} b/{rp}")
        if s.is_new_file:
            out.append("new file mode 100644")
        out.append(f"--- {a}")
        out.append(f"+++ {b}")
        for h in s.hunks:
            out.append(h.header if h.header.startswith("@@ ") else _rebuild_header(h))
            out.extend(h.lines)
    return "\n".join(out) + "\n"


def _rebuild_header(h):
    return f"@@ -{h.old_start},{h.old_len} +{h.new_start},{h.new_len} @@"


# --------------------------------------------------------------------------- #
# Apply engine
# --------------------------------------------------------------------------- #


def _run(cmd, cwd, stdin=""):
    return subprocess.run(cmd, cwd=cwd, input=stdin, capture_output=True,
                          text=True)


FUZZ_RE = re.compile(r"with fuzz (\d+)(?:\s*\(offset (-?\d+) lines?\))?")
OFFSET_RE = re.compile(r"\(offset (-?\d+) lines?\)")


def _stage_tree(root, workdir, resolved, sections):
    """Copy just the files the patch touches into workdir, normalized to LF,
    remembering each one's original line ending."""
    endings = {}
    for s in sections:
        rp = resolved[id(s)]
        if rp is None or s.is_new_file:
            continue
        src = os.path.join(root, rp)
        dst = os.path.join(workdir, rp)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        data = _read(src)
        endings[rp] = detect_line_ending(data)
        with open(dst, "wb") as fh:
            fh.write(to_lf(data))
    return endings


def apply_tiers(root, sections, resolved, normalized_patch):
    """Try no-op detection then T1->T2->T3 in a scratch copy. Returns a dict."""
    result = {"tier": None, "fuzz": 0, "offset": 0, "status": None,
              "workdir": None, "endings": {}}
    tmp = tempfile.mkdtemp(prefix="patchmerge_")
    endings = _stage_tree(root, tmp, resolved, sections)
    result["endings"] = endings
    patch_path = os.path.join(tmp, "_change.patch")
    with open(patch_path, "w", newline="\n") as fh:
        fh.write(normalized_patch)

    # No-op / already-applied: reverse-apply cleanly?
    rev = _run(["git", "apply", "-p1", "--reverse", "--check",
                "--whitespace=nowarn", patch_path], cwd=tmp)
    fwd_check = _run(["git", "apply", "-p1", "--check",
                      "--whitespace=nowarn", patch_path], cwd=tmp)
    if rev.returncode == 0 and fwd_check.returncode != 0:
        result["status"] = "no-op"
        result["tier"] = 0
        result["workdir"] = tmp
        return result

    # T1 strict: git apply
    if fwd_check.returncode == 0:
        ap = _run(["git", "apply", "-p1", "--whitespace=nowarn", patch_path],
                  cwd=tmp)
        if ap.returncode == 0:
            result.update(tier=1, status="applied", workdir=tmp)
            return result

    # T2 offset-tolerant: patch -F0
    _restage(root, tmp, resolved, sections)
    t2 = _run(["patch", "-p1", "-F0", "--verbose", "-i", patch_path], cwd=tmp,
              stdin="")
    if t2.returncode == 0:
        result.update(tier=2, status="applied", workdir=tmp,
                      offset=_max_offset(t2.stdout))
        return result

    # T3 fuzzy + whitespace-insensitive: patch -F2 -l
    _restage(root, tmp, resolved, sections)
    t3 = _run(["patch", "-p1", "-F2", "-l", "--verbose", "-i", patch_path],
              cwd=tmp, stdin="")
    if t3.returncode == 0:
        fuzz = _max_fuzz(t3.stdout)
        result.update(tier=3, status="applied", workdir=tmp,
                      fuzz=fuzz, offset=_max_offset(t3.stdout))
        return result

    result.update(tier=None, status="rejected", workdir=tmp)
    return result


def _restage(root, workdir, resolved, sections):
    for s in sections:
        rp = resolved[id(s)]
        if rp is None or s.is_new_file:
            continue
        # remove any .orig/.rej and reset the file to LF pre-image
        for suffix in ("", ".orig", ".rej"):
            p = os.path.join(workdir, rp + suffix)
            if suffix and os.path.exists(p):
                os.remove(p)
        src = os.path.join(root, rp)
        dst = os.path.join(workdir, rp)
        with open(dst, "wb") as fh:
            fh.write(to_lf(_read(src)))
    # also drop any newly created files from a failed prior tier
    for s in sections:
        if s.is_new_file:
            rp = resolved[id(s)]
            p = os.path.join(workdir, rp)
            if os.path.exists(p):
                os.remove(p)


def _max_fuzz(out):
    vals = [int(g[0]) for g in FUZZ_RE.findall(out)]
    return max(vals) if vals else 0


def _max_offset(out):
    offs = [abs(int(m)) for m in OFFSET_RE.findall(out)]
    return max(offs) if offs else 0


# --------------------------------------------------------------------------- #
# Re-indentation to house style (for whitespace-dialect patches)
# --------------------------------------------------------------------------- #


def house_indent_style(original_lf: bytes):
    tabs = spaces = 0
    for ln in original_lf.decode("utf-8", "replace").splitlines():
        if ln.startswith("\t"):
            tabs += 1
        elif ln.startswith("    "):
            spaces += 1
    if tabs > spaces:
        return "tab"
    if spaces > tabs:
        return "space"
    return None


def reindent_added_lines(original_lf: bytes, result_lf: bytes, style):
    """Convert leading whitespace of newly-inserted lines to the file's style."""
    if style is None:
        return result_lf, False
    o = original_lf.decode("utf-8", "replace").splitlines()
    r = result_lf.decode("utf-8", "replace").splitlines()
    sm = difflib.SequenceMatcher(None, o, r)
    changed = False
    for tag, _i1, _i2, j1, j2 in sm.get_opcodes():
        if tag in ("insert", "replace"):
            for j in range(j1, j2):
                fixed = _convert_indent(r[j], style)
                if fixed != r[j]:
                    r[j] = fixed
                    changed = True
    if not changed:
        return result_lf, False
    trailing = b"\n" if result_lf.endswith(b"\n") else b""
    return ("\n".join(r)).encode("utf-8") + trailing, True


def _convert_indent(line, style):
    m = re.match(r"^([ \t]*)", line)
    lead = m.group(1)
    rest = line[len(lead):]
    if style == "tab":
        # turn runs of (up to) 4 spaces into a tab, keep existing tabs
        spaces = lead.replace("\t", "    ")
        n = len(spaces)
        return "\t" * (n // 4) + " " * (n % 4) + rest
    else:  # space
        return lead.replace("\t", "    ") + rest


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def merge_patch(patch_text, root, forced_target=None):
    """Core entry point. Returns (report_dict, writes) where writes maps
    resolved_relpath -> bytes to write (only populated when safe to apply)."""
    dialect = detect_dialect(patch_text)
    _pre, sections = parse_patch(patch_text)
    metadata = extract_metadata(patch_text, dialect)

    report = {
        "dialect": dialect,
        "metadata": metadata,
        "strip": None,
        "safety": {"passed": True, "findings": []},
        "overall_status": None,
        "files": [],
    }

    # ---- safety scan (before any file I/O) ----
    findings = safety_scan(sections, metadata, patch_text)
    if findings:
        report["safety"] = {"passed": False, "findings": findings}
        report["overall_status"] = "rejected"
        report["strip"] = detect_strip(sections)
        for s in sections:
            report["files"].append({
                "vendor_path": _safe_vp(s),
                "resolved_path": None,
                "resolution_lane": "n/a",
                "tier": None, "fuzz": 0, "offset_delta": 0,
                "line_ending": None, "status": "rejected", "verified": False,
                "reason": "patch failed the safety scan",
            })
        return report, {}

    strip = detect_strip(sections)
    report["strip"] = strip

    # ---- resolve paths ----
    resolved = {}
    for s in sections:
        s.vendor_path = _safe_vp(s)
        rp, lane = resolve_path(s, root, strip,
                                forced_target if len(sections) == 1 else None)
        resolved[id(s)] = rp
        s.resolved_path = rp
        s.resolution_lane = lane

    unresolved = [s for s in sections if resolved[id(s)] is None]

    # ---- apply (all-or-nothing across the whole patch) ----
    apply_result = {"tier": None, "fuzz": 0, "offset": 0, "status": "rejected",
                    "workdir": None, "endings": {}}
    writes = {}
    if not unresolved:
        normalized = build_normalized_patch(sections, resolved)
        apply_result = apply_tiers(root, sections, resolved, normalized)

    status = apply_result["status"]
    tier = apply_result["tier"]
    fuzz = apply_result["fuzz"]
    offset = apply_result["offset"]
    workdir = apply_result["workdir"]
    endings = apply_result["endings"]

    # ---- verification + write staging ----
    # A hunk that only lands with fuzz > 0 means context was discarded -> the
    # region is structurally different from what the vendor patched. Even
    # though `patch` reports success, that result is not trustworthy.
    verified = status == "applied" and (tier in (1, 2) or (tier == 3 and fuzz == 0))
    if status == "applied" and not verified:
        status = "needs-review"

    per_file = []
    for s in sections:
        rp = resolved[id(s)]
        vp = s.vendor_path
        if rp is None:
            per_file.append(_file_entry(
                vp, None, s.resolution_lane, None, 0, 0, None,
                "rejected", False,
                "vendor path could not be resolved in the target tree — "
                "confident reject, escalate for a manual rebase"))
            continue

        ending = "LF" if s.is_new_file else endings.get(rp, "LF")
        f_status = status
        f_reason = None
        f_verified = verified
        reindented = False

        if status == "no-op":
            f_status = "no-op"
            f_verified = True
            f_reason = "already present in the tree — not re-applied"
        elif status == "rejected":
            f_status = "rejected"
            f_verified = False
            f_reason = ("no tolerance tier could land this hunk — context does "
                        "not exist here; confident reject, escalate")
        elif status in ("applied", "needs-review"):
            # stage the merged file content
            src_result = os.path.join(workdir, rp)
            if os.path.isfile(src_result):
                merged_lf = _read(src_result)
                if not s.is_new_file:
                    orig_lf = to_lf(_read(os.path.join(root, rp)))
                    style = house_indent_style(orig_lf)
                    if tier == 3:
                        merged_lf, reindented = reindent_added_lines(
                            orig_lf, merged_lf, style)
                writes[rp] = apply_line_ending(merged_lf, ending)
            if f_status == "needs-review":
                f_reason = (
                    f"landed only under fuzzy matching (fuzz {fuzz}, offset "
                    f"{offset}) — the surrounding code was refactored, so the "
                    f"hunk may have landed in a place that no longer means what "
                    f"the vendor intended. A human must confirm the merged "
                    f"region before this ships.")
            else:
                bits = [f"applied at T{tier}"]
                if offset:
                    bits.append(f"offset {offset} lines (line numbers ignored)")
                if reindented:
                    bits.append("re-indented added lines to house style")
                f_reason = "; ".join(bits)

        per_file.append(_file_entry(
            vp, rp, s.resolution_lane, tier if f_status in ("applied", "needs-review") else (0 if f_status == "no-op" else None),
            fuzz, offset, ending, f_status, f_verified, f_reason, reindented))

    # ---- aggregate overall status (all-or-nothing) ----
    statuses = {e["status"] for e in per_file}
    if "rejected" in statuses:
        overall = "rejected"
        writes = {}  # all-or-nothing: don't write anything on a partial failure
    elif "needs-review" in statuses:
        overall = "needs-review"
    elif statuses == {"no-op"}:
        overall = "no-op"
        writes = {}
    elif statuses <= {"applied", "no-op"}:
        overall = "applied"
    else:
        overall = "needs-review"

    report["overall_status"] = overall
    report["files"] = per_file

    if workdir and os.path.isdir(workdir):
        shutil.rmtree(workdir, ignore_errors=True)

    return report, writes


def _safe_vp(section):
    raw = section.new_path_raw or section.old_path_raw
    if not raw:
        return None
    p = _clean_path_label(raw)
    if p == "/dev/null":
        p = _clean_path_label(section.old_path_raw or "")
    return re.sub(r"^[ab]/", "", p) if p else None


def _file_entry(vendor_path, resolved_path, lane, tier, fuzz, offset,
                line_ending, status, verified, reason, reindented=False):
    e = {
        "vendor_path": vendor_path,
        "resolved_path": resolved_path,
        "resolution_lane": lane,
        "tier": tier,
        "fuzz": fuzz,
        "offset_delta": offset,
        "line_ending": line_ending,
        "status": status,
        "verified": verified,
        "reason": reason,
    }
    if reindented:
        e["reindented"] = True
    return e


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _human_summary(report):
    md = report["metadata"]
    lines = []
    st = report["overall_status"]
    badge = {"applied": "APPLIED", "no-op": "NO-OP (already present)",
             "needs-review": "NEEDS REVIEW", "rejected": "REJECTED"}.get(st, st)
    lines.append(f"status : {badge}")
    lines.append(f"dialect: {report['dialect']}  (strip -p{report['strip']})")
    lines.append(f"cve    : {md.get('cve') or '(none)'}   cr: {md.get('cr') or '(none)'}"
                 f"   severity: {md.get('severity') or '(none)'}")
    if not report["safety"]["passed"]:
        lines.append("safety : FAILED")
        for f in report["safety"]["findings"]:
            lines.append(f"   ✗ {f}")
    for e in report["files"]:
        tier = f"T{e['tier']}" if e["tier"] else "-"
        lines.append(
            f"   [{e['status']:>12}] {e['vendor_path']}"
            + (f"  ->  {e['resolved_path']}"
               if e["resolved_path"] and e["resolved_path"] != e["vendor_path"]
               else "")
            + f"   ({e['resolution_lane']}, {tier}"
            + (f", fuzz {e['fuzz']}" if e["fuzz"] else "")
            + f", {e['line_ending'] or '-'})")
        if e.get("reason"):
            lines.append(f"                 {e['reason']}")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Apply a vendor CVE patch to a file or source tree, safely.")
    ap.add_argument("patch", help="path to the patch file")
    ap.add_argument("--file", help="target file (single-file patch)")
    ap.add_argument("--root", help="source tree root (multi-file patch)")
    ap.add_argument("--in-place", action="store_true",
                    help="write merged files back into the tree (only when the "
                         "result is 'applied')")
    ap.add_argument("--apply-anyway", action="store_true",
                    help="also write results when status is 'needs-review'")
    ap.add_argument("--out", help="write merged files under this directory")
    ap.add_argument("--json", action="store_true",
                    help="print the JSON report only")
    ap.add_argument("--html", nargs="?", const="", default=None,
                    metavar="PATH",
                    help="write the visual review page to PATH (default: a temp "
                         "file). A review page is generated on every run unless "
                         "--json is used alone.")
    ap.add_argument("--open", action="store_true", dest="open_page",
                    help="(default) open the review page in the browser")
    ap.add_argument("--no-open", action="store_true", dest="no_open",
                    help="generate the review page but do NOT open a browser")
    ap.add_argument("--findings", help="JSON file of reviewer findings to embed "
                    "in the review page: [{severity,title,body,evidence}]")
    args = ap.parse_args(argv)

    with open(args.patch, "r", encoding="utf-8", errors="replace") as fh:
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

    report, writes = merge_patch(patch_text, root, forced_target)
    report["patch_filename"] = os.path.basename(args.patch)

    # ---- visual review page (generated + opened by default) ----
    # Render BEFORE write-back so the "Before" side reads the pre-patch file,
    # even when --in-place is about to overwrite it in the tree.
    html_path = None
    make_html = (args.html is not None) or (not args.json)
    if make_html:
        html_path = _write_review(report, writes, patch_text, root, args)
        if html_path and not args.no_open and not args.json:
            import webbrowser
            webbrowser.open("file://" + os.path.abspath(html_path))

    # write-back
    wrote = []
    if writes and (args.in_place or args.out):
        allow = report["overall_status"] == "applied" or args.apply_anyway
        if report["overall_status"] == "needs-review" and not args.apply_anyway:
            allow = False
        if allow:
            for rp, data in writes.items():
                if args.out:
                    dst = os.path.join(os.path.abspath(args.out), rp)
                else:
                    dst = os.path.join(root, rp)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with open(dst, "wb") as fh:
                    fh.write(data)
                wrote.append(dst)

    report["written"] = wrote

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(_human_summary(report), file=sys.stderr)
        print(json.dumps(report, indent=2))
        if wrote:
            print("\nwrote:", file=sys.stderr)
            for w in wrote:
                print(f"   {w}", file=sys.stderr)
        elif (args.in_place or args.out) and report["overall_status"] not in (
                "applied",):
            print(f"\n(no files written — status is "
                  f"'{report['overall_status']}')", file=sys.stderr)

    if html_path:
        print(f"\nreview page: {html_path}", file=sys.stderr)

    exit_map = {"applied": 0, "no-op": 0, "needs-review": 2, "rejected": 3}
    return exit_map.get(report["overall_status"], 1)


def render_review(report, writes, patch_text, root, findings=None):
    """Build the per-file payload (current / merged / incoming) for the 3-way
    conflict view and return the rendered HTML page. Reusable by the CLI and by
    batch mode. If findings is None, auto-detected blockers are used."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import review

    # raw vendor patch text per file, shown as the "Patch" panel
    patch_by_file = {}
    _pre, sections = parse_patch(patch_text)
    for s in sections:
        vp = _safe_vp(s)
        if not vp:
            continue
        lines = []
        for h in s.hunks:
            lines.append(h.header)
            lines.extend(h.lines)
        if lines:
            patch_by_file[vp] = "\n".join(lines[:200])

    payload = {}
    for e in report["files"]:
        vp = e["vendor_path"]
        rp = e["resolved_path"]
        current = None
        if rp and os.path.isfile(os.path.join(root, rp)):
            current = to_lf(_read(os.path.join(root, rp))).decode("utf-8", "replace")
        merged = None
        if rp and rp in writes:
            merged = to_lf(writes[rp]).decode("utf-8", "replace")
        payload[vp] = {"current": current, "merged": merged,
                       "patch": patch_by_file.get(vp)}

    if findings is None:
        findings = _auto_findings(report, patch_text, root) or None
    return review.render(report, payload=payload, findings=findings)


def _write_review(report, writes, patch_text, root, args):
    """CLI wrapper: render the review page, write it to disk, return its path.

    A report is written for EVERY outcome (applied / no-op / needs-review /
    rejected). When --html is not given, it lands in a predictable
    ``patch-reports/`` folder next to the tree, named after the patch, instead
    of a throwaway temp file — so it is always easy to find and reopen."""
    findings = None
    if args.findings:
        with open(args.findings, encoding="utf-8") as fh:
            findings = json.load(fh)
    page = render_review(report, writes, patch_text, root, findings=findings)

    path = args.html
    if not path:  # default run: stable, discoverable location
        base = os.path.dirname(root) if args.root else root
        rdir = os.path.join(base or ".", "patch-reports")
        os.makedirs(rdir, exist_ok=True)
        stem = os.path.splitext(os.path.basename(args.patch))[0]
        path = os.path.join(rdir, stem + ".html")
    else:
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(page)
    return path


def _tree_text(root, _cache={}):
    if root in _cache:
        return _cache[root]
    buf = []
    for dp, _dn, fns in os.walk(root):
        if ".git" in dp.split(os.sep):
            continue
        for fn in fns:
            try:
                buf.append(_read(os.path.join(dp, fn)).decode("utf-8", "replace"))
            except OSError:
                pass
    text = "\n".join(buf)
    _cache[root] = text
    return text


def _auto_findings(report, patch_text, root):
    """Cheap, false-positive-averse static checks for a suspect/rejected merge:
    flag project-local helpers the added code calls that don't exist anywhere in
    the target tree (a link error the patch carries in with it)."""
    if report.get("overall_status") not in ("needs-review", "rejected"):
        return []

    # derive the project's symbol prefix from a resolved basename, e.g. "npu_"
    prefix = None
    for e in report["files"]:
        base = os.path.basename(e.get("resolved_path") or e.get("vendor_path") or "")
        if "_" in base:
            prefix = base.split("_", 1)[0] + "_"
            break
    if not prefix:
        return []

    _pre, sections = parse_patch(patch_text)
    called = set()
    for s in sections:
        for h in s.hunks:
            for ln in h.lines:
                if ln.startswith("+"):
                    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", ln[1:]):
                        called.add(m.group(1))

    tree = _tree_text(root)
    findings = []
    for fn in sorted(called):
        if not fn.startswith(prefix):
            continue  # only project-local symbols — kernel/libc APIs aren't here
        if not re.search(r"\b" + re.escape(fn) + r"\s*\(", tree):
            findings.append({
                "severity": "dep",
                "title": f"Calls {fn}(), which isn't in this tree",
                "body": (f"The added code calls {fn}(), but nothing under the "
                         f"target tree defines or declares it. As it stands the "
                         f"change won't link — this helper has to be sourced from "
                         f"the rest of the vendor series before it can build."),
                "evidence": f"grep -rn '{fn}' <tree>  ->  only the patch itself",
            })
    return findings


if __name__ == "__main__":
    sys.exit(main())
