---
name: patch-merger
description: >-
  Apply a vendor patch / unified diff to a file or source tree, safely. Use
  whenever the user gives you a patch (or .diff / .patch file) plus a target
  file or tree and wants the changes applied or "merged" — especially vendor
  CVE patches in Qualcomm / MediaTek / LSI dialects that must be re-landed on
  code that has drifted. Handles strip-level and dialect detection, a safety
  scan (rejects path traversal, absolute paths, binary blobs, malformed or
  untraceable patches), relocated-file resolution, no-op / already-applied
  detection, escalating apply tiers (exact -> offset -> fuzzy), line-ending
  preservation, and post-apply verification that flags a hunk which only lands
  fuzzily as needs-review. Triggers: "apply this patch", "merge this diff",
  "land this CVE fix", "patch this file", "does this patch still apply?".
---

# Patch Merger

Apply a unified-diff patch to a target file or source tree, and — this is the
point — say honestly whether the result is trustworthy. Mechanical patch tools
report "success" on refactored code where the hunk landed somewhere plausible
and wrong. This skill runs a deterministic applier and then makes *you* verify
the cases the applier flags.

## When to use

The user hands you a patch and a file (or tree) and wants it applied / merged.
Vendor CVE patches are the core case, but any unified diff works.

## The tool

`scripts/merge.py` does the deterministic work. Stdlib only; needs `git` and
GNU `patch` on PATH.

```bash
# single file + patch (the common ask)
python3 scripts/merge.py <patch> --file <target>

# a whole source tree (multi-file patches)
python3 scripts/merge.py <patch> --root <tree>

# actually write the result back (only writes when status is "applied")
python3 scripts/merge.py <patch> --root <tree> --in-place
python3 scripts/merge.py <patch> --root <tree> --out <dir>   # write to a copy

# JSON report only (what you parse)
python3 scripts/merge.py <patch> --file <target> --json
```

It prints a per-file JSON report. Exit codes: `0` applied/no-op, `2`
needs-review, `3` rejected.

### What each field means

```json
{
  "overall_status": "applied | no-op | needs-review | rejected",
  "dialect": "qualcomm | mediatek | lsi | unknown",
  "strip": 0,
  "metadata": {"cve": "...", "cr": "...", "severity": "...", "component": "..."},
  "safety": {"passed": true, "findings": []},
  "files": [{
    "vendor_path": "npu/mem/npu_mem.c",
    "resolved_path": "npu/core/npu_mem_map.c",
    "resolution_lane": "exact | filename-search | content-search | new-file | forced",
    "tier": 1,                 // 1 git apply, 2 patch -F0, 3 patch -F2 -l
    "fuzz": 0,                 // >0 means context lines were discarded to land it
    "offset_delta": 0,
    "line_ending": "LF | CRLF",
    "status": "applied | no-op | needs-review | rejected",
    "verified": true,
    "reason": "..."
  }]
}
```

## Workflow

1. **Run the tool** on the patch and target. If the user gave one file, use
   `--file`; if a tree, use `--root`.

2. **Read `overall_status` and act on it:**

   - **`applied`** — landed at tier 1/2, or tier 3 with fuzz 0. Trustworthy.
     Report the tier, CVE/CR, and where it landed. If they asked you to write
     it, re-run with `--in-place` (or `--out`).

   - **`no-op`** — the change is already in the tree. Do **not** re-apply or
     reverse it. Tell the user it's already integrated (idempotency).

   - **`rejected`** — either the safety scan tripped, or no tier could land the
     hunk (the context genuinely doesn't exist here). This is a *confident*
     reject. Quote the `safety.findings` or the per-file reason and escalate;
     do not try to force it. A malformed/hostile patch is rejected before any
     file is opened — never bypass that.

   - **`needs-review`** — **this is the case that matters.** The hunk only
     landed under fuzzy matching (`fuzz > 0`): `patch` says success, but
     context lines had to be thrown away, which means the surrounding code was
     refactored and the hunk may now sit in a place that no longer means what
     the vendor intended. Do **not** present this as done. Instead:

     a. Open the resolved file and read the region around where the hunk landed.
     b. Read the hunk's added lines and ask: does the code they touch still
        do what the patch assumed? Look for error paths, cleanup, locks, or
        mechanisms the added lines depend on that the refactor changed.
     c. Report specifically *why* it needs review — name the mismatch — and
        present it as a review request, never an approval. The tool caught that
        it's suspect; your job is to explain what's actually wrong.

     > Worked example (corpus 0007): a firmware-signature check is added to
     > `npu_power_on()`. The tree refactored that function from a single
     > regulator into a rail-table loop. The patch lands fuzzily, and its error
     > path calls `regulator_disable(dev->vdd)` — a mechanism that no longer
     > exists — leaking every rail the loop acquired. Nothing mechanical flags
     > it. That is exactly what `needs-review` is protecting against.

3. **All-or-nothing.** For a multi-file patch, if any file rejects, nothing is
   written. Report the whole patch's status, not a partial apply.

4. **Never** hand-edit the file to "make the patch fit" and call it applied.
   If it doesn't land cleanly, it's `needs-review` or `rejected` — say so.

## Web UI

For an interactive view (paste a file + patch, or run any bundled corpus
fixture and watch the tiers, the diff, and the safety rejects):

```bash
python3 scripts/server.py            # http://127.0.0.1:8765
python3 scripts/server.py --fixtures /path/to/patch-merger-fixtures
```

## Scope / limits

- Tiers stop at fuzzy apply (T3). A genuine three-way rebase (T4 /
  `git merge-file`) and an LLM-assisted rebase are out of scope for the
  deterministic tool — those are escalations, and the assisted-rebase output
  must itself be re-verified before it ships (see `CVE_NPU_Automation_Plan.md`
  Tier 3).
- "Verified" here means the re-diff matched under exact/whitespace matching. It
  does **not** mean the result compiles or is semantically correct — a clean
  apply can still break the build. Say that when it matters.
