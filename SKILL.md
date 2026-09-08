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

**Step 1 is always to run the tool.** Do not analyse a patch by reading it
yourself and writing a prose verdict — run `merge.py`. It generates and opens a
visual review page on every run (that page is the deliverable the user expects),
and its status/tier/fuzz are the ground truth your analysis must rest on.

```bash
# single file + patch (the common ask) — opens the review page automatically
python3 scripts/merge.py <patch> --file <target>

# a whole source tree (multi-file patches)
python3 scripts/merge.py <patch> --root <tree>

# actually write the result back (only writes when status is "applied")
python3 scripts/merge.py <patch> --root <tree> --in-place
python3 scripts/merge.py <patch> --root <tree> --out <dir>   # write to a copy

# save the review page to a known path (still opens it)
python3 scripts/merge.py <patch> --root <tree> --html review.html

# machine-readable, no page, no browser
python3 scripts/merge.py <patch> --file <target> --json
```

It prints a per-file JSON report and, unless `--json` is used alone, **writes a
visual review page and opens it in the browser** (add `--no-open` to generate it
without opening). Exit codes: `0` applied/no-op, `2` needs-review, `3` rejected.

### Many patches at once — batch mode

When the user points at a **folder of patches** (or asks "which of these merge?",
"merge what you can and report each", "run the whole set"), use `batch.py`. It
applies every clean patch to the tree, leaves conflicts and rejects unwritten,
writes one report per patch, and a summary index of what merged and what needs a
human. By default it works on a **copy** (`<tree>__merged`) so the original stays
intact; `--in-place` applies to the real tree.

```bash
python3 scripts/batch.py --patches <patches_dir> --tree <tree> --open
python3 scripts/batch.py --patches <patches_dir> --tree <tree> \
        --apply-to <merged_dir> --reports <reports_dir>
python3 scripts/batch.py --patches <patches_dir> --tree <tree> --in-place
```

It prints a per-patch line (merged / already-present / conflict / rejected), then
the paths to the merged tree, the reports folder, and the summary `index.html`
(each row links to that patch's own conflict-resolution report). Open the summary
in the Browser pane and tell the user which patches merged and which need their
decision. Do **not** auto-resolve a `needs-review` patch — that is the one place
to stop and ask.

### The review page is the point

Every normal run opens a self-contained **3-way conflict page** — a verdict
header, auto-detected blockers, then per changed region three columns:
**Current (your tree) · Incoming (the patch) · Keep?**, where the third column
is a live radio (keep current / take incoming). A clean apply defaults to "take
incoming"; a `needs-review` landing starts every block *undecided* and flagged,
and the merged result stays blocked until the reviewer resolves each one. The
result rebuilds live, with Copy and Download. So the user *resolves* the merge,
not just reads a status line. In this Claude Code session, also open the
generated page in the Browser pane (its path is printed as `review page: …`), so
it surfaces even when the system browser doesn't.

For a `needs-review` (or `rejected`) result, enrich the page: once you've read
the landing region (workflow step 2) and worked out the concrete defects, write
them to a small JSON file and regenerate the page so those defects render as
cards on it:

```bash
# findings.json: [{ "severity": "compile|leak|dep|warn|danger|info",
#                   "title": "...", "body": "...", "evidence": "..." }, ...]
python3 scripts/merge.py <patch> --root <tree> --html review.html \
        --findings findings.json
```

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
     d. Write those defects to a `findings.json` and regenerate the review page
        with `--findings` (see *Always show the result visually*) so the user
        sees the reasons as cards on the page, not just in chat.

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
