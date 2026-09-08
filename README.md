# patch-merger

Apply a vendor patch / unified diff to a file or source tree — safely, with tier
tracking, honest post-apply verification, and a Perforce-style visual review of
exactly what changed.

Built for re-landing vendor **CVE fixes** (Qualcomm / MediaTek / LSI dialects)
onto a tree that has drifted, where a naive `patch` will happily land a hunk in
the wrong place and report success. Works on any unified diff.

Ships as a [Claude Code](https://claude.com/claude-code) skill; the tools and
web UI also run standalone.

## What's here

| Piece | Path | What it is |
|---|---|---|
| **Skill** | `SKILL.md` | Tells Claude when to run the tools and how to act on each status — and to read a `needs-review` region and explain the real defect. |
| **Merge tool** | `scripts/merge.py` | The deterministic CLI for one patch. Stdlib only. |
| **Batch tool** | `scripts/batch.py` | Merge a whole folder of patches, apply the clean ones, report the rest. |
| **Report renderer** | `scripts/review.py` | The P4-style before/after review page + the batch summary. |
| **Web UI** | `scripts/server.py` + `scripts/index.html` | Paste a file + patch, or run any corpus fixture, in the browser. |
| **Tests** | `scripts/run_fixtures.py` | Asserts all 10 corpus outcomes. |
| **Corpus** | `fixtures/` | Ten source files, ten vendor patches, one scenario each. |

## Requirements

`python3`, `git`, and GNU `patch` on `PATH`. No pip installs.

## Use it

### One patch
```bash
# single file + patch — opens the review page in your browser automatically
python3 scripts/merge.py PATCH --file TARGET

# a whole tree (multi-file patches)
python3 scripts/merge.py PATCH --root TREE

# write the result back (only writes when status is "applied")
python3 scripts/merge.py PATCH --root TREE --in-place
python3 scripts/merge.py PATCH --root TREE --out DIR     # write to a copy

# no page / no browser (scripting)
python3 scripts/merge.py PATCH --file TARGET --json
python3 scripts/merge.py PATCH --root TREE --no-open
```

Exit codes: `0` applied / no-op · `2` needs-review · `3` rejected.

### A whole folder of patches (batch)
```bash
python3 scripts/batch.py --patches PATCHES_DIR --tree TREE --open
python3 scripts/batch.py --patches PATCHES_DIR --tree TREE --in-place
```

Applies every clean patch to a working copy (`<tree>__merged` by default, so the
original stays intact), leaves conflicts and rejects unwritten, and writes one
report per patch plus a summary index of what merged and what needs a human.

## The review page

Every run opens a self-contained page. Per file it shows:

- a **Before | After side-by-side** (Perforce style) with line numbers, changed
  lines highlighted (removed red on the left, added green on the right, aligned),
  and long unchanged regions collapsed;
- **Copy merged** / **Download merged**;
- the **patch** itself (raw unified diff), so you can see the vendor's change at a
  glance;
- any **auto-detected blockers** (e.g. a project-local helper the patch calls
  that doesn't exist in the tree — a link error the patch carries in).

A `needs-review` landing is shown the same way, but the After column is labelled a
**candidate** and the blockers sit above it. A `rejected` patch shows the reason
and the patch, with no candidate.

## What the merge does

1. **Parse + detect** the vendor dialect and strip level (`-p0` / `-p1`), and pull
   out CVE ID, CR number, severity, component.
2. **Safety scan** *before touching any file* — rejects path traversal, absolute
   paths, binary payloads, hunks whose line counts don't match their header, and
   patches with no CVE **and** no CR (untraceable).
3. **Resolve** the vendor path in the tree: exact → basename search →
   content/anchor search (handles a file that was relocated *and* renamed).
4. **Detect no-ops** — an already-backported patch reverse-applies cleanly and is
   reported as `no-op`, never double-applied.
5. **Apply at escalating tiers** — `git apply` (T1, strict) → `patch -F0` (T2,
   offset-tolerant) → `patch -F2 -l` (T3, fuzzy + whitespace-insensitive).
6. **Preserve line endings** (LF / CRLF) on write-back; re-indent added lines to
   the file's house style when a whitespace-dialect patch lands at T3.
7. **Verify** — a hunk that only lands with **fuzz > 0** means context was
   discarded, so the region was refactored and the result is not trustworthy:
   status becomes `needs-review`, `verified: false`.

## Tests

```bash
python3 scripts/run_fixtures.py           # all 10 fixtures -> ALL PASS
```

Every expected outcome in `fixtures/` was produced by actually running `git
apply` / `patch` / `git merge-file` — see `fixtures/verify.sh`. The CVE IDs, CR
numbers and source files are synthetic test data.

## The case that matters (fixture 0007)

`npu_power_on()` was refactored from a single-regulator sequence into a rail-table
loop. A vendor patch adds a firmware-signature check into the *old* sequence.
`patch -F2 -l` lands it with fuzz 1 and reports success; `git merge-file`
three-way merges it with no conflict. Both produce the same code, and it's wrong —
the error path calls `regulator_disable(dev->vdd)`, a mechanism that no longer
exists, leaking every rail the loop acquired.

Nothing mechanical flags it. `patch-merger` returns it as `needs-review` because
it only landed fuzzily; the page flags the missing helper automatically, and the
skill has Claude read the region and explain the leak. A merger that ships 0007
silently is not safe to run unattended.

## Install as a Claude Code skill

```bash
git clone https://github.com/codejawk/patch ~/.claude/skills/patch-merger
```

Then ask Claude to "apply this patch to that file", or "merge every patch in this
folder and report each", and the skill triggers.

## Scope

Deterministic tiers stop at fuzzy apply. A real three-way rebase and an
LLM-assisted rebase are escalations, not part of the deterministic path.
"Verified" means the re-diff matched — it does **not** mean the result compiles.
