# patch-merger

Apply a vendor patch / unified diff to a file or source tree — safely, with
tier tracking and honest post-apply verification.

Built for re-landing vendor **CVE fixes** (Qualcomm / MediaTek / LSI dialects)
onto a tree that has drifted, where a naive `patch` will happily land a hunk in
the wrong place and report success. Works on any unified diff.

It ships as a [Claude Code](https://claude.com/claude-code) skill, but the tool
and web UI run standalone.

## What's here

| Piece | Path | What it is |
|---|---|---|
| **Skill** | `SKILL.md` | Tells Claude when to run the tool and how to act on each status — especially reading a `needs-review` region and explaining the mismatch. |
| **Tool** | `scripts/merge.py` | The deterministic CLI. Stdlib only. |
| **Web UI** | `scripts/server.py` + `scripts/index.html` | Paste a file + patch, or run any corpus fixture, and see the tier, diff, and audit report. |
| **Tests** | `scripts/run_fixtures.py` | Asserts all 10 corpus outcomes. |
| **Corpus** | `fixtures/` | Ten source files, ten vendor patches, one scenario each. |

## Requirements

`python3`, `git`, and GNU `patch` on `PATH`. No pip installs.

## Use it

```bash
# one file + one patch (the common ask)
python3 scripts/merge.py PATCH --file TARGET

# a whole tree (multi-file patches)
python3 scripts/merge.py PATCH --root TREE

# write the result back (only writes when status is "applied")
python3 scripts/merge.py PATCH --root TREE --in-place
python3 scripts/merge.py PATCH --root TREE --out DIR      # write to a copy

# machine-readable
python3 scripts/merge.py PATCH --file TARGET --json
```

Exit codes: `0` applied / no-op · `2` needs-review · `3` rejected.

### Web UI

```bash
python3 scripts/server.py                 # http://127.0.0.1:8765
```

Two modes: paste a single file + patch, or pick any of the ten corpus fixtures
and run it against the bundled source tree.

### Tests

```bash
python3 scripts/run_fixtures.py           # all 10 fixtures -> ALL PASS
```

## What it does

1. **Parse + detect** the vendor dialect and strip level (`-p0` / `-p1`), and
   pull out CVE ID, CR number, severity, component.
2. **Safety scan** *before touching any file* — rejects path traversal,
   absolute paths, binary payloads, hunks whose line counts don't match their
   header, and patches with no CVE **and** no CR (untraceable).
3. **Resolve** the vendor path in the tree: exact → basename search →
   content/anchor search (handles a file that was relocated *and* renamed).
4. **Detect no-ops** — an already-backported patch reverse-applies cleanly and
   is reported as `no-op`, never double-applied.
5. **Apply at escalating tiers** — `git apply` (T1, strict) → `patch -F0` (T2,
   offset-tolerant) → `patch -F2 -l` (T3, fuzzy + whitespace-insensitive).
6. **Preserve line endings** (LF / CRLF) on write-back; re-indent added lines to
   the file's house style when a whitespace-dialect patch lands at T3.
7. **Verify** — a hunk that only lands with **fuzz > 0** means context was
   discarded, so the region was refactored and the result is not trustworthy:
   status becomes `needs-review`, `verified: false`.

## The case that matters (fixture 0007)

`npu_power_on()` was refactored from a single-regulator sequence into a
rail-table loop. A vendor patch adds a firmware-signature check into the *old*
sequence. `patch -F2 -l` lands it with fuzz 1 and reports success; `git
merge-file` three-way merges it with no conflict. Both produce the same code,
and it's wrong — the error path calls `regulator_disable(dev->vdd)`, a mechanism
that no longer exists, leaking every rail the loop acquired.

Nothing mechanical flags it. `patch-merger` returns it as `needs-review` because
it only landed fuzzily, and the skill then has Claude read the region and
explain the leak. A merger that ships 0007 silently is not safe to run
unattended.

## Install as a Claude Code skill

```bash
git clone https://github.com/codejawk/patch ~/.claude/skills/patch-merger
```

Then ask Claude to "apply this patch to that file" and the skill triggers.

## Scope

Deterministic tiers stop at fuzzy apply. A real three-way rebase and an
LLM-assisted rebase are escalations, not part of the deterministic path.
"Verified" means the re-diff matched — it does **not** mean the result compiles.

## Corpus provenance

Every expected outcome in `fixtures/` was produced by actually running `git
apply` / `patch` / `git merge-file` against the tree — see `fixtures/verify.sh`.
The CVE IDs, CR numbers and source files are synthetic test data.
