# Patch-merger test fixtures

Test corpus for a patch-merging skill (Claude / Cline). Ten source files, ten
vendor patches, one scenario per patch.

Every outcome below was produced by actually running `git apply`, `patch` and
`git merge-file` against the tree — see `verify.sh`. Nothing here is asserted
from reading the diffs.

```
src/                    the Samsung-side tree the patches land on
vendor_base/<id>/       the pre-image each vendor patched against (for 3-way)
patches/                the ten vendor patches
verify.sh               reproduces the matrix below
```

## Running it

```bash
./verify.sh
```

Requires `git`, GNU `patch`, `diff`.

## Tolerance levels

| Tier | Command | Tolerates |
|---|---|---|
| T1 strict | `git apply` | exact context |
| T2 offset | `patch -F0` | offset drift only |
| T3 fuzzy | `patch -F2 -l` | missing context lines, whitespace changes |
| T4 three-way | `git merge-file` vs `vendor_base/` | structural divergence |

## Verified behaviour matrix

| # | Scenario | T1 | T2 | T3 | T4 | Correct handling |
|---|---|---|---|---|---|---|
| 0001 | clean exact apply | ✅ | ✅ | ✅ | ✅ | apply at T1 |
| 0002 | offset drift (+18 lines of local code above) | ✅ | ✅ | ✅ | ✅ | apply; **never trust `@@` line numbers** |
| 0003 | whitespace: our tree is tabs, vendor is spaces | ❌ | ❌ | ✅ | ❌ | apply at T3 with `-l`, re-indent to house style |
| 0004 | already backported (idempotency) | ❌ | ❌ | ❌ | ✅ | detect as **no-op**, do not double-apply or reverse |
| 0005 | 2 hunks in one file + 1 in another | ✅ | ✅ | ✅ | ✅ | all-or-nothing across both files |
| 0006 | vendor path doesn't exist (file relocated) | ❌ | ❌ | ❌ | ❌ | resolve `npu/mem/npu_mem.c` → `npu/core/npu_mem_map.c`, then apply |
| 0007 | **region refactored — every tier "succeeds" and is WRONG** | ❌ | ❌ | ⚠️ | ⚠️ | must be caught by semantic verification |
| 0008 | new file + header decl + deletion-only hunk, CRLF target | ✅ | ✅ | ✅ | ✅ | preserve CRLF on write-back |
| 0009 | vendor patched a rewrite we never took | ❌ | ❌ | ❌ | ❌ | confident **reject** → escalate |
| 0010 | malformed / hostile | ❌ | ❌ | ❌ | — | reject in the safety scan, before touching any file |

⚠️ = the tool reports success and the result is incorrect.

## The one that matters: 0007

`npu_power_on()` was refactored on the Samsung side from a single-regulator
sequence into a rail-table loop. The vendor patch adds a firmware-signature
check into the old sequence.

- `patch -F2 -l` applies it with *fuzz 1, offset 11* and reports success.
- `git merge-file` three-way merges it with **no conflict** and reports success.
- Both produce the same code, and it is wrong: the error path calls
  `regulator_disable(dev->vdd)`, which is no longer the mechanism in use, and
  leaks every rail acquired by the loop above it.

The security check itself lands in a plausible place. Nothing mechanical flags
it. This is the failure mode that makes automated CVE merging dangerous, and it
is the case your skill's post-apply verification exists to catch. If a merger
passes 0001–0006 and 0008–0010 but ships 0007 silently, it is not safe to run
unattended.

## Vendor dialects (deliberately inconsistent)

Real vendor patches don't agree on format. The corpus reflects that:

| Vendor | Header style | Path prefix | Strip |
|---|---|---|---|
| Qualcomm | `git format-patch` — `From <sha>`, `Subject:`, `diff --git` | `a/` `b/` | `-p1` |
| MediaTek | free-text block, bare unified diff | none | `-p0` |
| LSI | `Index:` + `===` separator, SVN-ish, `(revision N)` / `(working copy)` suffixes on the `---`/`+++` labels | none | `-p0` |

Detecting strip level per patch is part of the job. The LSI label suffixes will
break a naive path parser — that is intentional.

## Metadata to extract

Each patch carries CVE ID, CR number, severity and component, in a
vendor-specific place:

- Qualcomm: `CR-Id:`, `CVE:`, `Severity:`, `Component:` in the commit trailer
- MediaTek: `CR Number :`, `CVE :`, `Severity :`, `Module :` in the text block
- LSI: `CR:`, bare `CVE-XXXX-XXXXX` line, `Severity:` after `Index:`

`0010` has none — a patch with no CR and no CVE is itself a rejection signal.

## Suggested skill contract

A merger run over this corpus should emit, per file:

```json
{
  "vendor_path": "npu/mem/npu_mem.c",
  "resolved_path": "npu/core/npu_mem_map.c",
  "resolution_lane": "filename-search",
  "tier": 1,
  "offset_delta": 0,
  "line_ending": "LF",
  "status": "applied",
  "verified": true
}
```

with `status` in `applied | no-op | rejected | needs-review` and `verified`
meaning the post-apply re-diff matched the intent. `0007` must come back
`needs-review` with `verified: false` regardless of which tier landed it.

## Extending the corpus

Gaps worth adding next, in rough order of value:

1. A patch that applies cleanly but breaks the build (catches "verified by
   diff" vs "verified by compile").
2. A hunk that appears twice in the file — ambiguous anchor, must not pick one
   arbitrarily.
3. A patch depending on an earlier CVE fix not yet integrated (ordering).
4. A rename *inside* the patch (`rename from` / `rename to` git headers).
5. Non-UTF-8 bytes in a context line.
