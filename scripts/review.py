#!/usr/bin/env python3
"""
review.py — render a merge result as a P4-style side-by-side review page.

merge.py / batch.py call this on every run. Per file it shows:

  * a Before | After side-by-side diff, changed lines highlighted (removed red
    on the left, added green on the right, aligned, with line numbers), and
  * the patch itself (the raw unified diff), so you can see what the vendor
    changed at a glance.

Clean applies get Copy / Download of the merged result. A needs-review landing
is shown the same way but flagged: the "After" column is a candidate, not
trusted, and the blockers are listed above it. Rejected patches show the patch
and the reason, with no candidate.

Pure stdlib; the page needs no libraries and only a little JS for Copy/Download.
"""

from __future__ import annotations

import difflib
import html
import json

STATUS = {
    "applied":      ("APPLIED",        "good",
                     "Landed cleanly. Here is exactly what changed."),
    "no-op":        ("ALREADY IN TREE", "accent",
                     "This change is already present — nothing to merge."),
    "needs-review": ("NEEDS REVIEW",   "warn",
                     "It only landed under fuzzy matching. The After side is a "
                     "candidate — review it against the blockers before trusting it."),
    "rejected":     ("REJECTED",       "danger",
                     "It could not land here, or failed the safety scan. No "
                     "candidate to show — resolve by hand or escalate."),
}
SUMMARY_LABEL = {"applied": "merged", "no-op": "already in tree",
                 "needs-review": "needs you", "rejected": "rejected"}
SUMMARY_ORDER = {"applied": 0, "no-op": 1, "needs-review": 2, "rejected": 3}


def _esc(s):
    return html.escape(s if s is not None else "")


# --------------------------------------------------------------------------- #
# side-by-side (P4-style) diff
# --------------------------------------------------------------------------- #


_GAP = [0]  # unique id source for collapsible regions


def _sxs(before_text, after_text):
    before = (before_text or "").split("\n")
    after = (after_text or "").split("\n")
    sm = difflib.SequenceMatcher(None, before, after, autojunk=False)

    def cell(num, text, cls, attr=""):
        return (f'<div class="lno {cls}"{attr}>{num if num is not None else ""}</div>'
                f'<div class="code {cls}"{attr}>{_esc(text)}</div>')

    rows = ['<div class="sxs-h left">Before — your tree</div>'
            '<div class="sxs-h right">After — merged</div>']
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            n = i2 - i1
            if n <= 6:
                for k in range(n):
                    rows.append(cell(i1 + k + 1, before[i1 + k], "")
                                + cell(j1 + k + 1, after[j1 + k], ""))
                continue
            # collapse the middle: 3 shown, a clickable divider, hidden lines, 3 shown
            _GAP[0] += 1
            gid = _GAP[0]
            label = f"&#9662; {n - 6} unchanged lines — click to expand"
            for k in range(3):
                rows.append(cell(i1 + k + 1, before[i1 + k], "")
                            + cell(j1 + k + 1, after[j1 + k], ""))
            rows.append(f'<div class="gap" data-g="{gid}" '
                        f'data-label="{label}">{label}</div>')
            for k in range(3, n - 3):
                rows.append(cell(i1 + k + 1, before[i1 + k], "xr", f' data-g="{gid}"')
                            + cell(j1 + k + 1, after[j1 + k], "xr", f' data-g="{gid}"'))
            for k in range(n - 3, n):
                rows.append(cell(i1 + k + 1, before[i1 + k], "")
                            + cell(j1 + k + 1, after[j1 + k], ""))
        elif tag == "replace":
            L, R = before[i1:i2], after[j1:j2]
            for k in range(max(len(L), len(R))):
                left = cell(i1 + k + 1, L[k], "del") if k < len(L) else cell(None, "", "pad")
                right = cell(j1 + k + 1, R[k], "add") if k < len(R) else cell(None, "", "pad")
                rows.append(left + right)
        elif tag == "delete":
            for k in range(i2 - i1):
                rows.append(cell(i1 + k + 1, before[i1 + k], "del") + cell(None, "", "pad"))
        elif tag == "insert":
            for k in range(j2 - j1):
                rows.append(cell(None, "", "pad") + cell(j1 + k + 1, after[j1 + k], "add"))
    return '<div class="sxswrap"><div class="sxs">' + "".join(rows) + "</div></div>"


def _patch_html(patch_text):
    if not patch_text:
        return ""
    out = ['<pre class="patch"><code>']
    for line in patch_text.split("\n"):
        cls = ("d-hunk" if line.startswith("@@")
               else "d-head" if line[:3] in ("---", "+++", "dif")
               else "d-add" if line.startswith("+")
               else "d-del" if line.startswith("-") else "")
        out.append(f'<span class="pln {cls}">{_esc(line) or " "}</span>')
    out.append("</code></pre>")
    return "".join(out)


# --------------------------------------------------------------------------- #
# page
# --------------------------------------------------------------------------- #


def render(report, payload=None, findings=None, assist=None):
    payload = payload or {}
    status = report.get("overall_status", "rejected")
    label, role, blurb = STATUS.get(status, STATUS["rejected"])
    md = report.get("metadata", {}) or {}
    safety = report.get("safety", {}) or {}

    fuzz = max([f.get("fuzz", 0) or 0 for f in report.get("files", [])] or [0])
    offset = max([f.get("offset_delta", 0) or 0 for f in report.get("files", [])] or [0])
    tiers = [f.get("tier") for f in report.get("files", []) if f.get("tier")]
    tier = max(tiers) if tiers else None

    chips = [("cve", md.get("cve")), ("cr", md.get("cr")),
             ("severity", md.get("severity")),
             ("dialect", f'{report.get("dialect","?")} · strip {report.get("strip","?")}')]
    if tier:
        landed = f"tier {tier}" + (f" · fuzz {fuzz}" if fuzz else "") + \
                 (f" · offset +{offset}" if offset else "")
        chips.append(("landed", landed))
    chip_html = "".join(f'<span class="chip"><b>{_esc(k)}</b> {_esc(str(v))}</span>'
                        for k, v in chips if v)

    safety_html = ""
    if safety.get("passed") is False and safety.get("findings"):
        items = "".join(f"<li>{_esc(x)}</li>" for x in safety["findings"])
        safety_html = ('<div class="banner danger"><b>Refused by the safety scan '
                       '— no file was opened.</b><ul>' + items + "</ul></div>")

    # If Claude produced a verified rebase, that IS the answer — so the blockers
    # (which only explain why the *original* patch couldn't be trusted) collapse
    # to a one-line summary the reader can expand if they want the audit trail.
    verified_fix = bool(assist and assist.get("diff") and assist.get("verified"))
    findings_html = ""
    if findings:
        cards = "".join(
            f'<div class="defect"><div class="num">{i}</div><div>'
            f'<span class="sevtag s-{_esc(f.get("severity","note"))}">{_esc(f.get("severity","note"))}</span>'
            f'<h3>{_esc(f.get("title",""))}</h3><p>{_esc(f.get("body",""))}</p>'
            + (f'<div class="ev">{_esc(f.get("evidence"))}</div>' if f.get("evidence") else "")
            + "</div></div>" for i, f in enumerate(findings, 1))
        if verified_fix:
            findings_html = (
                f'<details class="whyblock"><summary>Why the original patch '
                f"couldn't land — {len(findings)} findings (the rebase above already "
                f'clears them)</summary>{cards}</details>')
        else:
            findings_html = ('<section><span class="eyebrow">Blockers found</span>'
                             '<h2>Problems to clear before this ships</h2>' + cards + "</section>")

    merged_map = {}
    files_html = []
    for idx, e in enumerate(report.get("files", [])):
        vp = e.get("vendor_path")
        rp = e.get("resolved_path")
        p = payload.get(vp, {})
        current, merged, patch = p.get("current"), p.get("merged"), p.get("patch")
        st = e.get("status")

        head = (f'<span class="mono">{_esc(vp)}</span> <span class="arrow">&rarr;</span> '
                f'<span class="mono strong">{_esc(rp)}</span>'
                if rp and rp != vp else
                f'<span class="mono strong">{_esc(rp or vp)}</span>')

        parts = [f'<div class="file-head"><span class="path">{head}</span>'
                 f'<span class="pill {st}">{_esc(st)}</span></div>']

        if merged is not None:
            if st == "needs-review":
                parts.append('<div class="cand-note">⚠ The After side is the '
                             'fuzzy <b>candidate</b> — review it against the '
                             'blockers above before using it.</div>')
            parts.append(_sxs(current or "", merged))
            merged_map[str(idx)] = merged
            note = " (candidate)" if st == "needs-review" else ""
            parts.append(
                f'<div class="bar"><span class="hint">Before&nbsp;→&nbsp;After of '
                f'this merge</span><span class="btns">'
                f'<button class="act" data-copy="{idx}">Copy merged{note}</button>'
                f'<button class="act primary" data-dl="{idx}" '
                f'data-name="{_esc((rp or vp or "merged.txt").split("/")[-1])}">Download merged{note}</button>'
                f'</span></div>')
        elif st == "no-op":
            parts.append('<div class="cand-note">Already present — the file is '
                         'unchanged by this patch.</div>')
        else:
            parts.append('<div class="cand-note">No safe automatic merge — nothing '
                         'was written. The patch is shown below; resolve by hand.</div>')

        if patch:
            parts.append('<details class="patchbox" open><summary>Patch — what the '
                         'vendor changed</summary>' + _patch_html(patch) + "</details>")

        files_html.append('<div class="file">' + "".join(parts) + "</div>")

    assist_html = ""
    if assist and assist.get("diff"):
        ok = assist.get("verified")
        badge = ('<span class="a-badge ok">✓ verified — applies cleanly (T'
                 f'{assist.get("tier", 1)})</span>' if ok else
                 '<span class="a-badge bad">✗ not verified — this rebase did not '
                 'apply; treat as a draft only</span>')
        assist_html = (
            '<section><span class="eyebrow">AI-assisted rebase (Claude)</span>'
            '<h2>Proposed rebase against the current code</h2>'
            '<div class="assist"><div class="a-head">' + badge +
            '<span class="a-note">Generated by Claude for review — never '
            'auto-applied. Confirm it before shipping.</span></div>'
            + _patch_html(assist["diff"])
            + (f'<div class="a-why">{_esc(assist.get("note"))}</div>'
               if assist.get("note") else "")
            + '</div></section>')

    data = json.dumps(merged_map).replace("</", "<\\/")
    return _head(md.get("cve") or "Patch review") + f'''
  <div class="wrap">
    <div class="verdict {role}">
      <div class="stamp">{_esc(label)}</div>
      <div><h1>{_esc(blurb)}</h1>
        <div class="patchname">{_esc(report.get("patch_filename") or "patch")}</div>
        <div class="chips">{chip_html}</div></div>
    </div>
    {safety_html}
    {assist_html}
    <section><span class="eyebrow">The changes</span>
      <h2>Before &nbsp;·&nbsp; After &nbsp;·&nbsp; the patch</h2>
      {"".join(files_html)}
    </section>
    {findings_html}
    <div class="prov">generated by the patch-merger skill</div>
  </div>
  <div class="toast" id="toast"></div>
  <script type="application/json" id="merged-data">{data}</script>
  <script>{_SCRIPT}</script>
</body></html>'''


_SCRIPT = r'''
const M = JSON.parse(document.getElementById('merged-data').textContent);
function toast(m){const t=document.getElementById('toast');t.textContent=m;
  t.classList.add('show');setTimeout(()=>t.classList.remove('show'),1400);}
document.addEventListener('click',e=>{
  const g=e.target.closest('.gap[data-g]');
  if(g){ const id=g.dataset.g, open=g.classList.toggle('open');
    document.querySelectorAll('.xr[data-g="'+id+'"]').forEach(x=>x.style.display=open?'block':'');
    g.innerHTML = open ? '&#9652; hide unchanged lines' : g.dataset.label; return; }
  const c=e.target.closest('[data-copy]'), d=e.target.closest('[data-dl]');
  if(c){navigator.clipboard.writeText(M[c.dataset.copy]||'')
      .then(()=>toast('Merged file copied')).catch(()=>toast('Copy failed'));}
  if(d){const t=M[d.dataset.dl]||'';const b=new Blob([t+'\n'],{type:'text/plain'});
    const a=document.createElement('a');a.href=URL.createObjectURL(b);
    a.download=d.dataset.name||'merged.txt';document.body.appendChild(a);a.click();
    a.remove();toast('Downloaded '+a.download);}
});
'''


def _head(title):
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<title>{_esc(title)} review</title>'
            '<link rel="preconnect" href="https://fonts.googleapis.com">'
            '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
            '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?'
            'family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap">'
            f"<style>{_CSS}</style></head><body>")


_CSS = """
  :root{--bg:#eef1f5;--surface:#fff;--surface-2:#f6f8fb;--code-bg:#f4f6fa;
    --ink:#152030;--muted:#5a6675;--faint:#8b97a6;--line:#dbe1ea;
    --accent:#2f4bb0;--accent-bg:#e6ebf8;--accent-line:#c3cff0;
    --warn:#a6690b;--warn-bg:#fbf1de;--warn-line:#e9cf9a;
    --danger:#b8321f;--danger-bg:#fbe9e6;--danger-line:#f0c4bc;
    --good:#1a7f4b;--good-bg:#e4f4ea;--good-line:#b4dcc4;
    --del-bg:#fceeef;--del-ink:#a3291a;--del-gut:#f6d6d2;
    --add-bg:#e6f5ec;--add-ink:#146c3a;--add-gut:#c7e9d4;
    --hunk:#2f4bb0;
    --mono:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;
    --sans:"IBM Plex Sans",system-ui,-apple-system,"Segoe UI",sans-serif;}
  @media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
    --bg:#0d1117;--surface:#161c26;--surface-2:#1c232f;--code-bg:#12161d;
    --ink:#e7ecf3;--muted:#9aa7b7;--faint:#66727f;--line:#28313d;
    --accent:#8098ff;--accent-bg:#1e2740;--accent-line:#31406a;
    --warn:#e0ac52;--warn-bg:#2c2413;--warn-line:#4a3c1c;
    --danger:#f0917f;--danger-bg:#2e1815;--danger-line:#4d271f;
    --good:#68c795;--good-bg:#132a1e;--good-line:#204d36;
    --del-bg:#2b1613;--del-ink:#f0917f;--del-gut:#3f1f1a;
    --add-bg:#122a1d;--add-ink:#68c795;--add-gut:#1c3d2a;--hunk:#8098ff;}}
  :root[data-theme="dark"]{--bg:#0d1117;--surface:#161c26;--surface-2:#1c232f;--code-bg:#12161d;
    --ink:#e7ecf3;--muted:#9aa7b7;--faint:#66727f;--line:#28313d;--accent:#8098ff;
    --accent-bg:#1e2740;--accent-line:#31406a;--warn:#e0ac52;--warn-bg:#2c2413;--warn-line:#4a3c1c;
    --danger:#f0917f;--danger-bg:#2e1815;--danger-line:#4d271f;--good:#68c795;--good-bg:#132a1e;--good-line:#204d36;
    --del-bg:#2b1613;--del-ink:#f0917f;--del-gut:#3f1f1a;--add-bg:#122a1d;--add-ink:#68c795;--add-gut:#1c3d2a;--hunk:#8098ff;}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);line-height:1.5}
  .wrap{max-width:1200px;margin:0 auto;padding:28px 22px 80px}
  .mono{font-family:var(--mono)} .strong{font-weight:600}
  .eyebrow{font-family:var(--mono);font-size:11px;font-weight:500;letter-spacing:.16em;
    text-transform:uppercase;color:var(--faint);display:block;margin-bottom:9px}
  h1,h2,h3{margin:0;text-wrap:balance} h2{font-size:19px;font-weight:600;letter-spacing:-.01em}
  section{margin-top:32px} p{margin:8px 0 0}
  .verdict{display:grid;grid-template-columns:auto 1fr;gap:20px;align-items:center;
    background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:20px 22px}
  .verdict.good{border-left:6px solid var(--good)} .verdict.warn{border-left:6px solid var(--warn)}
  .verdict.danger{border-left:6px solid var(--danger)} .verdict.accent{border-left:6px solid var(--accent)}
  .stamp{font-family:var(--mono);font-weight:600;font-size:12px;letter-spacing:.09em;
    border-radius:999px;padding:8px 15px;white-space:nowrap;text-align:center}
  .good .stamp{color:var(--good);background:var(--good-bg);border:1px solid var(--good-line)}
  .warn .stamp{color:var(--warn);background:var(--warn-bg);border:1px solid var(--warn-line)}
  .danger .stamp{color:var(--danger);background:var(--danger-bg);border:1px solid var(--danger-line)}
  .accent .stamp{color:var(--accent);background:var(--accent-bg);border:1px solid var(--accent-line)}
  .verdict h1{font-size:22px;font-weight:700;letter-spacing:-.02em}
  .patchname{margin-top:2px;font-family:var(--mono);font-size:12px;color:var(--faint)}
  .chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}
  .chip{font-family:var(--mono);font-size:12px;background:var(--surface-2);
    border:1px solid var(--line);border-radius:7px;padding:5px 9px}
  .chip b{color:var(--faint);font-weight:500;margin-right:2px}
  .banner{margin-top:20px;border-radius:10px;padding:12px 16px;font-size:14px}
  .banner.danger{background:var(--danger-bg);border:1px solid var(--danger-line);color:var(--danger)}
  .banner ul{margin:8px 0 0 18px}
  .file{margin-top:18px;background:var(--surface);border:1px solid var(--line);border-radius:12px;overflow:hidden}
  .file-head{display:flex;align-items:center;justify-content:space-between;gap:12px;
    padding:12px 16px;background:var(--surface-2);border-bottom:1px solid var(--line)}
  .file-head .path{font-family:var(--mono);font-size:13px;font-weight:600}
  .file-head .arrow{color:var(--faint);margin:0 5px}
  .pill{font-family:var(--mono);font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;
    font-weight:600;padding:4px 9px;border-radius:999px}
  .pill.applied{color:var(--good);background:var(--good-bg)}
  .pill.no-op{color:var(--accent);background:var(--accent-bg)}
  .pill.needs-review{color:var(--warn);background:var(--warn-bg)}
  .pill.rejected{color:var(--danger);background:var(--danger-bg)}
  .cand-note{padding:10px 16px;font-size:13.5px;color:var(--muted);border-bottom:1px solid var(--line)}
  .cand-note b{color:var(--ink)}
  /* side-by-side */
  .sxswrap{overflow-x:auto;border-bottom:1px solid var(--line)}
  .sxs{display:grid;grid-template-columns:auto minmax(0,1fr) auto minmax(0,1fr);
    font-family:var(--mono);font-size:12px;line-height:1.6;min-width:640px}
  .sxs-h{background:var(--surface-2);color:var(--faint);font-family:var(--mono);
    font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;padding:7px 14px;
    border-bottom:1px solid var(--line)}
  .sxs-h.left{grid-column:1/3} .sxs-h.right{grid-column:3/5;border-left:1px solid var(--line)}
  .lno{text-align:right;padding:0 8px;color:var(--faint);user-select:none;
    border-right:1px solid var(--line);background:var(--code-bg)}
  .code{padding:0 12px;white-space:pre-wrap;word-break:break-word;background:var(--surface)}
  .code.pad,.lno.pad{background:repeating-linear-gradient(45deg,transparent,transparent 6px,var(--code-bg) 6px,var(--code-bg) 12px)}
  .lno.del{background:var(--del-gut);color:var(--del-ink)} .code.del{background:var(--del-bg);color:var(--del-ink)}
  .lno.add{background:var(--add-gut);color:var(--add-ink)} .code.add{background:var(--add-bg);color:var(--add-ink)}
  .code:nth-child(4n+2){border-right:1px solid var(--line)}
  .gap{grid-column:1/-1;background:var(--code-bg);color:var(--faint);text-align:center;
    font-size:11px;padding:5px;border-top:1px solid var(--line);border-bottom:1px solid var(--line);
    cursor:pointer;user-select:none;font-family:var(--mono)}
  .gap:hover{color:var(--accent);background:var(--accent-bg)}
  .gap.open{color:var(--accent)}
  .xr{display:none}
  .bar{display:flex;align-items:center;justify-content:space-between;gap:12px;
    padding:10px 16px;background:var(--surface-2);flex-wrap:wrap}
  .bar .hint{font-size:12.5px;color:var(--muted)}
  .btns{display:flex;gap:8px}
  button.act{font-family:var(--sans);font-size:12.5px;font-weight:600;cursor:pointer;
    border:1px solid var(--line);background:var(--surface);color:var(--ink);border-radius:8px;padding:7px 13px}
  button.act.primary{background:var(--accent);color:#fff;border-color:var(--accent)}
  .patchbox{border-top:1px solid var(--line)}
  .patchbox>summary{cursor:pointer;padding:9px 16px;font-size:12px;font-weight:600;
    color:var(--muted);background:var(--surface-2);list-style:none}
  .patchbox>summary::-webkit-details-marker{display:none}
  .patchbox>summary::before{content:'▸ ';color:var(--faint)}
  .patchbox[open]>summary::before{content:'▾ '}
  pre.patch{margin:0;overflow-x:auto;background:var(--code-bg);font-family:var(--mono);font-size:12px;line-height:1.6}
  pre.patch code{display:block;padding:10px 0}
  .pln{display:block;white-space:pre;padding:0 16px}
  .pln.d-add{background:var(--add-bg);color:var(--add-ink)}
  .pln.d-del{background:var(--del-bg);color:var(--del-ink)}
  .pln.d-hunk{color:var(--hunk);font-weight:600} .pln.d-head{color:var(--faint)}
  .defect{display:grid;grid-template-columns:48px 1fr;gap:14px;margin-top:12px;
    background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
  .defect .num{font-family:var(--mono);font-size:22px;font-weight:600;color:var(--faint)}
  .defect h3{font-size:15px;font-weight:600} .defect p{margin:7px 0 0;font-size:14px}
  .sevtag{display:inline-block;font-family:var(--mono);font-size:10px;letter-spacing:.07em;
    text-transform:uppercase;font-weight:600;padding:3px 8px;border-radius:6px;margin-bottom:7px}
  .s-compile,.s-leak,.s-danger{color:var(--danger);background:var(--danger-bg);border:1px solid var(--danger-line)}
  .s-dep,.s-warn{color:var(--warn);background:var(--warn-bg);border:1px solid var(--warn-line)}
  .s-info,.s-note{color:var(--accent);background:var(--accent-bg);border:1px solid var(--accent-line)}
  .ev{margin-top:10px;background:var(--code-bg);border:1px solid var(--line);border-radius:8px;
    padding:9px 12px;font-family:var(--mono);font-size:12px;color:var(--muted);overflow-x:auto;white-space:pre}
  .assist{margin-top:12px;background:var(--surface);border:1px solid var(--accent-line);
    border-radius:12px;overflow:hidden}
  .a-head{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:12px 16px;
    background:var(--accent-bg);border-bottom:1px solid var(--accent-line)}
  .a-badge{font-family:var(--mono);font-size:11px;font-weight:600;padding:4px 10px;border-radius:999px}
  .a-badge.ok{color:var(--good);background:var(--good-bg);border:1px solid var(--good-line)}
  .a-badge.bad{color:var(--danger);background:var(--danger-bg);border:1px solid var(--danger-line)}
  .a-note{font-size:12.5px;color:var(--muted)}
  .a-why{padding:12px 16px;font-size:14px;color:var(--ink);border-top:1px solid var(--line)}
  .whyblock{margin-top:26px;border:1px solid var(--line);border-radius:12px;background:var(--surface);overflow:hidden}
  .whyblock>summary{cursor:pointer;padding:13px 18px;font-size:13px;font-weight:600;color:var(--muted);
    list-style:none;background:var(--surface-2)}
  .whyblock>summary::-webkit-details-marker{display:none}
  .whyblock>summary::before{content:'▸ ';color:var(--faint)}
  .whyblock[open]>summary::before{content:'▾ '}
  .whyblock .defect:first-of-type{margin-top:14px}
  .whyblock .defect{margin-left:16px;margin-right:16px}
  .whyblock .defect:last-child{margin-bottom:16px}
  .prov{margin-top:40px;border-top:1px solid var(--line);padding-top:15px;
    font-family:var(--mono);font-size:12px;color:var(--faint)}
  .toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);background:var(--ink);
    color:var(--bg);padding:9px 16px;border-radius:8px;font-size:13px;opacity:0;
    transition:opacity .2s;pointer-events:none}
  .toast.show{opacity:1}
"""


# --------------------------------------------------------------------------- #
# batch summary index
# --------------------------------------------------------------------------- #


def render_summary(rows, tree=""):
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    tiles = "".join(
        f'<div class="tile s-{_esc(k)}"><div class="n">{v}</div>'
        f'<div class="l">{_esc(SUMMARY_LABEL.get(k, k))}</div></div>'
        for k, v in sorted(counts.items(), key=lambda kv: SUMMARY_ORDER.get(kv[0], 9)))
    trows = []
    for r in rows:
        files = ", ".join(r.get("files") or []) or "—"
        rep = r.get("report")
        name = (f'<a href="{_esc(rep)}">{_esc(r["patch"])}</a>' if rep else _esc(r["patch"]))
        trows.append(
            f'<tr><td class="mono">{name}</td><td class="mono">{_esc(r.get("cve") or "—")}</td>'
            f'<td>{_esc(r.get("severity") or "—")}</td>'
            f'<td><span class="pill s-{_esc(r["status"])}">{_esc(SUMMARY_LABEL.get(r["status"], r["status"]))}</span></td>'
            f'<td>{_esc(r.get("action") or "")}</td><td class="mono files">{_esc(files)}</td></tr>')
    return _SUMMARY.format(tiles=tiles, rows="".join(trows), tree=_esc(tree), total=len(rows))


_SUMMARY = r'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Patch merge report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap">
<style>
  :root{{--bg:#eef1f5;--surface:#fff;--surface-2:#f6f8fb;--ink:#152030;--muted:#5a6675;
    --faint:#8b97a6;--line:#dbe1ea;--accent:#2f4bb0;--good:#1a7f4b;--good-bg:#e4f4ea;
    --accent-bg:#e6ebf8;--warn:#a6690b;--warn-bg:#fbf1de;--danger:#b8321f;--danger-bg:#fbe9e6;
    --mono:"IBM Plex Mono",ui-monospace,Menlo,monospace;--sans:"IBM Plex Sans",system-ui,sans-serif;}}
  @media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{--bg:#0d1117;--surface:#161c26;
    --surface-2:#1c232f;--ink:#e7ecf3;--muted:#9aa7b7;--faint:#66727f;--line:#28313d;--accent:#8098ff;
    --good:#68c795;--good-bg:#132a1e;--accent-bg:#1e2740;--warn:#e0ac52;--warn-bg:#2c2413;--danger:#f0917f;--danger-bg:#2e1815;}}}}
  :root[data-theme="dark"]{{--bg:#0d1117;--surface:#161c26;--surface-2:#1c232f;--ink:#e7ecf3;--muted:#9aa7b7;
    --faint:#66727f;--line:#28313d;--accent:#8098ff;--good:#68c795;--good-bg:#132a1e;--accent-bg:#1e2740;
    --warn:#e0ac52;--warn-bg:#2c2413;--danger:#f0917f;--danger-bg:#2e1815;}}
  *{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);line-height:1.5}}
  .wrap{{max-width:1080px;margin:0 auto;padding:32px 24px 72px}}
  h1{{font-size:24px;font-weight:700;letter-spacing:-.02em;margin:0}}
  .sub{{color:var(--muted);margin-top:6px;font-size:14px}} .sub .mono{{font-family:var(--mono);font-size:12.5px}}
  .tiles{{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0 8px}}
  .tile{{flex:1;min-width:130px;background:var(--surface);border:1px solid var(--line);
    border-radius:12px;padding:16px 18px;border-left:5px solid var(--line)}}
  .tile.s-applied{{border-left-color:var(--good)}} .tile.s-no-op{{border-left-color:var(--accent)}}
  .tile.s-needs-review{{border-left-color:var(--warn)}} .tile.s-rejected{{border-left-color:var(--danger)}}
  .tile .n{{font-family:var(--mono);font-size:30px;font-weight:600}} .tile .l{{color:var(--muted);font-size:12.5px;margin-top:2px}}
  table{{width:100%;border-collapse:collapse;margin-top:22px;font-size:13.5px;background:var(--surface);
    border:1px solid var(--line);border-radius:12px;overflow:hidden}}
  th,td{{text-align:left;padding:11px 14px;border-bottom:1px solid var(--line);vertical-align:top}}
  th{{font-family:var(--mono);font-size:10.5px;letter-spacing:.09em;text-transform:uppercase;color:var(--faint);background:var(--surface-2)}}
  tr:last-child td{{border-bottom:none}} .mono{{font-family:var(--mono);font-size:12.5px}}
  .files{{color:var(--muted);font-size:11.5px}} a{{color:var(--accent)}}
  .pill{{font-family:var(--mono);font-size:10.5px;letter-spacing:.05em;text-transform:uppercase;
    font-weight:600;padding:4px 9px;border-radius:999px;white-space:nowrap}}
  .pill.s-applied{{color:var(--good);background:var(--good-bg)}} .pill.s-no-op{{color:var(--accent);background:var(--accent-bg)}}
  .pill.s-needs-review{{color:var(--warn);background:var(--warn-bg)}} .pill.s-rejected{{color:var(--danger);background:var(--danger-bg)}}
  .foot{{margin-top:20px;font-family:var(--mono);font-size:12px;color:var(--faint)}}
</style></head><body><div class="wrap">
  <h1>Patch merge report</h1>
  <div class="sub">{total} patches against <span class="mono">{tree}</span> · clean patches applied to the merged copy; conflicts and rejects left for you.</div>
  <div class="tiles">{tiles}</div>
  <table><thead><tr><th>patch</th><th>cve</th><th>severity</th><th>result</th><th>action</th><th>file(s)</th></tr></thead>
    <tbody>{rows}</tbody></table>
  <div class="foot">generated by the patch-merger skill · click a patch to open its full report</div>
</div></body></html>'''


if __name__ == "__main__":
    import sys
    rep = json.load(open(sys.argv[1]))
    sys.stdout.write(render(rep))
