"""
report/html_renderer.py

Builds a single, dependency-free HTML file: data is embedded as JSON,
filtering/search/chain-highlighting run in plain JS. No CDN fonts/scripts,
so the report still works when opened straight from disk with no network.
"""

from __future__ import annotations
import json
from html import escape

from ..models import AppraisalResult

RANK_COLORS = {
    "SSS": "#ff2d55", "SS": "#ff4d4d", "S": "#ff7a45",
    "A": "#f0a824", "B": "#e8d44d", "C": "#5aa9e6", "D": "#6b7280", "F": "#4b5563",
}


def render_html(result: AppraisalResult) -> str:
    findings = result.sorted_findings()
    data = {
        "extension_name": result.extension_name,
        "extension_version": result.extension_version,
        "manifest_version": result.manifest_version,
        "overall_grade": result.overall_grade(),
        "modules_run": result.modules_run,
        "modules_skipped": result.modules_skipped,
        "vendor_files": result.vendor_files,
        "findings": [
            {
                "id": f.id, "title": f.title, "category": f.category,
                "skill_name": f.skill_name, "skill_type": f.skill_type.value,
                "description": f.description, "technical_detail": f.technical_detail,
                "score": f.score, "rank": f.rank, "rank_label": f.rank_label,
                "vector": f.vector_short(), "evidence": f.evidence,
                "file": f.file, "line": f.line, "remediation": f.remediation,
                "references": f.references,
                "occurrence_count": f.occurrence_count, "all_lines": f.all_lines,
                "context": f.context,
                "verification": (
                    {"title": f.verification.title, "steps": f.verification.steps, "note": f.verification.note}
                    if f.verification else None
                ),
                "chain_ids": f.chain_ids, "is_chain_finding": f.is_chain_finding,
                "is_extinction": f.is_extinction,
            }
            for f in findings
        ],
    }
    data_json = json.dumps(data).replace("</", "<\\/")
    title = escape(f"GODSEYE: EX -- {result.extension_name}")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>{_CSS}</style>
</head>
<body>
<div id="app"></div>
<script>
const REPORT = {data_json};
{_JS}
</script>
</body>
</html>"""


_CSS = """
:root {
  --bg: #0a0b0d;
  --panel: #12141a;
  --panel-2: #181b22;
  --line: #232733;
  --text: #d8dce6;
  --text-dim: #8b92a3;
  --accent: #d9a93a;
  --mono: 'SF Mono', 'IBM Plex Mono', 'Liberation Mono', Menlo, Consolas, monospace;
  --sans: -apple-system, 'Segoe UI', 'Inter', Helvetica, Arial, sans-serif;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: radial-gradient(circle at 20% -10%, #1a1f2c 0%, var(--bg) 55%);
  color: var(--text); font-family: var(--sans); line-height: 1.5;
}
#app { max-width: 980px; margin: 0 auto; padding: 32px 20px 80px; }

.hero {
  border: 1px solid var(--line); background: linear-gradient(160deg, var(--panel) 0%, var(--panel-2) 100%);
  border-radius: 14px; padding: 28px 28px 24px; display: flex; align-items: center; gap: 28px;
  position: relative; overflow: hidden;
}
.hero::before {
  content: ""; position: absolute; inset: 0;
  background: repeating-linear-gradient(115deg, rgba(217,169,58,0.04) 0 2px, transparent 2px 28px);
  pointer-events: none;
}
.grade-badge {
  flex: 0 0 auto; width: 96px; height: 96px; border-radius: 12px;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  font-family: var(--mono); font-weight: 700; border: 2px solid currentColor; position: relative; z-index: 1;
}
.grade-badge .g { font-size: 38px; line-height: 1; }
.grade-badge .l { font-size: 9px; letter-spacing: 0.08em; color: var(--text-dim); margin-top: 4px; text-transform: uppercase; }
.hero-meta { position: relative; z-index: 1; }
.hero-meta h1 { margin: 0 0 4px; font-size: 22px; font-weight: 650; letter-spacing: -0.01em; }
.hero-meta .ver { color: var(--text-dim); font-family: var(--mono); font-size: 13px; }
.hero-meta .counts { margin-top: 14px; display: flex; gap: 10px; flex-wrap: wrap; }
.count-chip {
  font-family: var(--mono); font-size: 12px; padding: 4px 9px; border-radius: 999px;
  border: 1px solid var(--line); color: var(--text-dim);
}
.count-chip b { color: var(--text); }

.toolbar {
  margin-top: 22px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center;
}
.rank-filter {
  display: flex; gap: 6px; flex-wrap: wrap;
}
.rank-btn {
  font-family: var(--mono); font-size: 12px; font-weight: 700; padding: 5px 10px; border-radius: 6px;
  border: 1px solid var(--line); background: var(--panel); color: var(--text-dim); cursor: pointer;
  transition: transform 0.1s ease, opacity 0.15s ease;
}
.rank-btn[data-active="true"] { color: #0a0b0d; border-color: transparent; }
.rank-btn:hover { transform: translateY(-1px); }
#search {
  flex: 1; min-width: 180px; background: var(--panel); border: 1px solid var(--line); color: var(--text);
  border-radius: 8px; padding: 8px 12px; font-family: var(--sans); font-size: 13px;
}
#search:focus { outline: none; border-color: var(--accent); }

.findings { margin-top: 22px; display: flex; flex-direction: column; gap: 12px; }
.card {
  border: 1px solid var(--line); background: var(--panel); border-radius: 10px; padding: 16px 18px;
  border-left: 4px solid var(--line);
}
.card.chain { border-left-color: #ff4d4d; background: linear-gradient(90deg, rgba(255,77,77,0.07), var(--panel) 18%); }
.card-top { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
.rank-pill {
  font-family: var(--mono); font-weight: 800; font-size: 12px; padding: 2px 8px; border-radius: 5px; color: #0a0b0d;
}
.card-title { font-weight: 650; font-size: 15px; }
.card-meta { margin-left: auto; font-family: var(--mono); font-size: 11px; color: var(--text-dim); }
.card-cat { font-family: var(--mono); font-size: 10px; color: var(--text-dim); border: 1px solid var(--line); border-radius: 4px; padding: 1px 6px; }
.card-body { margin-top: 10px; font-size: 13.5px; color: var(--text); }
.card-tech { margin-top: 6px; font-size: 13px; color: var(--text-dim); }
.section-label { font-family: var(--mono); font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--accent); margin-top: 12px; margin-bottom: 4px; }
.evidence, .remediation, .steps li { font-family: var(--mono); font-size: 12.5px; }
.evidence { background: #0d0f13; border: 1px solid var(--line); border-radius: 6px; padding: 8px 10px; color: #9fb0c3; white-space: pre-wrap; word-break: break-word; }
.code-block { background: #0d0f13; border: 1px solid var(--line); border-radius: 6px; padding: 6px 0; font-family: var(--mono); font-size: 12px; overflow-x: auto; }
.code-line { display: flex; gap: 10px; padding: 1px 10px; white-space: pre; }
.code-line .ln { color: var(--text-dim); min-width: 32px; text-align: right; user-select: none; }
.code-line.hit { background: rgba(217,169,58,0.12); border-left: 3px solid var(--accent); }
.code-line.hit .ln { color: var(--accent); font-weight: 700; }
.jump-row { display: flex; align-items: center; gap: 8px; margin-top: 6px; font-family: var(--mono); font-size: 11.5px; color: var(--text-dim); }
.copy-btn { font-family: var(--mono); font-size: 11px; padding: 2px 8px; border-radius: 5px; border: 1px solid var(--line); background: var(--panel-2); color: var(--text-dim); cursor: pointer; }
.copy-btn:hover { color: var(--text); border-color: var(--accent); }
.chain-pills { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 4px; }
.chain-pill {
  font-family: var(--mono); font-size: 11px; padding: 2px 8px; border-radius: 999px;
  border: 1px solid #ff4d4d; color: #ff8a8a; cursor: pointer; background: rgba(255,77,77,0.08);
}
.chain-pill:hover { background: rgba(255,77,77,0.18); }
.steps { margin: 4px 0 0 0; padding-left: 18px; color: var(--text-dim); }
.steps li { margin-bottom: 3px; }
.file-line { margin-top: 10px; font-family: var(--mono); font-size: 11.5px; color: var(--text-dim); }
.flash { animation: flash 1.1s ease; }
@keyframes flash { 0% { box-shadow: 0 0 0 2px #ff4d4d; } 100% { box-shadow: 0 0 0 0 rgba(255,77,77,0); } }
.empty { text-align: center; color: var(--text-dim); padding: 40px 0; font-family: var(--mono); font-size: 13px; }
footer { margin-top: 36px; text-align: center; color: var(--text-dim); font-size: 11px; font-family: var(--mono); }
"""

_JS = r"""
const RANK_COLORS = {SSS:"#ff2d55",SS:"#ff4d4d",S:"#ff7a45",A:"#f0a824",B:"#e8d44d",C:"#5aa9e6",D:"#6b7280",F:"#4b5563"};
const RANK_ORDER = ["SSS","SS","S","A","B","C","D","F"];

const state = { activeRanks: new Set(RANK_ORDER), query: "" };

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
}

function counts() {
  const c = {};
  for (const f of REPORT.findings) c[f.rank] = (c[f.rank]||0) + 1;
  return c;
}

function renderHero() {
  const grade = REPORT.overall_grade;
  const color = RANK_COLORS[grade] || "#6b7280";
  const c = counts();
  const chips = RANK_ORDER.filter(r => c[r]).map(r =>
    `<span class="count-chip" style="border-color:${color === RANK_COLORS[r] ? RANK_COLORS[r] : 'var(--line)'}"><b style="color:${RANK_COLORS[r]}">${c[r]}</b> ${r}</span>`
  ).join("");
  return `
    <div class="hero">
      <div class="grade-badge" style="color:${color}">
        <div class="g">${grade}</div>
        <div class="l">grade</div>
      </div>
      <div class="hero-meta">
        <h1>${escapeHtml(REPORT.extension_name)}</h1>
        <div class="ver">v${escapeHtml(REPORT.extension_version)} &middot; manifest v${REPORT.manifest_version ?? "?"} &middot; ${REPORT.modules_run.length} modules run${REPORT.vendor_files.length ? ` &middot; ${REPORT.vendor_files.length} vendor file(s) excluded` : ""}</div>
        <div class="counts">${chips || '<span class="count-chip">no findings</span>'}</div>
      </div>
    </div>`;
}

function renderToolbar() {
  const btns = RANK_ORDER.map(r => {
    const active = state.activeRanks.has(r);
    const bg = active ? RANK_COLORS[r] : "transparent";
    return `<button class="rank-btn" data-rank="${r}" data-active="${active}" style="background:${bg};${active ? "" : "color:"+RANK_COLORS[r]+";border-color:"+RANK_COLORS[r]+"55;"}">${r}</button>`;
  }).join("");
  return `
    <div class="toolbar">
      <div class="rank-filter">${btns}</div>
      <input id="search" type="text" placeholder="Search findings, files, rule IDs..." />
    </div>`;
}

function findingMatches(f) {
  if (!state.activeRanks.has(f.rank)) return false;
  if (!state.query) return true;
  const q = state.query.toLowerCase();
  return [f.title, f.id, f.file, f.description, f.category].some(v => String(v||"").toLowerCase().includes(q));
}

function renderCard(f) {
  const color = RANK_COLORS[f.rank] || "#6b7280";
  const chainPills = (f.chain_ids||[]).map(id => `<span class="chain-pill" data-jump="${escapeHtml(id)}">${escapeHtml(id)}</span>`).join("");
  const evidence = (f.evidence||[]).map(e => escapeHtml(e)).join("\n");
  const isCrossFile = String(f.file||"").startsWith("(");
  const codeBlock = (f.context && f.context.length && !isCrossFile) ? `
    <div class="section-label">Location</div>
    <div class="code-block">${f.context.map(([ln, content]) =>
      `<div class="code-line ${ln === f.line ? "hit" : ""}"><span class="ln">${ln}</span><span>${escapeHtml(content)}</span></div>`
    ).join("")}</div>
    <div class="jump-row">
      <code>code --goto ${escapeHtml(f.file)}:${f.line}</code>
      <button class="copy-btn" data-copy="code --goto ${escapeHtml(f.file)}:${f.line}">copy</button>
      <code>vim +${f.line} ${escapeHtml(f.file)}</code>
      <button class="copy-btn" data-copy="vim +${f.line} ${escapeHtml(f.file)}">copy</button>
    </div>
  ` : "";
  const steps = f.verification ? `
    <div class="section-label">Verify (non-exploit)</div>
    <div><strong>${escapeHtml(f.verification.title)}</strong></div>
    <ul class="steps">${f.verification.steps.map(s => `<li>${escapeHtml(s)}</li>`).join("")}</ul>
  ` : "";
  return `
    <div class="card ${f.is_chain_finding ? "chain" : ""}" id="finding-${escapeHtml(f.id)}">
      <div class="card-top">
        <span class="rank-pill" style="background:${color}">${f.rank}</span>
        <span class="card-title">${escapeHtml(f.title)}</span>
        <span class="card-cat">${escapeHtml(f.category)}</span>
        <span class="card-meta">${escapeHtml(f.id)} &middot; CVSS ${f.score} &middot; ${escapeHtml(f.vector)}</span>
      </div>
      <div class="card-body">${escapeHtml(f.description)}</div>
      <div class="card-tech">${escapeHtml(f.technical_detail)}</div>
      ${chainPills ? `<div class="section-label">Chain components</div><div class="chain-pills">${chainPills}</div>` : ""}
      ${evidence ? `<div class="section-label">Evidence</div><div class="evidence">${evidence}</div>` : ""}
      ${f.occurrence_count > 1 ? `<div class="section-label">Occurrences</div><div class="evidence">${f.occurrence_count} occurrences -- lines: ${f.all_lines.join(", ")}</div>` : ""}
      ${codeBlock}
      <div class="section-label">Remediation</div>
      <div class="evidence">${escapeHtml(f.remediation)}</div>
      ${steps}
      <div class="file-line">${escapeHtml(f.file)}${f.line ? ":" + f.line : ""}</div>
    </div>`;
}

function render() {
  const visible = REPORT.findings.filter(findingMatches);
  const body = visible.length
    ? visible.map(renderCard).join("")
    : `<div class="empty">No findings match the current filter.</div>`;
  document.getElementById("app").innerHTML = `
    ${renderHero()}
    ${renderToolbar()}
    <div class="findings">${body}</div>
    <footer>GODSEYE: EX -- static analysis only. No code from this extension was executed to produce this report.</footer>
  `;
  document.getElementById("search").value = state.query;
  document.getElementById("search").addEventListener("input", e => { state.query = e.target.value; render(); });
  document.querySelectorAll(".rank-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const r = btn.dataset.rank;
      if (state.activeRanks.has(r)) state.activeRanks.delete(r); else state.activeRanks.add(r);
      render();
    });
  });
  document.querySelectorAll(".chain-pill").forEach(pill => {
    pill.addEventListener("click", () => {
      const target = document.getElementById("finding-" + pill.dataset.jump);
      if (target) {
        target.scrollIntoView({behavior: "smooth", block: "center"});
        target.classList.remove("flash");
        requestAnimationFrame(() => target.classList.add("flash"));
      }
    });
  });
  document.querySelectorAll(".copy-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const text = btn.dataset.copy;
      const original = btn.textContent;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
          btn.textContent = "copied!";
          setTimeout(() => { btn.textContent = original; }, 1200);
        }).catch(() => {});
      }
    });
  });
}

render();
"""
