"""
report/renderer.py -- console / JSON / SARIF output for a scan result.
"""

from __future__ import annotations
import json
from dataclasses import asdict
from datetime import datetime, timezone

from ..models import AppraisalResult, Finding

RANK_COLOR = {
    "SSS": "\033[1;97;41m", "SS": "\033[1;91m", "S": "\033[91m",
    "A": "\033[93m", "B": "\033[33m", "C": "\033[94m", "D": "\033[90m", "F": "\033[90m",
}
RESET = "\033[0m"
SEVERITY_RANK_FOR_SARIF = {
    "SSS": "error", "SS": "error", "S": "error", "A": "error",
    "B": "warning", "C": "warning", "D": "note", "F": "note",
}


def _card(f: Finding, use_color: bool) -> str:
    c = RANK_COLOR.get(f.rank, "") if use_color else ""
    r = RESET if use_color else ""
    width = 70
    rule = "─" * width
    lines = []
    lines.append(f"{c}┌{rule}┐{r}")
    lines.append(f"{c}│{r} [{f.rank}] {f.title}")
    lines.append(f"{c}│{r} {f.id}   CVSS {f.score} ({f.vector_short()})")
    lines.append(f"{c}├{rule}┤{r}")
    for chunk in _wrap(f.description, width - 2):
        lines.append(f"{c}│{r} {chunk}")
    if f.is_chain_finding:
        lines.append(f"{c}│{r} components: {', '.join(f.chain_ids)}")
    if f.occurrence_count > 1:
        shown = ", ".join(str(l) for l in f.all_lines[:8])
        more = "" if len(f.all_lines) <= 8 else f" (+{len(f.all_lines) - 8} more)"
        lines.append(f"{c}│{r} occurrences: {f.occurrence_count}  lines: {shown}{more}")
    lines.append(f"{c}│{r} file: {f.file}:{f.line}")
    if f.context and not f.file.startswith("("):
        lines.append(f"{c}│{r}")
        for ln, content in f.context:
            marker = "\u25b8" if ln == f.line else " "
            lines.append(f"{c}│{r} {marker} {ln:>4} | {content}")
        lines.append(f"{c}│{r} jump: code --goto {f.file}:{f.line}   |   vim +{f.line} {f.file}")
    lines.append(f"{c}└{rule}┘{r}")
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines, cur = [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines or [""]


# Finding.score already exists; add a short vector helper as a free function
def _vector_short(f: Finding) -> str:
    v = f.cvss
    return f"AV:{v.AV}/AC:{v.AC}/PR:{v.PR}/UI:{v.UI}/S:{v.S}/C:{v.C}/I:{v.I}/A:{v.A}"


Finding.vector_short = _vector_short  # type: ignore[attr-defined]


def render_console(result: AppraisalResult, use_color: bool = True) -> str:
    findings = result.sorted_findings()
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.rank] = counts.get(f.rank, 0) + 1

    lines = []
    lines.append(f"\nGODSEYE: EX -- static appraisal of {result.extension_name} v{result.extension_version}")
    lines.append(f"Manifest version: {result.manifest_version}    Overall grade: {result.overall_grade()}")
    lines.append("Findings by rank: " + "  ".join(f"{r}:{counts.get(r,0)}" for r in ("SSS","SS","S","A","B","C","D","F") if counts.get(r)))
    lines.append(f"Modules run: {len(result.modules_run)}" + (f"  (skipped: {', '.join(result.modules_skipped)})" if result.modules_skipped else ""))
    if result.vendor_files:
        lines.append(f"Vendor/minified files excluded from pattern scanning: {len(result.vendor_files)} (use --include-vendor to scan anyway)")
    lines.append("-" * 72)
    if not findings:
        lines.append("No issues detected by current ruleset.")
    for f in findings:
        lines.append(_card(f, use_color))
        lines.append("")
    return "\n".join(lines)


def to_json(result: AppraisalResult) -> str:
    payload = {
        "tool": "godseye-ex",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": result.target,
        "extension_name": result.extension_name,
        "extension_version": result.extension_version,
        "manifest_version": result.manifest_version,
        "overall_grade": result.overall_grade(),
        "modules_run": result.modules_run,
        "modules_skipped": result.modules_skipped,
        "vendor_files": result.vendor_files,
        "findings": [
            {**asdict(f), "score": f.score, "rank": f.rank, "rank_label": f.rank_label,
             "cvss_vector": f.cvss.vector_string()}
            for f in result.sorted_findings()
        ],
    }
    return json.dumps(payload, indent=2, default=str)


def to_sarif(result: AppraisalResult) -> str:
    rules, results = {}, []
    for f in result.sorted_findings():
        if f.id not in rules:
            rules[f.id] = {
                "id": f.id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.technical_detail},
                "help": {"text": f.remediation or f.technical_detail},
                "properties": {"category": f.category, "rank": f.rank},
            }
        results.append({
            "ruleId": f.id,
            "level": SEVERITY_RANK_FOR_SARIF.get(f.rank, "warning"),
            "message": {"text": f"[{f.rank}] {f.description}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file or "manifest.json"},
                    "region": {"startLine": max(f.line, 1)},
                }
            }],
        })

    from .. import __version__ as _godseye_version

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "GODSEYE-EX",
                "informationUri": "https://github.com/rithinkrishnakv/godseye-ex",
                "version": _godseye_version,
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"target": result.extension_name, "version": result.extension_version},
        }],
    }
    return json.dumps(sarif, indent=2)
