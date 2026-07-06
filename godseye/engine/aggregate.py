"""
engine/aggregate.py

Collapses repeated identical findings (same rule, same file) into a single
Finding with an occurrence count and the full list of lines, instead of
N near-identical cards. Pure presentation-layer deduplication -- doesn't
change what was found, just how many times it's shown.
"""

from __future__ import annotations
from dataclasses import replace

from ..models import Finding


def aggregate_findings(findings: list[Finding]) -> list[Finding]:
    groups: dict[tuple[str, str], list[Finding]] = {}
    order: list[tuple[str, str]] = []

    for f in findings:
        key = (f.id, f.file)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    result: list[Finding] = []
    for key in order:
        group = groups[key]
        if len(group) == 1:
            result.append(group[0])
            continue

        primary = group[0]
        lines = sorted({g.line for g in group})
        evidence: list[str] = []
        seen: set[str] = set()
        for g in group:
            for e in g.evidence:
                if e not in seen:
                    seen.add(e)
                    evidence.append(e)
        shown_evidence = evidence[:3]
        if len(evidence) > 3:
            shown_evidence.append(f"... and {len(evidence) - 3} more occurrence(s) not shown")

        merged = replace(
            primary,
            title=f"{primary.title} (\u00d7{len(group)} occurrences)",
            evidence=shown_evidence,
            line=lines[0],
            occurrence_count=len(group),
            all_lines=lines,
        )
        result.append(merged)

    return result
