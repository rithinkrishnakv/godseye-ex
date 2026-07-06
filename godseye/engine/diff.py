"""
engine/diff.py -- compare two AppraisalResult objects (e.g. v1.2 vs v1.3
of the same extension) and report what changed.
"""

from __future__ import annotations
from dataclasses import dataclass, field

from ..models import AppraisalResult, Finding


@dataclass
class DiffResult:
    old_label: str
    new_label: str
    added: list[Finding] = field(default_factory=list)
    removed: list[Finding] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)

    @property
    def regressed(self) -> bool:
        return any(f.rank in ("SSS", "SS", "S", "A") for f in self.added)


def diff(old: AppraisalResult, new: AppraisalResult) -> DiffResult:
    # Key by (rule id, file) so the same rule firing in a different file still counts as "added".
    def key(f: Finding) -> tuple[str, str]:
        return (f.id, f.file)

    old_by_key = {key(f): f for f in old.findings}
    new_by_key = {key(f): f for f in new.findings}

    added = [f for k, f in new_by_key.items() if k not in old_by_key]
    removed = [f for k, f in old_by_key.items() if k not in new_by_key]
    unchanged = [f for k, f in new_by_key.items() if k in old_by_key]

    rank_order = {"SSS": 0, "SS": 1, "S": 2, "A": 3, "B": 4, "C": 5, "D": 6, "F": 7}
    added.sort(key=lambda f: rank_order.get(f.rank, 8))
    removed.sort(key=lambda f: rank_order.get(f.rank, 8))

    return DiffResult(
        old_label=f"{old.extension_name} v{old.extension_version}",
        new_label=f"{new.extension_name} v{new.extension_version}",
        added=added, removed=removed, unchanged=unchanged,
    )


def render_diff_console(d: DiffResult, use_color: bool = True) -> str:
    red = "\033[91m" if use_color else ""
    green = "\033[92m" if use_color else ""
    reset = "\033[0m" if use_color else ""

    lines = [f"\nGODSEYE: EX diff -- {d.old_label}  ->  {d.new_label}"]
    lines.append("-" * 60)
    if d.added:
        lines.append(f"{red}NEW findings ({len(d.added)}):{reset}")
        for f in d.added:
            lines.append(f"  {red}+{reset} [{f.rank}] {f.title}  ({f.file}:{f.line})")
    else:
        lines.append("No new findings.")

    lines.append("")
    if d.removed:
        lines.append(f"{green}RESOLVED findings ({len(d.removed)}):{reset}")
        for f in d.removed:
            lines.append(f"  {green}-{reset} [{f.rank}] {f.title}  ({f.file}:{f.line})")
    else:
        lines.append("Nothing resolved.")

    lines.append("")
    lines.append(f"Unchanged: {len(d.unchanged)}")
    if d.regressed:
        lines.append(f"\n{red}REGRESSION: a high-rank finding was introduced.{reset}")
    return "\n".join(lines)
