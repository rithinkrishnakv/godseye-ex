"""
report/theatrics.py

Polished terminal presentation for `godseye-ex scan`, built on `rich`.
Purely cosmetic: every number shown here comes from the same
AppraisalResult the plain renderer and JSON/SARIF/HTML outputs use.
Nothing here generates findings, executes anything, or talks to the
extension -- it only formats what the engine already produced.
"""

from __future__ import annotations
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.box import ROUNDED, HEAVY

from ..models import AppraisalResult, Finding

RANK_STYLE = {
    "SSS": ("\u2620", "bold white on red", "Extinction"),
    "SS": ("\u26a1", "bold red", "Devastating"),
    "S": ("\u2694", "red", "Critical"),
    "A": ("\u2605", "bright_yellow", "High"),
    "B": ("\u25b2", "yellow", "Medium"),
    "C": ("\u25c6", "cyan", "Low"),
    "D": ("\u25c7", "grey62", "Hardening"),
    "F": ("\u25cb", "grey50", "Informational"),
}
RANK_ORDER = ["SSS", "SS", "S", "A", "B", "C", "D", "F"]

VERSION = "1.0.0"
TAGLINE = "Static Extension Analysis Engine"
SUBTITLE = f"v{VERSION} \u2014 16 modules. Single-pass tokenizer. Real handler-body resolution."


def make_console(no_color: bool) -> Console:
    return Console(no_color=no_color, highlight=False)


def print_banner(console: Console) -> None:
    title = Text("GODSEYE: EX", style="bold magenta")
    body = Text()
    body.append(TAGLINE + "\n", style="italic cyan")
    body.append(SUBTITLE, style="dim")
    console.print(Panel(Align.center(body), title=title, box=HEAVY, border_style="magenta", padding=(1, 2)))


class ScanProgressBoard:
    """Prints one line per module as it completes. No Live/threads needed --
    modules run fast enough that a plain sequential print reads as "live."
    """

    def __init__(self, console: Console, total: int):
        self.console = console
        self.total = total
        self.done = 0
        self.console.print(Panel(Text("starting modules...", style="dim"), title="APPRAISAL IN PROGRESS",
                                  box=ROUNDED, border_style="grey50"))

    def report(self, name: str, type_: str, category: str, count: int | None, elapsed: float, skipped: bool) -> None:
        self.done += 1
        mark = "[dim]\u2014 skipped[/dim]" if skipped else "[green]\u2713[/green]"
        count_str = "" if skipped else f"  {count} finding{'s' if count != 1 else ''}"
        timing = "" if skipped else f"  [dim]{elapsed:.2f}s[/dim]"
        self.console.print(f"  {mark}  [{type_:<7}] {category:<5} {name:<28}{count_str}{timing}")


def print_target_locked(console: Console, result: AppraisalResult, scan_seconds: float) -> None:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="dim", justify="left")
    table.add_column(justify="left")
    table.add_row("Name", result.extension_name)
    table.add_row("Version", result.extension_version)
    table.add_row("Manifest", str(result.manifest_version))
    table.add_row("Modules run", f"{len(result.modules_run)} ({len(result.modules_skipped)} skipped)")
    if result.vendor_files:
        table.add_row("Vendor excluded", f"{len(result.vendor_files)} file(s)")
    table.add_row("Scan time", f"{scan_seconds:.2f}s")
    table.add_row("Timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    table.add_row("Total findings", str(len(result.findings)))
    console.print(Panel(table, title="TARGET LOCKED", box=HEAVY, border_style="cyan"))


def print_summary(console: Console, result: AppraisalResult) -> None:
    counts: dict[str, int] = {r: 0 for r in RANK_ORDER}
    for f in result.findings:
        counts[f.rank] = counts.get(f.rank, 0) + 1
    max_count = max(counts.values()) or 1

    table = Table(title="APPRAISAL SUMMARY", box=ROUNDED, show_lines=False)
    table.add_column("Rank", justify="center")
    table.add_column("Class")
    table.add_column("Count", justify="right")
    table.add_column("Status")

    for rank in RANK_ORDER:
        icon, style, label = RANK_STYLE[rank]
        n = counts[rank]
        bar_len = int((n / max_count) * 24) if n else 0
        bar = ("\u2588" * bar_len) or "\u00b7"
        table.add_row(f"[{style}]{icon} {rank}[/{style}]", label, str(n), f"[{style}]{bar}[/{style}]")

    console.print(table)

    highest = next((r for r in RANK_ORDER if counts[r] > 0), "F")
    icon, style, label = RANK_STYLE[highest]
    console.print(Panel(Align.center(Text(f"{icon} HIGHEST RANK: {highest} \u2014 {label}", style=f"bold {style}")),
                         box=ROUNDED, border_style=style))


def _finding_panel(f: Finding) -> Panel:
    icon, style, _ = RANK_STYLE.get(f.rank, ("\u25cb", "grey50", ""))
    header = Text()
    header.append(f"{icon} [{f.rank}] ", style=f"bold {style}")
    header.append(f.title)

    meta = Text(f"ID: {f.id}   Category: {f.category}   CVSS: {f.score}   {f.cvss.vector_string()}", style="dim")

    body = Text()
    body.append("Description\n", style="bold")
    body.append(f.description + "\n\n")
    body.append("Technical Detail\n", style="bold")
    body.append(f.technical_detail + "\n")
    if f.evidence:
        body.append("\nEvidence\n", style="bold")
        for e in f.evidence:
            body.append(f"  \u25b8 {e}\n", style="dim")
    if f.occurrence_count > 1:
        body.append(f"\n{f.occurrence_count} occurrences \u2014 lines: {', '.join(str(l) for l in f.all_lines)}\n", style="dim")
    if f.is_chain_finding:
        body.append(f"\nChain components: {', '.join(f.chain_ids)}\n", style="dim")
    body.append("\nRemediation\n", style="bold")
    body.append(f.remediation + "\n")
    if f.context and not f.file.startswith("("):
        body.append("\nLocation\n", style="bold")
        for ln, content in f.context:
            if ln == f.line:
                body.append(f"  \u25b8 {ln:>4} | {content}\n", style=f"bold {style}")
            else:
                body.append(f"    {ln:>4} | {content}\n", style="dim")
        body.append(f"  jump: code --goto {f.file}:{f.line}   |   vim +{f.line} {f.file}\n", style="dim italic")
    if f.verification:
        body.append(f"\nVerify ({f.verification.title})\n", style="bold")
        for step in f.verification.steps:
            body.append(f"  {step}\n", style="dim")
    loc = f.file if f.file.startswith("(") else f"{f.file}:{f.line}"
    body.append(f"\n{loc}", style="dim italic")

    content = Text.assemble(header, "\n", meta, "\n\n", body)
    return Panel(content, box=ROUNDED, border_style=style)


def print_findings(console: Console, result: AppraisalResult) -> None:
    console.rule("APPRAISAL RESULTS")
    for f in result.sorted_findings():
        console.print(_finding_panel(f))
    console.rule("END OF APPRAISAL")
