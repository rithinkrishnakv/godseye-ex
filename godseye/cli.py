"""
cli.py -- GODSEYE: EX v2 command-line entrypoint.

    godseye-ex scan <path> [--json out.json] [--html out.html] [--sarif out.sarif] [--min-rank B] [--skip "Module Name"]
    godseye-ex diff <old> <new> [--html out.html]
    godseye-ex info <path>
    godseye-ex list-modules

Static analysis only: reads manifest.json + source files, never launches a
browser or executes anything from the target extension.
"""

from __future__ import annotations
import argparse
import sys
import time
from pathlib import Path

from .engine.orchestrator import scan as run_scan, list_modules
from .engine.diff import diff as run_diff, render_diff_console
from .report.renderer import render_console, to_json, to_sarif
from .report.html_renderer import render_html
from .report import theatrics

RANK_ORDER = {"SSS": 0, "SS": 1, "S": 2, "A": 3, "B": 4, "C": 5, "D": 6, "F": 7}


def _write(path: str, content: str, label: str) -> None:
    Path(path).write_text(content, encoding="utf-8")
    print(f"{label} written to {path}")


def cmd_scan(args: argparse.Namespace) -> int:
    if args.plain:
        result = run_scan(args.target, skip=args.skip, include_vendor=args.include_vendor)
        if args.min_rank:
            threshold = RANK_ORDER[args.min_rank]
            result.findings = [f for f in result.findings if RANK_ORDER.get(f.rank, 8) <= threshold]
        print(render_console(result, use_color=not args.no_color))
    else:
        console = theatrics.make_console(no_color=args.no_color)
        theatrics.print_banner(console)
        board = None

        def on_module_done(name, type_, category, count, elapsed, skipped):
            nonlocal board
            if board is None:
                board = theatrics.ScanProgressBoard(console, total=len(list_modules()))
            board.report(name, type_, category, count, elapsed, skipped)

        start = time.perf_counter()
        result = run_scan(args.target, skip=args.skip, include_vendor=args.include_vendor, on_module_done=on_module_done)
        scan_seconds = time.perf_counter() - start

        if args.min_rank:
            threshold = RANK_ORDER[args.min_rank]
            result.findings = [f for f in result.findings if RANK_ORDER.get(f.rank, 8) <= threshold]

        theatrics.print_target_locked(console, result, scan_seconds)
        theatrics.print_summary(console, result)
        theatrics.print_findings(console, result)

    if args.json:
        _write(args.json, to_json(result), "JSON report")
    if args.sarif:
        _write(args.sarif, to_sarif(result), "SARIF report")
    if args.html:
        _write(args.html, render_html(result), "HTML report")

    if args.fail_on != "never":
        threshold = RANK_ORDER[args.fail_on]
        if any(RANK_ORDER.get(f.rank, 8) <= threshold for f in result.findings):
            return 1
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    old = run_scan(args.old)
    new = run_scan(args.new)
    d = run_diff(old, new)
    print(render_diff_console(d, use_color=not args.no_color))
    if args.html:
        # Reuse the single-result HTML renderer on the "new" scan, annotated with diff context.
        new.findings = d.added + d.unchanged
        _write(args.html, render_html(new), "HTML report (new-version findings)")
    return 1 if d.regressed else 0


def cmd_info(args: argparse.Namespace) -> int:
    result = run_scan(args.target, skip=[m["name"] for m in list_modules()])  # manifest only, skip all modules
    print(f"Name:             {result.extension_name}")
    print(f"Version:          {result.extension_version}")
    print(f"Manifest version: {result.manifest_version}")
    return 0


def cmd_list_modules(args: argparse.Namespace) -> int:
    for m in list_modules():
        print(f"[{m['type']:<7}] {m['category']:<5} {m['name']:<28} {m['description']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="godseye-ex", description="Static security appraisal for browser extensions.")
    sub = p.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a single extension")
    p_scan.add_argument("target", help="Unpacked extension directory, or a .crx/.xpi/.zip file")
    p_scan.add_argument("--json", metavar="FILE")
    p_scan.add_argument("--html", metavar="FILE")
    p_scan.add_argument("--sarif", metavar="FILE")
    p_scan.add_argument("--no-color", action="store_true")
    p_scan.add_argument("--min-rank", choices=list(RANK_ORDER.keys()), default=None,
                         help="Only show findings at or above this rank")
    p_scan.add_argument("--skip", action="append", default=[], metavar="MODULE_NAME",
                         help="Skip a module by name (repeatable)")
    p_scan.add_argument("--include-vendor", action="store_true",
                         help="Don't exclude vendored/minified third-party JS from pattern scanning")
    p_scan.add_argument("--plain", action="store_true",
                         help="Plain-text output (no banner/panels) -- friendlier for CI logs/grep")
    p_scan.add_argument("--fail-on", choices=[*RANK_ORDER.keys(), "never"], default="S",
                         help="Exit non-zero if a finding at or above this rank exists (default: S)")
    p_scan.set_defaults(func=cmd_scan)

    p_diff = sub.add_parser("diff", help="Compare two versions of an extension")
    p_diff.add_argument("old")
    p_diff.add_argument("new")
    p_diff.add_argument("--html", metavar="FILE")
    p_diff.add_argument("--no-color", action="store_true")
    p_diff.set_defaults(func=cmd_diff)

    p_info = sub.add_parser("info", help="Show extension metadata without a full scan")
    p_info.add_argument("target")
    p_info.set_defaults(func=cmd_info)

    p_list = sub.add_parser("list-modules", help="List all available analysis modules")
    p_list.set_defaults(func=cmd_list_modules)

    return p


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(run())
