"""
engine/logging_config.py

Structured logging for the engine. Deliberately writes to stderr only --
scan output (console report, JSON, SARIF redirected to a file, etc.) goes
to stdout, and the two must never mix or a piped/redirected report file
would end up with log noise in it.

Default level is WARNING so a normal scan stays quiet; --verbose on the
CLI bumps this to INFO/DEBUG.
"""

from __future__ import annotations
import logging
import sys

_CONFIGURED = False


def configure(verbose: bool = False) -> None:
    global _CONFIGURED
    if _CONFIGURED:
        logging.getLogger("godseye").setLevel(logging.DEBUG if verbose else logging.WARNING)
        return

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    ))
    root = logging.getLogger("godseye")
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if verbose else logging.WARNING)
    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    if not _CONFIGURED:
        configure()
    return logging.getLogger(f"godseye.{name}")
