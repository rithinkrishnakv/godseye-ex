"""
engine/vendor_detect.py

Identifies third-party/vendored/minified JS so structural pattern modules
(injection, dynamic-code, messaging, hardening, storage) don't spam alerts
for code nobody wrote and nobody is going to "fix." The Supply Chain
module deliberately does NOT use this filter -- fingerprinting vendor
libraries for known CVEs is its entire job.

This is a heuristic, not a guarantee: a real first-party file that happens
to be heavily minified will also get excluded. Use --include-vendor on
the CLI to disable this and scan everything.
"""

from __future__ import annotations
import re

KNOWN_LIBRARY_RE = re.compile(
    r"(?i)\b(jquery|angular|react(-dom)?|vue|lodash|underscore|moment|"
    r"bootstrap|popper|d3|chart(\.?js)?|three|backbone|knockout|"
    r"fontawesome|font-awesome|polyfill|sweetalert2?|select2|dropzone|"
    r"ext-all|modernizr|swiper|slick|axios|socket\.io|babel|webpack|"
    r"core-js|regenerator-runtime|prop-types|redux)([.\-][\w.]*)?\.js$"
)
MIN_SUFFIX_RE = re.compile(r"\.min\.js$", re.IGNORECASE)
VENDOR_DIR_RE = re.compile(r"(?i)[/\\](vendor|libs?|third[-_]?party|node_modules|bower_components)[/\\]")
LICENSE_BANNER_RE = re.compile(r"/\*!?\s*(jQuery|Bootstrap|@license|Copyright)")


def looks_minified(text: str) -> bool:
    lines = text.splitlines() or [""]
    if len(lines) <= 15 and len(text) > 3000:
        return True
    longest = max(len(l) for l in lines)
    if longest > 900:
        return True
    avg = sum(len(l) for l in lines) / len(lines)
    return avg > 250


def is_vendor_file(rel_path: str, text: str) -> bool:
    name = rel_path.replace("\\", "/").rsplit("/", 1)[-1]
    if KNOWN_LIBRARY_RE.search(name):
        return True
    if MIN_SUFFIX_RE.search(name):
        return True
    if VENDOR_DIR_RE.search(rel_path):
        return True
    if LICENSE_BANNER_RE.search(text[:300]) and looks_minified(text):
        return True
    return looks_minified(text)
