"""
engine/context_bridge.py

Cross-Context Message Bridge Matrix.

Extension zero-days almost always involve multi-hop privilege escalation:
  malicious page → content script (via postMessage)
  → background script (via chrome.runtime.sendMessage)
  → native host / executeScript / storage (privileged action)

This module builds a graph of:
  - Which files are in which context (content, background, popup, devtools)
  - Where sendMessage / postMessage calls originate
  - Where onMessage handlers respond
  - What privileged actions (sinks) those handlers perform

Then it identifies complete escalation paths: an attack chain that starts
from an untrusted source (web page → content script) and ends at a
privileged sink (native message, executeScript, cookie access).

Output: a list of BridgeViolation objects that become findings.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field

from .logging_config import get_logger

log = get_logger("context_bridge")

# ── Context classification ────────────────────────────────────────────────────

class FileContext:
    CONTENT = "content_script"
    BACKGROUND = "background"
    POPUP = "popup"
    DEVTOOLS = "devtools"
    OPTIONS = "options"
    UNKNOWN = "unknown"


def classify_files(manifest: dict, all_files: list) -> dict[str, str]:
    """Return {rel_path: FileContext} for every source file."""
    ctx: dict[str, str] = {}
    all_paths = {f.rel_path for f in all_files}

    # Content scripts
    for cs in manifest.get("content_scripts", []) or []:
        for js in cs.get("js", []) or []:
            ctx[js] = FileContext.CONTENT

    # Background
    bg = manifest.get("background", {}) or {}
    for key in ("service_worker", "scripts", "page"):
        val = bg.get(key)
        if isinstance(val, str):
            ctx[val] = FileContext.BACKGROUND
        elif isinstance(val, list):
            for v in val:
                ctx[v] = FileContext.BACKGROUND

    # Popup / action
    for action_key in ("action", "browser_action", "page_action"):
        popup = (manifest.get(action_key) or {}).get("default_popup")
        if popup:
            ctx[popup] = FileContext.POPUP

    # Devtools
    devtools = manifest.get("devtools_page")
    if devtools:
        ctx[devtools] = FileContext.DEVTOOLS

    # Options
    for opt_key in ("options_page", "options_ui"):
        page = manifest.get(opt_key)
        if isinstance(page, str):
            ctx[page] = FileContext.OPTIONS
        elif isinstance(page, dict):
            p = page.get("page")
            if p:
                ctx[p] = FileContext.OPTIONS

    # Everything else
    for p in all_paths:
        if p not in ctx:
            ctx[p] = FileContext.UNKNOWN

    return ctx


# ── Message send / receive patterns ──────────────────────────────────────────

SENDS: list[tuple[str, re.Pattern]] = [
    ("runtime.sendMessage",  re.compile(r"chrome\.runtime\.sendMessage\s*\(")),
    ("tabs.sendMessage",     re.compile(r"chrome\.tabs\.sendMessage\s*\(")),
    ("port.postMessage",     re.compile(r"\.postMessage\s*\(")),
    ("window.postMessage",   re.compile(r"window\.postMessage\s*\(")),
]

RECEIVES: list[tuple[str, re.Pattern]] = [
    ("onMessage",         re.compile(r"chrome\.runtime\.onMessage\.addListener")),
    ("onMessageExternal", re.compile(r"chrome\.runtime\.onMessageExternal\.addListener")),
    ("postMessage",       re.compile(r"addEventListener\s*\(\s*['\"]message['\"]")),
    ("port.onMessage",    re.compile(r"\.onMessage\.addListener")),
]

PRIVILEGED_SINKS: list[tuple[str, re.Pattern]] = [
    ("executeScript",     re.compile(r"chrome\.scripting\.executeScript\s*\(")),
    ("tabs.executeScript",re.compile(r"chrome\.tabs\.executeScript\s*\(")),
    ("nativeMessage",     re.compile(r"chrome\.runtime\.(connectNative|sendNativeMessage)\s*\(")),
    ("cookies.getAll",    re.compile(r"chrome\.cookies\.(get|getAll)\s*\(")),
    ("downloads",         re.compile(r"chrome\.downloads\.download\s*\(")),
    ("proxy.set",         re.compile(r"chrome\.proxy\.settings\.set\s*\(")),
    ("eval",              re.compile(r"\beval\s*\(")),
    ("innerHTML",         re.compile(r"\.innerHTML\s*=")),
    ("webRequest.hook",   re.compile(r"chrome\.webRequest\.on\w+\.addListener")),
]


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


# ── Bridge violation dataclass ────────────────────────────────────────────────

@dataclass
class BridgeViolation:
    chain_id: str
    description: str
    technical_detail: str
    from_file: str
    from_ctx: str
    from_line: int
    from_pattern: str
    to_file: str
    to_ctx: str
    to_line: int
    to_pattern: str
    sink_file: str
    sink_label: str
    sink_line: int
    escalation_level: str  # "web→content", "content→background", "full-chain"


def analyze_bridge(
    file_contexts: dict[str, str],
    file_texts: dict[str, str],
) -> list[BridgeViolation]:
    """
    Identify cross-context privilege escalation paths.
    """
    violations: list[BridgeViolation] = []

    # Map each file's sends, receives, sinks
    sends_by_file: dict[str, list[tuple[str, int]]] = {}
    receives_by_file: dict[str, list[tuple[str, int]]] = {}
    sinks_by_file: dict[str, list[tuple[str, int]]] = {}

    for rel, text in file_texts.items():
        s_list = []
        for label, pattern in SENDS:
            for m in pattern.finditer(text):
                s_list.append((label, _line_of(text, m.start())))
        sends_by_file[rel] = s_list

        r_list = []
        for label, pattern in RECEIVES:
            for m in pattern.finditer(text):
                r_list.append((label, _line_of(text, m.start())))
        receives_by_file[rel] = r_list

        k_list = []
        for label, pattern in PRIVILEGED_SINKS:
            for m in pattern.finditer(text):
                k_list.append((label, _line_of(text, m.start())))
        sinks_by_file[rel] = k_list

    # Pattern 1: content script → background (sendMessage in content, handler in background with privileged sink)
    content_files = [f for f, c in file_contexts.items() if c == FileContext.CONTENT]
    bg_files = [f for f, c in file_contexts.items() if c == FileContext.BACKGROUND]

    for cf in content_files:
        sends = sends_by_file.get(cf, [])
        if not sends:
            continue
        for bgf in bg_files:
            receives = receives_by_file.get(bgf, [])
            sinks = sinks_by_file.get(bgf, [])
            if receives and sinks:
                send_label, send_line = sends[0]
                recv_label, recv_line = receives[0]
                sink_label, sink_line = sinks[0]
                violations.append(BridgeViolation(
                    chain_id=f"BRIDGE-CONTENT-TO-BG-{cf[:20]}-{bgf[:20]}",
                    description=(
                        f"Content script '{cf}' sends a message to background '{bgf}', "
                        f"which contains a privileged sink ({sink_label})."
                    ),
                    technical_detail=(
                        f"A malicious web page can trigger a postMessage/DOM event in the content "
                        f"script ({cf}:{send_line}), which relays a message to the background handler "
                        f"({bgf}:{recv_line}). If that handler doesn't validate sender.id AND passes "
                        f"any message data into '{sink_label}' ({bgf}:{sink_line}), the web page "
                        "achieves a full privilege escalation into a background-context privileged action."
                    ),
                    from_file=cf, from_ctx=FileContext.CONTENT,
                    from_line=send_line, from_pattern=send_label,
                    to_file=bgf, to_ctx=FileContext.BACKGROUND,
                    to_line=recv_line, to_pattern=recv_label,
                    sink_file=bgf, sink_label=sink_label, sink_line=sink_line,
                    escalation_level="content→background",
                ))

    # Pattern 2: unknown/popup → background with privileged sink
    for uf in [f for f, c in file_contexts.items() if c in (FileContext.POPUP, FileContext.UNKNOWN)]:
        sends = sends_by_file.get(uf, [])
        if not sends:
            continue
        for bgf in bg_files:
            receives = receives_by_file.get(bgf, [])
            sinks = sinks_by_file.get(bgf, [])
            if receives and sinks:
                send_label, send_line = sends[0]
                recv_label, recv_line = receives[0]
                sink_label, sink_line = sinks[0]
                violations.append(BridgeViolation(
                    chain_id=f"BRIDGE-POPUP-TO-BG-{uf[:20]}-{bgf[:20]}",
                    description=(
                        f"Popup/page '{uf}' sends a message to background '{bgf}', "
                        f"which contains a privileged sink ({sink_label})."
                    ),
                    technical_detail=(
                        f"If '{uf}' can be influenced by web content (e.g. it reads URL params or "
                        f"is itself vulnerable to XSS), an attacker can craft a flow from that page "
                        f"through the background handler ({bgf}:{recv_line}) into '{sink_label}' "
                        f"({bgf}:{sink_line})."
                    ),
                    from_file=uf, from_ctx=file_contexts.get(uf, "unknown"),
                    from_line=send_line, from_pattern=send_label,
                    to_file=bgf, to_ctx=FileContext.BACKGROUND,
                    to_line=recv_line, to_pattern=recv_label,
                    sink_file=bgf, sink_label=sink_label, sink_line=sink_line,
                    escalation_level="popup→background",
                ))

    # Deduplicate by chain_id
    seen: set[str] = set()
    unique: list[BridgeViolation] = []
    for v in violations:
        if v.chain_id not in seen:
            seen.add(v.chain_id)
            unique.append(v)

    return unique
