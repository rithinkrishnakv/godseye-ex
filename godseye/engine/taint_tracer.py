"""
engine/taint_tracer.py

Heuristic source-to-sink taint analysis.

A real zero-day = untrusted data (SOURCE) flows into a dangerous function
(SINK) without a sanitizer in between. This module operates on the
resolved handler blocks produced by the tokenizer (span.block.text) and
performs intra-block taint propagation.

Algorithm (intra-block, single file):
  1. Identify SOURCE expressions in the block text (message payloads,
     URL params, storage reads, postMessage event.data, etc.)
  2. Extract the likely variable names holding that tainted data
  3. Check whether any SINK expression in the same block uses one of
     those variable names
  4. Check whether any SANITIZER pattern appears between the source and
     sink (DOMPurify, textContent assignment, encodeURIComponent, etc.)
  5. If source variable reaches sink WITHOUT a sanitizer between them,
     emit a TaintFlow finding

Limitations (intentional and documented):
  - Intra-block only: cross-function, cross-file flows are handled by
    the Context Bridge Matrix, not here.
  - No variable renaming/SSA: if the tainted value is assigned to a new
    name before the sink, we won't catch it unless the new name also
    looks suspicious.
  - No path sensitivity: we assume any path that contains both source and
    sink is reachable (conservative / may produce false positives).
  - Template literal interpolation: `<div>${msg.data}</div>` IS detected
    because msg.data appears in the block text as a source variable.
"""

from __future__ import annotations
import re
from dataclasses import dataclass

from .logging_config import get_logger

log = get_logger("taint")

# ── Source patterns ───────────────────────────────────────────────────────────

SOURCES: list[tuple[str, re.Pattern]] = [
    ("MSG_PAYLOAD",   re.compile(r"\b(msg|message|request|req|payload|data)\b\s*\.\s*([A-Za-z_$]\w*)")),
    ("MSG_DATA",      re.compile(r"\bevent\s*\.\s*data\b")),
    ("URL_PARAM",     re.compile(r"\blocation\s*\.\s*(search|hash|href|pathname)\b")),
    ("URL_SEARCH",    re.compile(r"URLSearchParams|getParameter|searchParams\.get")),
    ("STORAGE_READ",  re.compile(r"chrome\.storage\.[a-z]+\.get\s*\(")),
    ("LOCALSTORAGE",  re.compile(r"localStorage\.getItem\s*\(")),
    ("COOKIE_READ",   re.compile(r"document\.cookie")),
    ("INTENT_DATA",   re.compile(r"getStringExtra|getData\(\)")),
    ("XHR_RESPONSE",  re.compile(r"\.responseText\b|\.responseXML\b")),
    ("FETCH_RESPONSE", re.compile(r"\.text\(\)|\.json\(\)|response\.body")),
]

# ── Sink patterns (keyed to the rule_id they would escalate) ─────────────────

SINKS: list[tuple[str, str, re.Pattern]] = [
    # (rule_id_base, human_label, pattern)
    ("TAINT-DOM-XSS",          "innerHTML/outerHTML sink",
     re.compile(r"\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\s*\(")),
    ("TAINT-EVAL-SINK",        "eval()/Function() dynamic execution sink",
     re.compile(r"\beval\s*\(|new\s+Function\s*\(")),
    ("TAINT-EXEC-SCRIPT-SINK", "executeScript injection sink",
     re.compile(r"chrome\.scripting\.executeScript\s*\(|chrome\.tabs\.executeScript\s*\(")),
    ("TAINT-DOCUMENT-WRITE",   "document.write() sink",
     re.compile(r"document\.write(ln)?\s*\(")),
    ("TAINT-SCRIPT-SRC",       "dynamic script src assignment",
     re.compile(r"\.src\s*=\s*[^=]")),
    ("TAINT-OPEN-REDIRECT",    "window.location assignment (open redirect)",
     re.compile(r"(?:window\s*\.\s*)?location\s*(?:\.href|\.replace)?\s*=\s*[^=]")),
    ("TAINT-NATIVE-MSG",       "native message relay",
     re.compile(r"chrome\.runtime\.(connectNative|sendNativeMessage)\s*\(")),
]

# ── Sanitizer patterns ────────────────────────────────────────────────────────

SANITIZERS: list[re.Pattern] = [
    re.compile(r"\bDOMPurify\s*\.\s*(sanitize|clean)\b"),
    re.compile(r"\btextContent\s*="),
    re.compile(r"\bencodeURIComponent\b"),
    re.compile(r"\bescapeHTML\b|\bescapeXML\b|\bhtmlEscape\b"),
    re.compile(r"\bvalidat(e|ion)\b"),
    re.compile(r"\bsanitiz(e|ation)\b"),
    re.compile(r"AllowedTags|allowedAttributes|ALLOWED_"),
    re.compile(r"\bjsonSchema\b|\bAjv\b|\byup\b|\bzod\b"),
]


@dataclass
class TaintFlow:
    rule_id: str
    source_type: str
    sink_label: str
    file: str
    source_line: int
    sink_line: int
    sanitized: bool
    source_snippet: str
    sink_snippet: str
    block_text: str


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _extract_tainted_vars(block: str, source_pattern: re.Pattern) -> set[str]:
    """
    Pull variable names that are likely assigned from source expressions.
    Handles:  const x = msg.data;   let html = event.data;
    """
    vars_: set[str] = set()
    assign = re.compile(
        r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*[^;\n]*"""
    )
    for m in assign.finditer(block):
        rhs_start = m.start() + m.group(0).index("=") + 1
        rhs = m.group(0)[m.group(0).index("=") + 1:].strip()
        if source_pattern.search(rhs):
            vars_.add(m.group(1))

    # Also add implicit references: any param matching common taint names
    for m in re.finditer(r"\b(msg|message|request|req|payload|event|data)\b", block):
        vars_.add(m.group(1))

    return vars_


def _sanitizer_between(block: str, source_end: int, sink_start: int) -> bool:
    segment = block[source_end:sink_start]
    return any(p.search(segment) for p in SANITIZERS)


def trace_block(
    block_text: str,
    file: str,
    block_start_line: int,
) -> list[TaintFlow]:
    flows: list[TaintFlow] = []
    if not block_text:
        return flows

    for source_type, source_pattern in SOURCES:
        source_match = source_pattern.search(block_text)
        if not source_match:
            continue

        tainted_vars = _extract_tainted_vars(block_text, source_pattern)

        for rule_id, sink_label, sink_pattern in SINKS:
            for sink_match in sink_pattern.finditer(block_text):
                # Check whether any tainted variable appears near the sink
                sink_context = block_text[max(0, sink_match.start() - 80):sink_match.end() + 80]
                var_reaches_sink = (
                    any(re.search(r"\b" + re.escape(v) + r"\b", sink_context) for v in tainted_vars)
                    or source_pattern.search(sink_context)
                )
                if not var_reaches_sink:
                    continue

                sanitized = _sanitizer_between(
                    block_text,
                    source_match.end(),
                    sink_match.start(),
                )
                flows.append(TaintFlow(
                    rule_id=rule_id + ("-SANITIZED" if sanitized else ""),
                    source_type=source_type,
                    sink_label=sink_label,
                    file=file,
                    source_line=block_start_line + _line_of(block_text, source_match.start()) - 1,
                    sink_line=block_start_line + _line_of(block_text, sink_match.start()) - 1,
                    sanitized=sanitized,
                    source_snippet=block_text[source_match.start():source_match.end() + 40].strip(),
                    sink_snippet=block_text[sink_match.start():sink_match.end() + 40].strip(),
                    block_text=block_text,
                ))

    return flows
