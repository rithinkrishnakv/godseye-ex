"""
engine/tokenizer.py

The shared indexing layer every module reads from. Built exactly once per
scan, at context-construction time -- modules never re-read or re-regex
raw source text themselves after this runs.

Two things live here:

1. MATCH INDEXING -- every rule's regex is run against every applicable
   file exactly once, centrally, and the resulting MatchSpans are stored
   keyed by rule_id. Modules ask `ctx.index.get(rule_id)` instead of each
   independently looping over files and calling `pattern.finditer()`.

2. BLOCK RESOLUTION -- for "anchor" rules (listener registrations like
   onMessage.addListener, postMessage handlers, etc.), this module finds
   the actual enclosing function body using a string/comment-aware brace
   scanner, rather than a fixed character-count window. A fixed window
   (e.g. "look 400 characters ahead for a sender check") can both miss a
   check that's legitimately further away AND falsely match an unrelated
   check that happens to sit in a different, nearby function -- that's
   the "token collision" failure mode this replaces.

IMPORTANT SCOPE NOTE: this is a lexer-with-boundary-resolution, not an
AST parser. It tracks strings, template literals, and comments well
enough to find matching braces reliably, but it does no semantic
analysis, no variable binding, no type information, and does not attempt
to distinguish regex literals from division (a famously ambiguous case
without a real parser) -- regex literals are simply not modeled. Treat
block resolution as "best-effort structural boundary finding," not proof
of program structure.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from enum import Enum

from .logging_config import get_logger

log = get_logger("tokenizer")

MAX_BLOCK_LOOKAHEAD = 4000   # how far past an anchor match we'll search for a body to resolve
MAX_BLOCK_SCAN = 30000       # hard cap on brace-matching scan length, protects against pathological input
MAX_OBJECT_LOOKAHEAD = 400   # object-literal arguments are short; no need for the larger function-body window

_ARROW_OR_FUNCTION_RE = re.compile(r"=>|function\b")


class FileScope(str, Enum):
    JS_NONVENDOR = "js_nonvendor"   # ctx.js_files() -- vendor/minified excluded (the common case)
    JS_ALL = "js_all"               # ctx.all_js_files() -- vendor included (e.g. supply-chain fingerprinting)
    HTML = "html"                   # ctx.html_files()


class Resolution(str, Enum):
    NONE = "none"                    # just record the match
    BLOCK = "block"                  # resolve the enclosing function/arrow body (listener registrations)
    OBJECT_LITERAL = "object_literal"  # resolve the next balanced {...} argument (e.g. storage.set({...}))


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    pattern: re.Pattern
    scope: FileScope = FileScope.JS_NONVENDOR
    resolution: Resolution = Resolution.NONE


@dataclass
class Block:
    file: str
    start_line: int
    end_line: int
    text: str


@dataclass
class MatchSpan:
    rule_id: str
    file: str
    line: int
    start: int
    end: int
    snippet: str
    groups: tuple[str | None, ...] = ()
    block: Block | None = None


@dataclass
class FileIndex:
    rel_path: str
    text: str
    spans_by_rule: dict[str, list[MatchSpan]] = field(default_factory=dict)


@dataclass
class SourceIndex:
    files: dict[str, FileIndex] = field(default_factory=dict)
    _by_rule: dict[str, list[MatchSpan]] = field(default_factory=dict, init=False)

    def register(self, span: MatchSpan) -> None:
        self._by_rule.setdefault(span.rule_id, []).append(span)
        self.files[span.file].spans_by_rule.setdefault(span.rule_id, []).append(span)

    def get(self, rule_id: str) -> list[MatchSpan]:
        return self._by_rule.get(rule_id, [])

    def any(self, rule_id: str) -> bool:
        return bool(self._by_rule.get(rule_id))

    def get_in_file(self, rule_id: str, rel_path: str) -> list[MatchSpan]:
        fi = self.files.get(rel_path)
        return fi.spans_by_rule.get(rule_id, []) if fi else []

    def file_text(self, rel_path: str) -> str:
        fi = self.files.get(rel_path)
        return fi.text if fi else ""


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _skip_balanced_parens(text: str, open_idx: int, limit: int) -> int | None:
    """text[open_idx] must be '('. Returns index AFTER the matching ')', or None."""
    depth = 0
    i = open_idx
    end = min(len(text), open_idx + limit)
    in_str: str | None = None
    while i < end:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ("'", '"', "`"):
            in_str = c
            i += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def _scan_matching_brace(text: str, open_idx: int, limit: int) -> int | None:
    """text[open_idx] must be '{'. String/template/comment-aware. Returns index of matching '}', or None."""
    depth = 0
    i = open_idx
    end = min(len(text), open_idx + limit)
    # state stack entries: "normal" | "'" | '"' | "`" | "//" | "/*" | "${"
    # hole_depths runs parallel to state for "${" entries: the depth value
    # *before* that hole's own opening brace was counted, so we know exactly
    # when a '}' closes the hole itself vs. something nested inside it.
    state: list[str] = ["normal"]
    hole_depths: list[int] = []

    while i < end:
        c = text[i]
        top = state[-1]

        if top == "//":
            if c == "\n":
                state.pop()
            i += 1
            continue
        if top == "/*":
            if c == "*" and i + 1 < end and text[i + 1] == "/":
                state.pop()
                i += 2
                continue
            i += 1
            continue
        if top in ("'", '"'):
            if c == "\\":
                i += 2
                continue
            if c == top:
                state.pop()
            i += 1
            continue
        if top == "`":
            if c == "\\":
                i += 2
                continue
            if c == "`":
                state.pop()
                i += 1
                continue
            if c == "$" and i + 1 < end and text[i + 1] == "{":
                hole_depths.append(depth)
                state.append("${")
                depth += 1
                i += 2
                continue
            i += 1
            continue

        # top == "normal" or "${": looking for comments/strings/braces
        if c == "/" and i + 1 < end and text[i + 1] == "/":
            state.append("//")
            i += 2
            continue
        if c == "/" and i + 1 < end and text[i + 1] == "*":
            state.append("/*")
            i += 2
            continue
        if c == "'" or c == '"':
            state.append(c)
            i += 1
            continue
        if c == "`":
            state.append("`")
            i += 1
            continue
        if c == "{":
            depth += 1
            i += 1
            continue
        if c == "}":
            depth -= 1
            if top == "${" and depth == hole_depths[-1]:
                # this '}' closes the ${ hole itself -- pop back into the template
                state.pop()
                hole_depths.pop()
                i += 1
                continue
            if top == "normal" and depth == 0:
                return i
            i += 1
            continue
        i += 1

    return None


def resolve_block(text: str, anchor_end: int) -> Block | None:
    """Best-effort: find the enclosing function/arrow body starting after `anchor_end`."""
    try:
        window_end = min(len(text), anchor_end + MAX_BLOCK_LOOKAHEAD)
        m = _ARROW_OR_FUNCTION_RE.search(text, anchor_end, window_end)
        if not m:
            return None

        if m.group(0) == "=>":
            search_from = m.end()
        else:
            paren_idx = text.find("(", m.end())
            if paren_idx == -1 or paren_idx > window_end:
                return None
            after_params = _skip_balanced_parens(text, paren_idx, MAX_BLOCK_SCAN)
            if after_params is None:
                return None
            search_from = after_params

        # skip whitespace to find the body opener
        j = search_from
        while j < len(text) and text[j] in " \t\r\n":
            j += 1
        if j >= len(text) or text[j] != "{":
            return None  # concise arrow body (no block) -- nothing to resolve

        close_idx = _scan_matching_brace(text, j, MAX_BLOCK_SCAN)
        if close_idx is None:
            return None

        return Block(
            file="",  # filled in by caller
            start_line=_line_of(text, j),
            end_line=_line_of(text, close_idx),
            text=text[j:close_idx + 1],
        )
    except Exception:
        log.debug("resolve_block failed defensively", exc_info=True)
        return None


def resolve_object_literal(text: str, anchor_end: int) -> Block | None:
    """
    Best-effort: find the next balanced {...} starting shortly after `anchor_end`.
    Used for call arguments like chrome.storage.local.set({...}) where the old
    approach (`[^}]{0,300}`) would silently truncate at the FIRST '}' -- which is
    wrong the moment the stored object contains any nested object, array, or
    template literal of its own. This reuses the same string/comment-aware brace
    scanner as resolve_block, so nesting inside the literal is handled correctly.
    """
    try:
        window_end = min(len(text), anchor_end + MAX_OBJECT_LOOKAHEAD)
        j = anchor_end
        while j < window_end and text[j] in " \t\r\n(":
            j += 1
        if j >= window_end or text[j] != "{":
            return None
        close_idx = _scan_matching_brace(text, j, MAX_BLOCK_SCAN)
        if close_idx is None:
            return None
        return Block(
            file="",
            start_line=_line_of(text, j),
            end_line=_line_of(text, close_idx),
            text=text[j:close_idx + 1],
        )
    except Exception:
        log.debug("resolve_object_literal failed defensively", exc_info=True)
        return None


def build_file_index(rel_path: str, text: str, rules: list[RuleSpec]) -> FileIndex:
    fi = FileIndex(rel_path=rel_path, text=text)
    for rule in rules:
        for m in rule.pattern.finditer(text):
            block = None
            if rule.resolution == Resolution.BLOCK:
                block = resolve_block(text, m.end())
            elif rule.resolution == Resolution.OBJECT_LITERAL:
                block = resolve_object_literal(text, m.end())
            if block is not None:
                block.file = rel_path
            span = MatchSpan(
                rule_id=rule.rule_id,
                file=rel_path,
                line=_line_of(text, m.start()),
                start=m.start(),
                end=m.end(),
                snippet=text[m.start():m.start() + 80].strip(),
                groups=m.groups(),
                block=block,
            )
            fi.spans_by_rule.setdefault(rule.rule_id, []).append(span)
    return fi


def build_index(file_texts: dict[str, str], rules: list[RuleSpec]) -> SourceIndex:
    """Single-scope convenience entrypoint -- mainly used by tests."""
    index = SourceIndex()
    for rel_path, text in file_texts.items():
        fi = build_file_index(rel_path, text, rules)
        index.files[rel_path] = fi
        for rule_id, spans in fi.spans_by_rule.items():
            index._by_rule.setdefault(rule_id, []).extend(spans)
    return index


def build_scoped_index(scope_files: dict[FileScope, list], rule_specs: list[RuleSpec]) -> SourceIndex:
    """
    Real entrypoint used by the loader. `scope_files` maps each FileScope to the
    list of SourceFile objects that scope covers (already vendor-filtered as
    appropriate by the caller). Guarantees every file is tokenized exactly once
    in total -- if a file qualifies under more than one scope's file list, the
    union of applicable rules is still evaluated in a single pass over that
    file's text, not once per scope.
    """
    file_objs: dict[str, object] = {}
    rules_for_file: dict[str, list[RuleSpec]] = {}

    for scope, files in scope_files.items():
        applicable = [r for r in rule_specs if r.scope == scope]
        if not applicable:
            continue
        for f in files:
            file_objs[f.rel_path] = f
            rules_for_file.setdefault(f.rel_path, [])
            rules_for_file[f.rel_path].extend(applicable)

    index = SourceIndex()
    for rel_path, rules in rules_for_file.items():
        text = file_objs[rel_path].text
        try:
            fi = build_file_index(rel_path, text, rules)
        except Exception:
            log.warning("tokenization failed for %s -- treating as zero matches", rel_path, exc_info=True)
            fi = FileIndex(rel_path=rel_path, text=text)
        index.files[rel_path] = fi
        for rule_id, spans in fi.spans_by_rule.items():
            index._by_rule.setdefault(rule_id, []).extend(spans)
    return index
