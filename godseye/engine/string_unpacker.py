"""
engine/string_unpacker.py

Pre-processor that expands common string obfuscation techniques in JS
source BEFORE the tokenizer runs. Produces a "shadow" text used only
for pattern matching -- the original is kept for display/snippets.

Handles:
  1. Hex / unicode / octal escape sequences inside string literals
     '\x65\x76\x61\x6c' → 'eval'
     '\u0065\u0076\u0061\u006c' → 'eval'

  2. String literal concatenation (single-pass, handles nesting)
     'chr' + 'ome' → 'chrome'
     "ex" + "ec" + "Script" → "execScript"

  3. Bracket-notation property access reconstruction
     window['eval'] → window.eval
     chrome['tabs']['executeScript'] → chrome.tabs.executeScript
     obj['chr'+'ome'] → obj['chrome'] → obj.chrome  (combined with #2)

  4. Array-index string join patterns
     ['\x65\x76\x61\x6c'].join('') → 'eval'

This is deliberately NOT a full constant-folding engine -- it handles the
top-5 obfuscation patterns seen in real malicious extensions and does NOT
attempt to evaluate arbitrary JS expressions. Correctness is bounded by
that scope: it will not confuse or crash on code it can't understand, it
will simply leave that text unchanged.
"""

from __future__ import annotations
import re

# ── 1. Escape sequence decoding ──────────────────────────────────────────────

_HEX_ESC = re.compile(r"\\x([0-9a-fA-F]{2})")
_UNI_ESC = re.compile(r"\\u([0-9a-fA-F]{4})")
_UNI_ESC6 = re.compile(r"\\u\{([0-9a-fA-F]{1,6})\}")
_OCT_ESC = re.compile(r"\\([0-7]{1,3})")


def _decode_escapes(s: str) -> str:
    s = _HEX_ESC.sub(lambda m: chr(int(m.group(1), 16)), s)
    s = _UNI_ESC6.sub(lambda m: chr(int(m.group(1), 16)), s)
    s = _UNI_ESC.sub(lambda m: chr(int(m.group(1), 16)), s)
    s = _OCT_ESC.sub(lambda m: chr(int(m.group(1), 8) & 0xFF), s)
    return s


# ── 2. String literal extraction helpers ─────────────────────────────────────

def _extract_string_value(text: str, start: int) -> tuple[str, int] | None:
    """
    Given text[start] is a quote char (' " `), return (content, end_idx)
    where content is the decoded string value and end_idx is the index
    AFTER the closing quote. Returns None on parse failure.
    Template literals with ${} holes are skipped entirely.
    """
    q = text[start]
    if q not in ("'", '"', "`"):
        return None
    i = start + 1
    chars: list[str] = []
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt in ("'", '"', "`", "\\", "/", "n", "r", "t", "b", "f", "v", "0"):
                chars.append({"n": "\n", "r": "\r", "t": "\t", "b": "\b",
                               "f": "\f", "v": "\v", "0": "\0"}.get(nxt, nxt))
                i += 2
            elif nxt == "x" and i + 3 < len(text):
                try:
                    chars.append(chr(int(text[i + 2:i + 4], 16)))
                    i += 4
                except ValueError:
                    chars.append(text[i]); i += 1
            elif nxt == "u":
                if i + 2 < len(text) and text[i + 2] == "{":
                    end = text.find("}", i + 3)
                    if end != -1:
                        try:
                            chars.append(chr(int(text[i + 3:end], 16)))
                            i = end + 1; continue
                        except (ValueError, OverflowError):
                            pass
                elif i + 5 < len(text):
                    try:
                        chars.append(chr(int(text[i + 2:i + 6], 16)))
                        i += 6; continue
                    except ValueError:
                        pass
                chars.append(text[i]); i += 1
            else:
                chars.append(c); i += 1
        elif c == q:
            return "".join(chars), i + 1
        elif c == "$" and q == "`" and i + 1 < len(text) and text[i + 1] == "{":
            return None  # template literal with hole -- skip
        else:
            chars.append(c)
            i += 1
    return None


# ── 3. String concatenation flattener ────────────────────────────────────────

_CONCAT_RE = re.compile(
    r"""(?P<q1>['"`])(?P<s1>(?:[^'"`\\]|\\.)*)(?P=q1)\s*\+\s*(?P<q2>['"`])(?P<s2>(?:[^'"`\\]|\\.)*)(?P=q2)"""
)


def _flatten_concat(text: str, max_passes: int = 8) -> str:
    """
    Repeatedly collapses adjacent string literal + string literal → merged literal.
    Stops when no more matches or max_passes reached.
    """
    for _ in range(max_passes):
        new = _CONCAT_RE.sub(lambda m: f'"{m.group("s1")}{m.group("s2")}"', text)
        if new == text:
            break
        text = new
    return text


# ── 4. Bracket-notation property reconstruction ───────────────────────────────

# Matches obj['key'] or obj["key"] and replaces with obj.key (safe identifiers)
_BRACKET_STR_RE = re.compile(r"""\[(['"])([A-Za-z_$][A-Za-z0-9_$]*)\1\]""")


def _expand_bracket_access(text: str) -> str:
    return _BRACKET_STR_RE.sub(lambda m: f".{m.group(2)}", text)


# ── 5. Array join pattern ─────────────────────────────────────────────────────

# ['chr','ome'].join('') → 'chrome' (simple cases only)
_ARRAY_JOIN_RE = re.compile(
    r"""\[(?:\s*(['"])[^'"]+\1\s*,?\s*)+\]\s*\.\s*join\s*\(\s*['"]?\s*['"]?\s*\)"""
)


def _expand_array_join(text: str) -> str:
    def _repl(m: re.Match) -> str:
        inner = m.group(0)
        parts = re.findall(r"""['"]([^'"]+)['"]""", inner.split(".join")[0])
        return f'"{" ".join(parts)}"' if parts else m.group(0)
    return _ARRAY_JOIN_RE.sub(_repl, text)


# ── Public API ────────────────────────────────────────────────────────────────

def unpack(text: str) -> str:
    """
    Return a normalized shadow of `text` with common obfuscation expanded.
    Safe to call on any JS text -- failures leave the affected substring unchanged.
    Designed to be fast enough to run on every file in a pre-indexing pass.
    """
    try:
        text = _flatten_concat(text)
        text = _expand_array_join(text)
        text = _expand_bracket_access(text)
        text = _decode_escapes(text)
        return text
    except Exception:
        return text  # never crash the pipeline; return input unchanged
