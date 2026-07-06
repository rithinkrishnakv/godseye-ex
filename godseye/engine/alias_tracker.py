"""
engine/alias_tracker.py

Lexical alias resolution for dangerous function references.

Catches patterns like:
    const safeLog = eval;
    var exec = chrome.scripting.executeScript;
    let fn = new Function;
    const runCode = window.eval;

After building an alias map for a file, the module checks whether any of
those aliases are *called* in the same file. If so, it generates synthetic
MatchSpans with the original dangerous rule_id but pointing at the alias
call site -- so the finding surfaces at the right line with the right rule.

Scope caveat: this is file-level, not function-level. We don't track
variable shadowing across nested scopes (that would require a real AST).
We use a conservative approach: if an alias to a dangerous function exists
anywhere in the file AND is called anywhere in the file, flag it. This
will occasionally produce false positives in large files where a variable
name is reused, but will never miss an alias assignment that is actually
called in the same file.
"""

from __future__ import annotations
import re
from dataclasses import dataclass

from .tokenizer import MatchSpan

# Dangerous targets we track aliases to.
# Maps canonical rule_id → regex that matches the dangerous reference itself.
DANGEROUS_REFS: dict[str, re.Pattern] = {
    "DYN-EVAL": re.compile(r"\beval\b"),
    "DYN-NEW-FUNCTION": re.compile(r"\bnew\s+Function\b"),
    "DYN-EXECUTE-SCRIPT": re.compile(r"chrome\.scripting\.executeScript\b"),
    "DYN-TABS-EXECUTE-SCRIPT": re.compile(r"chrome\.tabs\.executeScript\b"),
    "NATIVE-CONNECT-CALL": re.compile(r"chrome\.runtime\.(connectNative|sendNativeMessage)\b"),
    "CTX-WINDOW-EVAL": re.compile(r"window\.eval\b"),
}

# Pattern for  const/let/var  <identifier>  =  <rhs up to ; or newline>
_ASSIGN_RE = re.compile(
    r"""(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([^\n;]{3,80})"""
)

# Identifier call site: <identifier>(
_CALL_RE = re.compile(r"""\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(""")


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def build_alias_spans(rel_path: str, text: str) -> list[MatchSpan]:
    """
    Return synthetic MatchSpans for aliased dangerous function calls.
    """
    result: list[MatchSpan] = []
    alias_to_rule: dict[str, str] = {}

    for m in _ASSIGN_RE.finditer(text):
        var_name = m.group(1)
        rhs = m.group(2).strip().rstrip(";").strip()
        for rule_id, ref_pattern in DANGEROUS_REFS.items():
            if ref_pattern.search(rhs):
                alias_to_rule[var_name] = rule_id

    if not alias_to_rule:
        return []

    for m in _CALL_RE.finditer(text):
        callee = m.group(1)
        if callee not in alias_to_rule:
            continue
        rule_id = alias_to_rule[callee]
        line_no = _line_of(text, m.start())
        result.append(MatchSpan(
            rule_id=f"{rule_id}-ALIAS",
            file=rel_path,
            line=line_no,
            start=m.start(),
            end=m.end(),
            snippet=f"[alias call] {text[m.start():m.start()+80].strip()}",
            groups=(callee,),
            block=None,
        ))

    return result
