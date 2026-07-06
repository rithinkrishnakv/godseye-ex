"""
engine/snippet.py

Extracts a few lines of source around a finding so a reviewer can see the
problem immediately instead of just a line number. Pure text slicing --
no execution. For credential-shaped findings, the matched secret itself
is masked within the snippet so the report never reproduces the actual
value, only its location.
"""

from __future__ import annotations


def extract_snippet(text: str, line_no: int, before: int = 2, after: int = 2) -> list[tuple[int, str]]:
    lines = text.splitlines()
    if not lines:
        return []
    start = max(line_no - 1 - before, 0)
    end = min(line_no - 1 + after + 1, len(lines))
    return [(i + 1, lines[i]) for i in range(start, end)]


def extract_masked_snippet(
    text: str, line_no: int, sensitive_substr: str, before: int = 2, after: int = 2
) -> list[tuple[int, str]]:
    snippet = extract_snippet(text, line_no, before, after)
    if not sensitive_substr:
        return snippet
    mask = "*" * min(len(sensitive_substr), 24)
    return [
        (ln, content.replace(sensitive_substr, mask) if ln == line_no else content)
        for ln, content in snippet
    ]
