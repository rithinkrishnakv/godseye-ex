"""
modules/injection_module.py

[ACTIVE] Injection Sight
Covers E3 - Content Script Injection / DOM-based XSS.

Patterns are registered as RULE_SPECS and tokenized once by the shared
loader; this module only reads pre-computed matches from ctx.index.
"""

from __future__ import annotations
import re

from ..models import Finding, CVSSVector, SkillType, Verification
from ..engine.base_module import BaseModule
from ..engine.loader import AnalysisContext
from ..engine.tokenizer import RuleSpec, FileScope
from ..engine.snippet import extract_snippet

_RULE_META = {
    "INJ-INNERHTML": ("Direct innerHTML assignment", "Assigning to innerHTML with unsanitized input can lead to DOM-based XSS inside the extension's privileged context (content script or extension page)."),
    "INJ-OUTERHTML": ("Direct outerHTML assignment", "Same risk class as innerHTML -- replaces the element with parsed HTML."),
    "INJ-INSERT-ADJACENT-HTML": ("insertAdjacentHTML call", "Parses and inserts raw HTML at the given position; unsanitized input here is a DOM XSS sink."),
    "INJ-DOCUMENT-WRITE": ("document.write/writeln call", "Writes raw HTML/script into the current document; a classic XSS sink and also blocks rendering."),
    "INJ-DANGEROUSLY-SET-INNER-HTML": ("React dangerouslySetInnerHTML", "Bypasses React's normal escaping; unsanitized input here is a DOM XSS sink."),
}

_PATTERNS = {
    "INJ-INNERHTML": re.compile(r"\.innerHTML\s*="),
    "INJ-OUTERHTML": re.compile(r"\.outerHTML\s*="),
    "INJ-INSERT-ADJACENT-HTML": re.compile(r"\.insertAdjacentHTML\s*\("),
    "INJ-DOCUMENT-WRITE": re.compile(r"document\.write(ln)?\s*\("),
    "INJ-DANGEROUSLY-SET-INNER-HTML": re.compile(r"dangerouslySetInnerHTML"),
}

# Each rule applies to both JS and HTML files -- register once per scope so a
# single rule_id still aggregates matches from both file types in the index.
RULE_SPECS: list[RuleSpec] = [
    RuleSpec(rule_id, pattern, scope=scope)
    for rule_id, pattern in _PATTERNS.items()
    for scope in (FileScope.JS_NONVENDOR, FileScope.HTML)
]


class InjectionSightModule(BaseModule):
    SKILL_NAME = "Injection Sight"
    SKILL_TYPE = SkillType.ACTIVE
    CATEGORY = "E3"
    DESCRIPTION = "DOM-based injection sinks in content scripts and extension pages"
    RULE_SPECS = RULE_SPECS

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        self._findings = []
        for rule_id, (title, detail) in _RULE_META.items():
            for span in ctx.index.get(rule_id):
                text = ctx.index.file_text(span.file)
                self._add(Finding(
                    id=rule_id,
                    title=title,
                    category="E3",
                    skill_name=self.SKILL_NAME,
                    skill_type=self.SKILL_TYPE,
                    description=title + " found in extension source.",
                    technical_detail=detail,
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="L", A="N"),
                    evidence=[span.snippet],
                    file=span.file, line=span.line,
                    context=extract_snippet(text, span.line),
                    remediation="Use textContent for plain text, or run untrusted HTML through a sanitizer (e.g. DOMPurify) before insertion.",
                    verification=Verification(
                        title="Trace the data source",
                        steps=[f"Open {span.file} at line {span.line}.",
                               "Trace the value being assigned back to its source -- if it ever includes page content, a URL parameter, or a cross-context message payload, treat this as a confirmed sink."],
                    ),
                ))
        return self._findings
