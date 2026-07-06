"""
modules/hardening_module.py

[ACTIVE] Hardening Sight
Covers E10 - Hardening & Defense-in-Depth Gaps.
Low-severity-by-design: these are debug leftovers and missing-defense
signals, not exploitable bugs on their own.
"""

from __future__ import annotations
import re

from ..models import Finding, CVSSVector, SkillType
from ..engine.base_module import BaseModule
from ..engine.loader import AnalysisContext
from ..engine.tokenizer import RuleSpec, FileScope
from ..engine.snippet import extract_snippet

RULE_SPECS: list[RuleSpec] = [
    RuleSpec("HARDEN-CONSOLE-LOG-SENSITIVE", re.compile(r"console\.(log|debug|info|warn)\s*\([^)]*(?i:password|secret|token|api[_-]?key|auth|session)[^)]*\)"), scope=FileScope.JS_NONVENDOR),
    RuleSpec("HARDEN-DEBUGGER-STATEMENT", re.compile(r"(?<![\w.])debugger\s*;"), scope=FileScope.JS_NONVENDOR),
    RuleSpec("HARDEN-SECURITY-TODO", re.compile(r"(?i)//\s*(TODO|FIXME).{0,80}(security|secur|vuln|password|auth|sanitiz)"), scope=FileScope.JS_NONVENDOR),
]

_META = {
    "HARDEN-CONSOLE-LOG-SENSITIVE": dict(
        title="console.log of a sensitive-looking value",
        description="A log statement references a variable named like a credential.",
        technical_detail="Anything logged to the console is visible to anyone with DevTools open on that page/extension, and may be picked up by crash/log-reporting tooling.",
        cvss=CVSSVector(AV="L", AC="H", PR="L", UI="N", S="U", C="L", I="N", A="N"),
        remediation="Remove debug logging of credential-shaped values before shipping.",
    ),
    "HARDEN-DEBUGGER-STATEMENT": dict(
        title="Leftover debugger statement",
        description="A `debugger;` statement was left in shipped code.",
        technical_detail="Harmless by itself, but a reliable signal that this file wasn't fully cleaned up before release -- worth a closer look at what's nearby.",
        cvss=CVSSVector(AV="L", AC="H", PR="N", UI="N", S="U", C="N", I="N", A="N"),
        remediation="Remove leftover debugger statements from production builds.",
    ),
    "HARDEN-SECURITY-TODO": dict(
        title="TODO/FIXME referencing a security concern",
        description="A code comment flags unfinished security-relevant work.",
        technical_detail="The author already identified this as a concern -- treat it as a confirmed lead, not a false positive.",
        cvss=CVSSVector(AV="L", AC="H", PR="N", UI="N", S="U", C="L", I="L", A="N"),
        remediation="Resolve the noted concern, or open a tracked issue if it can't be fixed immediately.",
    ),
}


class HardeningSightModule(BaseModule):
    SKILL_NAME = "Hardening Sight"
    SKILL_TYPE = SkillType.ACTIVE
    CATEGORY = "E10"
    DESCRIPTION = "Debug leftovers and missing defense-in-depth signals"
    RULE_SPECS = RULE_SPECS

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        self._findings = []
        for rule_id, meta in _META.items():
            for span in ctx.index.get(rule_id):
                text = ctx.index.file_text(span.file)
                self._add(Finding(
                    id=rule_id,
                    category="E10",
                    skill_name=self.SKILL_NAME,
                    skill_type=self.SKILL_TYPE,
                    evidence=[span.snippet],
                    file=span.file, line=span.line,
                    context=extract_snippet(text, span.line),
                    **meta,
                ))
        return self._findings
