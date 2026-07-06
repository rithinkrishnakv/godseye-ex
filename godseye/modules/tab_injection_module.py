"""
modules/tab_injection_module.py

[ACTIVE] Tab Injection Controller
Covers E15 - Cross-Tab Script Injection.

Flags chrome.scripting.executeScript and chrome.tabs.executeScript calls
where the injection target (tabId) or the injected code is built from
external, potentially attacker-controlled data. In the worst case this
allows injecting arbitrary JS into any tab the extension has access to --
effectively a browser-wide XSS if the extension has broad host access.
"""

from __future__ import annotations
import re

from ..models import Finding, CVSSVector, SkillType, Verification
from ..engine.base_module import BaseModule
from ..engine.loader import AnalysisContext
from ..engine.tokenizer import RuleSpec, FileScope, Resolution
from ..engine.snippet import extract_snippet

# executeScript call -- resolve the argument object literal to check what's inside
EXEC_SCRIPT_MV3_RE = re.compile(r"chrome\.scripting\.executeScript\s*\(")
EXEC_SCRIPT_MV2_RE = re.compile(r"chrome\.tabs\.executeScript\s*\(")

# Patterns that suggest attacker-influenced values inside the resolved call
MSG_PAYLOAD_RE = re.compile(r"\bmsg(?:ata)?\.|\bmessage\.\w+|request\.\w+|payload\.\w+")
DYNAMIC_TAB_RE = re.compile(r"tabId\s*:\s*(?!sender\.tab\.id)\w")
STRING_CODE_RE = re.compile(r"""(?:code|function)\s*:\s*[`'"]""")
CONCAT_CODE_RE = re.compile(r"""code\s*:\s*\w+\s*\+|`[^`]*\$\{""")

RULE_SPECS: list[RuleSpec] = [
    RuleSpec("TAB-EXECUTE-SCRIPT-MV3", EXEC_SCRIPT_MV3_RE, scope=FileScope.JS_NONVENDOR, resolution=Resolution.OBJECT_LITERAL),
    RuleSpec("TAB-EXECUTE-SCRIPT-MV2", EXEC_SCRIPT_MV2_RE, scope=FileScope.JS_NONVENDOR, resolution=Resolution.OBJECT_LITERAL),
]


class TabInjectionControllerModule(BaseModule):
    SKILL_NAME = "Tab Injection Controller"
    SKILL_TYPE = SkillType.ACTIVE
    CATEGORY = "E15"
    DESCRIPTION = "Cross-tab script injection via executeScript with dynamic targets or code strings"
    RULE_SPECS = RULE_SPECS

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        self._findings = []
        for rule_id, label in [("TAB-EXECUTE-SCRIPT-MV3", "chrome.scripting.executeScript"), ("TAB-EXECUTE-SCRIPT-MV2", "chrome.tabs.executeScript")]:
            for span in ctx.index.get(rule_id):
                self._analyze(ctx, span, rule_id, label)
        return self._findings

    def _analyze(self, ctx: AnalysisContext, span, rule_id: str, label: str) -> None:
        body = span.block.text if span.block else ""
        text = ctx.index.file_text(span.file)

        # Accumulate risk signals from the resolved argument body
        signals: list[str] = []
        if body:
            if MSG_PAYLOAD_RE.search(body):
                signals.append("tabId or code may derive from a message payload")
            if DYNAMIC_TAB_RE.search(body):
                signals.append("tabId is set dynamically (not from sender.tab.id)")
            if STRING_CODE_RE.search(body):
                signals.append("code is a string literal -- dynamic code execution in target tab")
            if CONCAT_CODE_RE.search(body):
                signals.append("code is built via string concatenation or template literal -- potential injection sink")

        if not signals and body:
            # Call exists but argument body looks static -- still surface as info
            signals = ["call exists; argument body resolved but no high-risk signals detected -- confirm target and code source"]

        cvss = (
            CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N")
            if any("payload" in s or "injection" in s for s in signals)
            else CVSSVector(AV="L", AC="H", PR="N", UI="N", S="U", C="L", I="L", A="N")
        )

        self._add(Finding(
            id=rule_id,
            title=f"{label} call" + (" — dynamic target or code" if signals else ""),
            category="E15",
            skill_name=self.SKILL_NAME,
            skill_type=self.SKILL_TYPE,
            description=f"{label} injects code into an arbitrary tab. Risk depends entirely on whether the target tab and injected code/function are attacker-influenced.",
            technical_detail=(
                "Signals found in resolved argument body:\n• " + "\n• ".join(signals)
                if signals else "No argument body resolved -- likely a named function call."
            ),
            cvss=cvss,
            evidence=[span.snippet],
            file=span.file, line=span.line,
            context=extract_snippet(text, span.line),
            remediation=(
                "Ensure: (1) tabId always comes from sender.tab.id or a user-initiated action, never from a message payload. "
                "(2) injected functions are statically defined, never built from strings or message data. "
                "(3) If 'code' string injection is unavoidable, treat all interpolated values as untrusted and sanitize."
            ),
            verification=Verification(
                title="Trace the target tab and injected code sources",
                steps=[
                    f"Open {span.file} at line {span.line}.",
                    "Trace tabId back to its source -- is it from sender.tab.id (safe) or from a message/storage/URL (risky)?",
                    "Trace the 'func' or 'files' parameter -- is it a static reference or built from external data?",
                    "If 'code' is used instead of 'func', this is a string-injection path -- treat all interpolated values as untrusted.",
                ],
            ),
        ))
