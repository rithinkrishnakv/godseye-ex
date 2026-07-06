"""
modules/context_leakage_module.py

[UNIQUE] Context Leakage Auditor
Covers E14 - Content Script / Page Context Boundary Violations.

Content scripts run in an "isolated world" -- they share the page DOM
but have their own separate JavaScript scope. The chrome.* namespace is
only accessible to the content script, NOT to page scripts.

Leakage happens when a content script explicitly bridges its privileged
scope into the page context. The two real patterns are:

1. window.X = chrome.* (assigning a chrome API reference to window)
2. window.postMessage() or window.dispatchEvent() used to relay
   privileged data OUT to the page, where any page script can read it.
3. CustomEvent with detail containing chrome.* data.
4. Assigning chrome.* bound methods to page-reachable variables.

If a page is compromised (via XSS or by being an attacker-controlled
page), any leaked chrome.* capability becomes fully attacker-accessible.
"""

from __future__ import annotations
import re

from ..models import Finding, CVSSVector, SkillType, Verification
from ..engine.base_module import BaseModule
from ..engine.loader import AnalysisContext
from ..engine.tokenizer import RuleSpec, FileScope
from ..engine.snippet import extract_snippet

_RULES: list[dict] = [
    dict(
        rule_id="CTX-WINDOW-CHROME-ASSIGN",
        pattern=re.compile(r"window\s*\.\s*\w+\s*=\s*chrome\s*\."),
        title="chrome.* API assigned to window property (privileged API exposed to page context)",
        detail="Assigning a chrome.* method or object to a window property makes it accessible to any page script -- including attacker-controlled ones (e.g. via XSS). Content scripts run in an isolated world specifically to prevent this: intentionally bridging back to the page defeats the isolation.",
        remediation="Never assign chrome.* APIs or their results to window properties, DOM attributes, or other page-accessible locations from a content script.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N"),
    ),
    dict(
        rule_id="CTX-CUSTOM-EVENT-CHROME-DATA",
        pattern=re.compile(r"(?:new\s+CustomEvent|dispatchEvent)\s*\([^)]*chrome\s*\."),
        title="chrome.* data dispatched via CustomEvent to page context",
        detail="Dispatching a CustomEvent that includes chrome.* data bridges privileged information into the page's event system, where any event listener registered by page scripts can receive it. In an XSS scenario, this is equivalent to a direct API leak.",
        remediation="Never include chrome.* API data or results in CustomEvents dispatched to the page. If page-script communication is needed, use a carefully scoped message protocol with strict allowlisting of what data can be shared.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="L", A="N"),
    ),
    dict(
        rule_id="CTX-POSTMESSAGE-CHROME-DATA",
        pattern=re.compile(r"window\s*\.\s*postMessage\s*\([^)]*chrome\s*\."),
        title="chrome.* data sent via window.postMessage to page",
        detail="window.postMessage() from a content script sends data to the page's message queue, readable by any page script. Including chrome.* API data (storage values, tab info, cookies, etc.) leaks privileged information to the page context.",
        remediation="Strictly scope what data is sent via postMessage. Never relay raw chrome.* responses directly -- only minimal, necessary data.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="H", I="N", A="N"),
    ),
    dict(
        rule_id="CTX-EVAL-IN-PAGE-CONTEXT",
        pattern=re.compile(r"(?:document\.head|document\.body|document\.documentElement)\s*\.\s*appendChild\s*\([^)]*script[^)]*\)"),
        title="Script element injected into page DOM (potential isolated-world escape)",
        detail="Injecting a script element into the page DOM causes it to execute in the PAGE's JavaScript context, not the content script's isolated world. If the injected script text is built from chrome.* data or can be influenced by page input, this is both a context leak and a potential XSS sink.",
        remediation="Avoid injecting script elements into the page DOM from content scripts. Use chrome.scripting.executeScript from the background service worker instead if page-context execution is genuinely required.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N"),
    ),
]

RULE_SPECS: list[RuleSpec] = [
    RuleSpec(r["rule_id"], r["pattern"], scope=FileScope.JS_NONVENDOR)
    for r in _RULES
]


class ContextLeakageAuditorModule(BaseModule):
    SKILL_NAME = "Context Leakage Auditor"
    SKILL_TYPE = SkillType.UNIQUE
    CATEGORY = "E14"
    DESCRIPTION = "Content script isolated-world violations and privileged API leakage to page context"
    RULE_SPECS = RULE_SPECS

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        self._findings = []
        for rule in _RULES:
            for span in ctx.index.get(rule["rule_id"]):
                text = ctx.index.file_text(span.file)
                self._add(Finding(
                    id=rule["rule_id"],
                    title=rule["title"],
                    category="E14",
                    skill_name=self.SKILL_NAME,
                    skill_type=self.SKILL_TYPE,
                    description=rule["detail"],
                    technical_detail=rule["detail"],
                    cvss=rule["cvss"],
                    evidence=[span.snippet],
                    file=span.file, line=span.line,
                    context=extract_snippet(text, span.line),
                    remediation=rule["remediation"],
                    verification=Verification(
                        title="Confirm whether this file is a content script",
                        steps=[
                            "Check manifest.json's content_scripts entries -- does this file appear as a content script?",
                            "If yes: any chrome.* data bridged to the window here is accessible to page scripts.",
                            "If no (background/popup): the isolated-world concern doesn't apply, but the finding still warrants review.",
                        ],
                    ),
                ))
        return self._findings
