"""
modules/dynamic_code_module.py

[ACTIVE] Dynamic Code Sight
Covers E4 - Dynamic Code Execution.
"""

from __future__ import annotations
import re

from ..models import Finding, CVSSVector, SkillType, Verification
from ..engine.base_module import BaseModule
from ..engine.loader import AnalysisContext
from ..engine.tokenizer import RuleSpec, FileScope
from ..engine.snippet import extract_snippet

_RULE_META = {
    "DYN-EVAL": ("Use of eval()", "eval() executes arbitrary strings as code -- a common sink for injection bugs if any part of the string is attacker-influenced.", CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="L", A="N")),
    "DYN-EVAL-REFERENCE": (
        "eval passed as a callback reference",
        "eval is passed by reference as a callback (e.g. .then(eval), setTimeout(eval, N), [].forEach(eval)). "
        "This is functionally identical to eval() being called on every value the callback receives. "
        "Critically, this pattern evades all scanners that only look for 'eval(' -- "
        "including previous versions of this tool. When the data source is a remote fetch(), "
        "this becomes direct network-to-execution RCE in whatever context the code runs.",
        CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
    ),
    "DYN-NEW-FUNCTION": ("Use of new Function()", "Compiles a string into executable code -- equivalent risk to eval().", CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="L", A="N")),
    "DYN-SETTIMEOUT-STRING": ("setTimeout/setInterval with a string argument", "Passing a string to setTimeout/setInterval implicitly evals it.", CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="N", I="L", A="N")),
    "DYN-EXECUTE-SCRIPT": ("chrome.scripting.executeScript call", "Injects code into page contexts. Verify the injected function/args and target tab are not influenced by untrusted input.", CVSSVector(AV="L", AC="H", PR="N", UI="N", S="U", C="L", I="L", A="N")),
    "DYN-TABS-EXECUTE-SCRIPT": ("chrome.tabs.executeScript call (MV2)", "Legacy script-injection API; same review considerations as chrome.scripting.executeScript.", CVSSVector(AV="L", AC="H", PR="N", UI="N", S="U", C="L", I="L", A="N")),
    "DYN-REMOTE-IMPORTSCRIPTS": ("importScripts() loading a remote URL", "The service worker fetches and executes code from a remote host at runtime, outside the reviewed extension bundle.", CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N")),
    "DYN-DYNAMIC-SCRIPT-TAG": ("Dynamically created <script> element", "Programmatically creating a script element is a common pattern for loading remote/third-party code at runtime.", CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="L", A="N")),
}

_PATTERNS = {
    "DYN-EVAL": re.compile(r"\beval\s*\("),
    # Matches eval passed as a bare callback reference -- NOT a call site.
    # Covers: .then(eval)  setTimeout(eval, N)  arr.forEach(eval)  apply(x, eval)
    "DYN-EVAL-REFERENCE": re.compile(
        r"\.then\s*\(\s*eval\s*\)"
        r"|set(?:Timeout|Interval)\s*\(\s*eval\b"
        r"|\.\s*(?:forEach|map|reduce|apply|call)\s*\(\s*eval\b"
        r"|=\s*eval\s*[,;)\]]"
    ),
    "DYN-NEW-FUNCTION": re.compile(r"\bnew\s+Function\s*\("),
    "DYN-SETTIMEOUT-STRING": re.compile(r"set(Timeout|Interval)\s*\(\s*[\"'`]"),
    "DYN-EXECUTE-SCRIPT": re.compile(r"chrome\.scripting\.executeScript\s*\("),
    "DYN-TABS-EXECUTE-SCRIPT": re.compile(r"chrome\.tabs\.executeScript\s*\("),
    "DYN-REMOTE-IMPORTSCRIPTS": re.compile(r"importScripts\s*\(\s*[\"'`]https?://"),
    "DYN-DYNAMIC-SCRIPT-TAG": re.compile(r"createElement\(\s*[\"'`]script[\"'`]\s*\)"),
}

RULE_SPECS: list[RuleSpec] = [RuleSpec(rid, pat, scope=FileScope.JS_NONVENDOR) for rid, pat in _PATTERNS.items()]


class DynamicCodeSightModule(BaseModule):
    SKILL_NAME = "Dynamic Code Sight"
    SKILL_TYPE = SkillType.ACTIVE
    CATEGORY = "E4"
    DESCRIPTION = "Dynamic code execution and runtime script injection patterns"
    RULE_SPECS = RULE_SPECS

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        self._findings = []
        for rule_id, (title, detail, cvss) in _RULE_META.items():
            for span in ctx.index.get(rule_id):
                text = ctx.index.file_text(span.file)
                self._add(Finding(
                    id=rule_id,
                    title=title,
                    category="E4",
                    skill_name=self.SKILL_NAME,
                    skill_type=self.SKILL_TYPE,
                    description=title + " found in extension source.",
                    technical_detail=detail,
                    cvss=cvss,
                    evidence=[span.snippet],
                    file=span.file, line=span.line,
                    context=extract_snippet(text, span.line),
                    remediation="Avoid dynamic code construction; use static functions, JSON.parse, or a lookup table instead.",
                    verification=Verification(
                        title="Trace the data source",
                        steps=[f"Open {span.file} at line {span.line} and confirm whether any part of the executed/injected value can be influenced by page content, a message payload, or a URL parameter."],
                    ),
                ))
        return self._findings
