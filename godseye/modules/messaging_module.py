"""
modules/messaging_module.py

[ACTIVE] Messaging Sentinel
Covers E2 - Insecure Cross-Context Messaging.

This module is the flagship demo of the tokenizer's block resolution.
The old approach checked for `sender.id` within 400 characters of the
listener registration -- a fixed window that:
  - generated false positives (a sender check from a DIFFERENT, unrelated
    handler sitting nearby would suppress the finding)
  - generated false negatives (a check legitimately further in a longer
    handler body would be missed)

Now: patterns are registered as is_anchor=True (Resolution.BLOCK). The
tokenizer uses the string/comment/template-literal-aware brace scanner
to find the ACTUAL function body for each listener, and stores it in
span.block.text. This module then searches that body -- and only that
body -- for the relevant validation patterns.
"""

from __future__ import annotations
import re

from ..models import Finding, CVSSVector, SkillType, Verification
from ..engine.base_module import BaseModule
from ..engine.loader import AnalysisContext
from ..engine.tokenizer import RuleSpec, FileScope, Resolution
from ..engine.snippet import extract_snippet

# Anchor patterns -- we want the resolved handler body, not just the match line
ON_MSG_EXT_RE = re.compile(r"chrome\.runtime\.onMessageExternal\.addListener")
ON_CONN_EXT_RE = re.compile(r"chrome\.runtime\.onConnectExternal\.addListener")
ON_MSG_RE = re.compile(r"chrome\.runtime\.onMessage\.addListener")
POSTMSG_RE = re.compile(r'addEventListener\(\s*[\'"]message[\'"]\s*,\s*(?:function\s*\(|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*\))')

# Validation patterns searched INSIDE the resolved handler body
SENDER_CHECK_RE = re.compile(r"sender\.(id|origin|url)\b")
ORIGIN_CHECK_RE = re.compile(r"\.origin\s*(===|!==|==|!=)")

RULE_SPECS: list[RuleSpec] = [
    RuleSpec("MSG-ON-MESSAGE-EXTERNAL", ON_MSG_EXT_RE, scope=FileScope.JS_NONVENDOR, resolution=Resolution.BLOCK),
    RuleSpec("MSG-ON-CONNECT-EXTERNAL", ON_CONN_EXT_RE, scope=FileScope.JS_NONVENDOR, resolution=Resolution.BLOCK),
    RuleSpec("MSG-ON-MESSAGE", ON_MSG_RE, scope=FileScope.JS_NONVENDOR, resolution=Resolution.BLOCK),
    RuleSpec("MSG-POSTMESSAGE-LISTENER", POSTMSG_RE, scope=FileScope.JS_NONVENDOR, resolution=Resolution.BLOCK),
]


class MessagingSentinelModule(BaseModule):
    SKILL_NAME = "Messaging Sentinel"
    SKILL_TYPE = SkillType.ACTIVE
    CATEGORY = "E2"
    DESCRIPTION = "Cross-context and cross-origin message handler risk"
    RULE_SPECS = RULE_SPECS

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        self._findings = []
        self._check_on_message_external(ctx)
        self._check_on_connect_external(ctx)
        self._check_on_message(ctx)
        self._check_postmessage(ctx)
        return self._findings

    def _body_text(self, span) -> str:
        return span.block.text if span.block else ""

    def _check_on_message_external(self, ctx: AnalysisContext) -> None:
        for span in ctx.index.get("MSG-ON-MESSAGE-EXTERNAL"):
            body = self._body_text(span)
            validated = bool(body and SENDER_CHECK_RE.search(body))
            text = ctx.index.file_text(span.file)

            finding_id = "MSG-ON-MESSAGE-EXTERNAL-CHECKED" if validated else "MSG-ON-MESSAGE-EXTERNAL-NO-CHECK"
            self._add(Finding(
                id=finding_id,
                title="onMessageExternal listener" + ("" if validated else " — no sender check in handler body"),
                category="E2",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description="This handler accepts runtime messages from other extensions or, if declared in externally_connectable, from web pages.",
                technical_detail=(
                    "Handler body was resolved and a sender.id/sender.origin/sender.url check was found inside it. "
                    "Confirm it gates all sensitive actions, not just logs." if validated else
                    "Handler body was resolved and NO sender check was found inside it -- this handler acts on "
                    "every caller's message without verifying who sent it. This is the highest-confidence "
                    "messaging finding: the check is based on the actual resolved handler body, not a heuristic window."
                    if body else
                    "Handler body could not be resolved (likely a named function reference). Manual review required."
                ),
                cvss=(
                    CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="N", A="N") if validated else
                    CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N")
                ),
                evidence=[span.snippet, *(["[handler body resolved]"] if body else [])],
                file=span.file, line=span.line,
                context=extract_snippet(text, span.line),
                remediation="Validate sender.id (and sender.origin for web-triggered messages) against an allowlist before acting on the payload, and schema-check the message shape.",
                verification=Verification(
                    title="Read the handler body",
                    steps=[f"Open {span.file} at line {span.line} and read the full onMessageExternal callback.",
                           "Confirm it checks sender.id/sender.origin before performing any state-changing or data-returning action."],
                ),
            ))

    def _check_on_connect_external(self, ctx: AnalysisContext) -> None:
        for span in ctx.index.get("MSG-ON-CONNECT-EXTERNAL"):
            body = self._body_text(span)
            text = ctx.index.file_text(span.file)
            self._add(Finding(
                id="MSG-ON-CONNECT-EXTERNAL",
                title="onConnectExternal listener",
                category="E2",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description="This handler accepts long-lived Port connections from other extensions or external web pages.",
                technical_detail="Long-lived ports are easy to forget to validate on every message, not just at connect time.",
                cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                evidence=[span.snippet],
                file=span.file, line=span.line,
                context=extract_snippet(text, span.line),
                remediation="Validate the connecting sender at connect time AND re-validate the message shape on every port.onMessage event.",
            ))

    def _check_on_message(self, ctx: AnalysisContext) -> None:
        for span in ctx.index.get("MSG-ON-MESSAGE"):
            body = self._body_text(span)
            # Internal messaging with a sender check resolved inside the actual body is fine -- suppress.
            if body and SENDER_CHECK_RE.search(body):
                continue
            text = ctx.index.file_text(span.file)
            self._add(Finding(
                id="MSG-ON-MESSAGE-NO-SENDER-CHECK",
                title="Internal onMessage listener — no sender check in resolved handler body",
                category="E2",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description="Internal messaging handler (content script <-> background) with no sender validation found inside the resolved handler body.",
                technical_detail=(
                    "Handler body was resolved and contained no sender.id/sender.origin check. "
                    "If this handler performs a sensitive action (storage write, network call, tab manipulation), "
                    "confirm the message can only originate from this extension's own pages." if body else
                    "Handler body could not be resolved (likely a named function reference). Manual review required."
                ),
                cvss=CVSSVector(AV="L", AC="H", PR="N", UI="N", S="U", C="N", I="L", A="N"),
                evidence=[span.snippet],
                file=span.file, line=span.line,
                context=extract_snippet(text, span.line),
                remediation="Add a sender check for any onMessage handler that performs a sensitive action.",
            ))

    def _check_postmessage(self, ctx: AnalysisContext) -> None:
        for span in ctx.index.get("MSG-POSTMESSAGE-LISTENER"):
            body = self._body_text(span)
            # Confirmed origin check inside the actual handler body -- suppress.
            if body and ORIGIN_CHECK_RE.search(body):
                continue
            text = ctx.index.file_text(span.file)
            self._add(Finding(
                id="MSG-POSTMESSAGE-NO-ORIGIN-CHECK",
                title="window 'message' listener — no origin check in resolved handler body",
                category="E2",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description="A postMessage handler was found with no event.origin comparison in the resolved handler body.",
                technical_detail=(
                    "Without an origin check, any page that can reach this frame/window (including via an iframe "
                    "on an attacker-controlled page) can send this handler messages. This finding is based on the "
                    "actual resolved handler body, not a character-count heuristic." if body else
                    "Handler body could not be resolved. Manual review required."
                ),
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="L", A="N"),
                evidence=[span.snippet],
                file=span.file, line=span.line,
                context=extract_snippet(text, span.line),
                remediation='Add `if (event.origin !== EXPECTED_ORIGIN) return;` as the first line of the handler.',
                verification=Verification(
                    title="Read the handler body",
                    steps=[f"Open {span.file} at line {span.line} and confirm whether event.origin is checked before the payload is used."],
                ),
            ))
