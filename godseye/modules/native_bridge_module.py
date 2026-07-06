"""
modules/native_bridge_module.py

[UNIQUE] Native Bridge Sight
Covers E7 - Native Messaging & OS Bridge Exposure.
"""

from __future__ import annotations
import re

from ..models import Finding, CVSSVector, SkillType, Verification
from ..engine.base_module import BaseModule
from ..engine.loader import AnalysisContext
from ..engine.tokenizer import RuleSpec, FileScope
from ..engine.snippet import extract_snippet

CONNECT_NATIVE_RULE_ID = "NATIVE-CONNECT-CALL"
CONNECT_NATIVE_RE = re.compile(r"chrome\.runtime\.(connectNative|sendNativeMessage)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]")

RULE_SPECS: list[RuleSpec] = [RuleSpec(CONNECT_NATIVE_RULE_ID, CONNECT_NATIVE_RE, scope=FileScope.JS_NONVENDOR)]


class NativeBridgeSightModule(BaseModule):
    SKILL_NAME = "Native Bridge Sight"
    SKILL_TYPE = SkillType.UNIQUE
    CATEGORY = "E7"
    DESCRIPTION = "Native messaging / OS-level bridge exposure"
    RULE_SPECS = RULE_SPECS

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        self._findings = []
        perms = set(ctx.manifest.get("permissions", []) or [])
        if "nativeMessaging" in perms:
            self._add(Finding(
                id="NATIVE-PERMISSION-DECLARED",
                title="nativeMessaging permission declared",
                category="E7",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description="The extension can exchange messages with a native application installed on the OS.",
                technical_detail="This is the one permission that lets an extension step fully outside the browser sandbox. A bug in the native host's message handling (or an unauthenticated native host) turns an extension-level bug into OS-level code execution.",
                cvss=CVSSVector(AV="L", AC="H", PR="N", UI="N", S="C", C="H", I="H", A="H"),
                evidence=['"nativeMessaging" in permissions'],
                file=ctx.manifest_path.name,
                remediation="Confirm the native host validates and authenticates every message it receives, and runs with the least privilege it can.",
                verification=Verification(
                    title="Locate the native host manifest",
                    steps=["Find the native messaging host manifest registered for this extension's ID on the OS (registry on Windows, a JSON file under NativeMessagingHosts on macOS/Linux).",
                           "Confirm the native binary it points to validates message structure and sender identity."],
                ),
            ))

        for span in ctx.index.get(CONNECT_NATIVE_RULE_ID):
            host_name = span.groups[1] if len(span.groups) > 1 else "?"
            text = ctx.index.file_text(span.file)
            self._add(Finding(
                id="NATIVE-CONNECT-CALL",
                title=f"Native messaging call to host '{host_name}'",
                category="E7",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description=f"Extension code connects to native host '{host_name}'.",
                technical_detail="Trace what triggers this call -- if it can be reached from a content script or an external message, an attacker-controlled trigger could relay attacker-controlled data into the native host.",
                cvss=CVSSVector(AV="L", AC="H", PR="N", UI="N", S="C", C="H", I="H", A="L"),
                evidence=[span.snippet],
                file=span.file, line=span.line,
                context=extract_snippet(text, span.line),
                remediation="Ensure the payload sent to the native host is built from trusted, validated data only -- never forward a raw message/postMessage payload directly.",
            ))

        return self._findings
