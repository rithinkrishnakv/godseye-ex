"""
modules/cors_module.py

[ACTIVE] External CORS Auditor
Covers E16 - Permissive CORS & Cross-Origin Policy Weaknesses.

Flags:
- Overly permissive CORS headers set by the extension (via webRequest
  header modification or declarativeNetRequest inject rules)
- cross_origin_embedder_policy / cross_origin_opener_policy misconfiguration
  in manifest.json (these control whether extension pages opt into
  cross-origin isolation, which enables SharedArrayBuffer and high-res
  timers -- side-channel primitives)
- fetch/XMLHttpRequest calls with mode:'no-cors' where the response
  is used (opaque response, always succeeds, leaks timing)
- Access-Control-Allow-Origin: * in the extension's own response headers
"""

from __future__ import annotations
import re
from typing import Any

from ..models import Finding, CVSSVector, SkillType, Verification
from ..engine.base_module import BaseModule
from ..engine.loader import AnalysisContext
from ..engine.tokenizer import RuleSpec, FileScope
from ..engine.snippet import extract_snippet

_JS_RULES: list[dict] = [
    dict(
        rule_id="CORS-WILDCARD-HEADER-SET",
        pattern=re.compile(r"""['"](Access-Control-Allow-Origin)['"]\s*[,:].*['"]\*['"]""", re.IGNORECASE),
        title="Access-Control-Allow-Origin: * set in extension code",
        detail="Setting CORS to allow all origins removes the browser's cross-origin protection for requests to this endpoint. If the extension modifies response headers to add a wildcard CORS header, it allows any malicious website to read responses from the targeted server -- a direct data exfiltration primitive.",
        remediation="Scope Access-Control-Allow-Origin to specific, trusted origins. Never use '*' for authenticated endpoints.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="N", A="N"),
    ),
    dict(
        rule_id="CORS-NO-CORS-MODE-FETCH",
        pattern=re.compile(r"""mode\s*:\s*['"](no-cors)['"]"""),
        title="fetch() with mode:'no-cors' (opaque response / timing oracle)",
        detail="fetch() with mode:'no-cors' always succeeds (the response is opaque -- the JS cannot read it), but the request IS sent to the server. This can be used as a timing oracle: by measuring how long the request takes, an attacker can infer server-side state without being able to read the response body.",
        remediation="Avoid no-cors unless you explicitly need to fire-and-forget with no response. If you need the response, use mode:'cors' with a properly configured CORS policy on the server.",
        cvss=CVSSVector(AV="N", AC="H", PR="N", UI="R", S="U", C="L", I="N", A="N"),
    ),
    dict(
        rule_id="CORS-XHR-WITH-CREDENTIALS",
        pattern=re.compile(r"\.withCredentials\s*=\s*true"),
        title="XMLHttpRequest.withCredentials = true",
        detail="Setting withCredentials sends cookies, HTTP auth, and TLS client certs cross-origin. This is only safe when the server correctly validates the Origin header and does not echo back Access-Control-Allow-Origin: * (which browsers block, but extensions that modify headers could inadvertently enable).",
        remediation="Confirm the server's CORS policy is strict and that Access-Control-Allow-Origin is scoped to the exact allowed origin, not a wildcard.",
        cvss=CVSSVector(AV="N", AC="H", PR="N", UI="R", S="U", C="H", I="N", A="N"),
    ),
]

RULE_SPECS: list[RuleSpec] = [
    RuleSpec(r["rule_id"], r["pattern"], scope=FileScope.JS_NONVENDOR)
    for r in _JS_RULES
]


class ExternalCORSAuditorModule(BaseModule):
    SKILL_NAME = "External CORS Auditor"
    SKILL_TYPE = SkillType.ACTIVE
    CATEGORY = "E16"
    DESCRIPTION = "Permissive CORS, COEP/COOP misconfiguration, cross-origin data harvesting patterns"
    RULE_SPECS = RULE_SPECS

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        self._findings = []
        self._check_js_rules(ctx)
        self._check_manifest_isolation(ctx)
        return self._findings

    def _check_js_rules(self, ctx: AnalysisContext) -> None:
        for rule in _JS_RULES:
            for span in ctx.index.get(rule["rule_id"]):
                text = ctx.index.file_text(span.file)
                self._add(Finding(
                    id=rule["rule_id"],
                    title=rule["title"],
                    category="E16",
                    skill_name=self.SKILL_NAME,
                    skill_type=self.SKILL_TYPE,
                    description=rule["detail"],
                    technical_detail=rule["detail"],
                    cvss=rule["cvss"],
                    evidence=[span.snippet],
                    file=span.file, line=span.line,
                    context=extract_snippet(text, span.line),
                    remediation=rule["remediation"],
                ))

    def _check_manifest_isolation(self, ctx: AnalysisContext) -> None:
        """
        COEP / COOP are cross-origin isolation headers. When an extension page
        opts into cross-origin isolation (by setting both COEP: require-corp and
        COOP: same-origin), it unlocks SharedArrayBuffer and high-resolution
        timers -- which are Spectre / side-channel attack primitives. This isn't
        wrong on its own, but it means any XSS or context-leak in that page
        hands an attacker significantly more powerful timing tools.
        """
        m = ctx.manifest
        rel = ctx.manifest_path.name

        coep: Any = m.get("cross_origin_embedder_policy", {})
        coop: Any = m.get("cross_origin_opener_policy", {})

        coep_val = coep.get("value", "") if isinstance(coep, dict) else str(coep) if coep else ""
        coop_val = coop.get("value", "") if isinstance(coop, dict) else str(coop) if coop else ""

        if "require-corp" in coep_val.lower() and "same-origin" in coop_val.lower():
            self._add(Finding(
                id="CORS-CROSS-ORIGIN-ISOLATION-ENABLED",
                title="Cross-origin isolation enabled (COEP + COOP) — SharedArrayBuffer and high-res timers unlocked",
                category="E16",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description="The manifest enables cross-origin isolation via COEP: require-corp and COOP: same-origin.",
                technical_detail=(
                    "Cross-origin isolation is a valid security choice for extension pages that need SharedArrayBuffer. "
                    "The flag here is informational: an extension page with cross-origin isolation active "
                    "gives any XSS or content-script isolation failure on that page access to "
                    "SharedArrayBuffer and performance.now() at sub-microsecond resolution -- "
                    "the building blocks of Spectre-class side-channel attacks. This is worth knowing "
                    "about before deciding how much effort to spend on XSS hardening for that page."
                ),
                cvss=CVSSVector(AV="N", AC="H", PR="N", UI="R", S="C", C="H", I="N", A="N"),
                evidence=[
                    f"cross_origin_embedder_policy: {coep_val}",
                    f"cross_origin_opener_policy: {coop_val}",
                ],
                file=rel,
                remediation="This is informational -- the configuration may be intentional. Ensure XSS hardening for any page with cross-origin isolation is thorough, given the elevated side-channel attack surface.",
            ))

        if coep_val and "unsafe-none" in coep_val.lower():
            self._add(Finding(
                id="CORS-COEP-UNSAFE-NONE",
                title="cross_origin_embedder_policy explicitly set to 'unsafe-none'",
                category="E16",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description="COEP is explicitly set to unsafe-none, which opts this extension page out of cross-origin isolation protections.",
                technical_detail="This means the page can load cross-origin resources without a CORP/CORS header, but also that it will never be able to use SharedArrayBuffer. This is fine for most extension pages -- the flag is mostly informational.",
                cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="N", I="N", A="N"),
                evidence=[f"cross_origin_embedder_policy: {coep_val}"],
                file=rel,
                remediation="Intentional for most extensions. If cross-origin isolation is not needed, this is fine.",
            ))
