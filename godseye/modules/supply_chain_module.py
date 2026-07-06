"""
modules/supply_chain_module.py

[HIDDEN] Supply Chain Sentinel
Covers E6 - Supply Chain & Remote Dependencies.
"""

from __future__ import annotations
import re

from ..models import Finding, CVSSVector, SkillType
from ..engine.base_module import BaseModule
from ..engine.loader import AnalysisContext
from ..engine.tokenizer import RuleSpec, FileScope
from ..engine.snippet import extract_snippet

KNOWN_CDN_HOSTS = (
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "ajax.googleapis.com", "code.jquery.com",
)
ANALYTICS_HOSTS = (
    "google-analytics.com", "googletagmanager.com",
    "segment.io", "mixpanel.com", "amplitude.com",
)

LIBRARY_FINGERPRINTS = [
    dict(
        name="jQuery",
        rule_id="LIB-JQUERY-VERSION",
        pattern=re.compile(r"jQuery\s+v?(\d+\.\d+\.\d+)"),
        vulnerable_below="3.5.0",
        advisory="jQuery < 3.5.0 has a known XSS issue in jQuery.htmlPrefilter (CVE-2020-11022 / CVE-2020-11023).",
    ),
    dict(
        name="Lodash",
        rule_id="LIB-LODASH-VERSION",
        pattern=re.compile(r"lodash\.js\s+v?(\d+\.\d+\.\d+)|lodash@(\d+\.\d+\.\d+)"),
        vulnerable_below="4.17.21",
        advisory="Lodash < 4.17.21 has known prototype-pollution issues (e.g. CVE-2020-8203, CVE-2021-23337).",
    ),
]


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in v.split("."))


RULE_SPECS: list[RuleSpec] = [
    RuleSpec("SUPPLY-SCRIPT-SRC", re.compile(r'<script[^>]+src=["\']https?://([^"\']+)["\']', re.IGNORECASE), scope=FileScope.HTML),
    RuleSpec("SUPPLY-CSS-HREF", re.compile(r'<link[^>]+href=["\']https?://([^"\']+)["\'][^>]*rel=["\']stylesheet["\']', re.IGNORECASE), scope=FileScope.HTML),
    RuleSpec("SUPPLY-SCRIPT-SRC-JS", re.compile(r'<script[^>]+src=["\']https?://([^"\']+)["\']', re.IGNORECASE), scope=FileScope.JS_ALL),
    RuleSpec("SUPPLY-IMPORTSCRIPTS-REMOTE", re.compile(r"importScripts\s*\(\s*[\"'`](https?://[^\"'`]+)[\"'`]"), scope=FileScope.JS_ALL),
    *[RuleSpec(lib["rule_id"], lib["pattern"], scope=FileScope.JS_ALL) for lib in LIBRARY_FINGERPRINTS],
]


class SupplyChainSentinelModule(BaseModule):
    SKILL_NAME = "Supply Chain Sentinel"
    SKILL_TYPE = SkillType.HIDDEN
    CATEGORY = "E6"
    DESCRIPTION = "Remote dependency loading and known-vulnerable bundled libraries"
    RULE_SPECS = RULE_SPECS

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        self._findings = []
        self._scan_remote_refs(ctx)
        self._fingerprint_libraries(ctx)
        return self._findings

    def _scan_remote_refs(self, ctx: AnalysisContext) -> None:
        seen: set[tuple[str, str]] = set()
        for rule_id, kind in [
            ("SUPPLY-SCRIPT-SRC", "script"),
            ("SUPPLY-CSS-HREF", "stylesheet"),
            ("SUPPLY-SCRIPT-SRC-JS", "script"),
            ("SUPPLY-IMPORTSCRIPTS-REMOTE", "importScripts"),
        ]:
            for span in ctx.index.get(rule_id):
                host = span.groups[0] if span.groups else span.snippet
                key = (span.file, host)
                if key in seen:
                    continue
                seen.add(key)
                text = ctx.index.file_text(span.file)

                if any(h in host for h in ANALYTICS_HOSTS):
                    self._add(Finding(
                        id="SUPPLY-ANALYTICS-REMOTE",
                        title=f"Remote analytics/tracking {kind}: {host}",
                        category="E8",
                        skill_name=self.SKILL_NAME,
                        skill_type=self.SKILL_TYPE,
                        description="Extension page loads a third-party analytics/tracking resource.",
                        technical_detail="Confirm this is disclosed in the extension's privacy policy -- undisclosed tracking is a policy violation risk.",
                        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                        evidence=[f"references {host}"],
                        file=span.file, line=span.line,
                        context=extract_snippet(text, span.line),
                        remediation="Disclose third-party analytics in the privacy policy, or remove if not essential.",
                    ))
                    continue

                known = any(h in host for h in KNOWN_CDN_HOSTS)
                self._add(Finding(
                    id="SUPPLY-REMOTE-RESOURCE",
                    title=f"Remote {kind} reference: {host}",
                    category="E6",
                    skill_name=self.SKILL_NAME,
                    skill_type=self.SKILL_TYPE,
                    description=f"References a {kind} hosted on {host} rather than bundling it.",
                    technical_detail=(
                        "Recognized public CDN, but the extension still depends on that third party's integrity for every load." if known else
                        "Not a widely recognized CDN -- confirm this host is trusted and the resource is pinned to an immutable version."
                    ),
                    cvss=(CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="L", I="L", A="N") if known
                          else CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N")),
                    evidence=[f"references {host}"],
                    file=span.file, line=span.line,
                    context=extract_snippet(text, span.line),
                    remediation="Vendor the dependency into the extension bundle, or pin via Subresource Integrity (SRI) hashes.",
                ))

    def _fingerprint_libraries(self, ctx: AnalysisContext) -> None:
        for lib in LIBRARY_FINGERPRINTS:
            for span in ctx.index.get(lib["rule_id"]):
                version = next((g for g in span.groups if g), None)
                if not version:
                    continue
                try:
                    if _version_tuple(version) >= _version_tuple(lib["vulnerable_below"]):
                        continue
                except ValueError:
                    continue
                text = ctx.index.file_text(span.file)
                self._add(Finding(
                    id=f"SUPPLY-VULNERABLE-LIB-{lib['name'].upper()}",
                    title=f"Bundled {lib['name']} {version} has known public advisories",
                    category="E6",
                    skill_name=self.SKILL_NAME,
                    skill_type=self.SKILL_TYPE,
                    description=f"{lib['name']} {version} is bundled, below the {lib['vulnerable_below']} threshold.",
                    technical_detail=lib["advisory"],
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="L", A="N"),
                    evidence=[span.snippet],
                    file=span.file, line=span.line,
                    context=extract_snippet(text, span.line),
                    remediation=f"Update bundled {lib['name']} to the latest stable release.",
                ))
