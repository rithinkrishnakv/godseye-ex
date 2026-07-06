"""
modules/network_policy_module.py

[ACTIVE] Network Policy Auditor
Covers E13 - Network Policy & Traffic Manipulation.

Flags:
- chrome.declarativeNetRequest dynamic rules built from runtime input
  (static bundled rulesets are reviewed; dynamic ones built at runtime
  from external/message data are the risk)
- chrome.webRequest onBeforeSendHeaders / onHeadersReceived hooks that
  modify security-relevant headers
- Hardcoded cleartext HTTP endpoints (http:// in extension source)
- chrome.proxy usage (full traffic redirect/intercept capability)
"""

from __future__ import annotations
import re

from ..models import Finding, CVSSVector, SkillType, Verification
from ..engine.base_module import BaseModule
from ..engine.loader import AnalysisContext
from ..engine.tokenizer import RuleSpec, FileScope, Resolution
from ..engine.snippet import extract_snippet

SECURITY_HEADERS = re.compile(
    r"""(?i)(Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|"""
    r"""X-Content-Type-Options|Access-Control-Allow-Origin|Authorization|Cookie)""",
    re.IGNORECASE,
)

_RULES: list[dict] = [
    dict(
        rule_id="NET-RCE-FETCH-EVAL",
        pattern=re.compile(r"fetch\s*\(\s*[\"'`]https?://"),
        resolution=Resolution.NONE,
        title="Remote fetch() piped directly into eval — Network RCE",
        detail=(
            "fetch() retrieves content from a remote URL and an eval reference "
            "(direct call or passed as a callback, e.g. .then(eval)) was found "
            "nearby in the same file. This is not a 'cleartext HTTP' issue — it is "
            "full Remote Code Execution: an attacker who controls the remote server "
            "(or MitMs an unencrypted connection) can inject arbitrary JavaScript "
            "that runs inside the extension's context with all declared permissions. "
            "No user interaction required if this fires on install/update. Combined "
            "with broad permissions (cookies, history, clipboardRead) this means "
            "complete browser session compromise from a single network position."
        ),
        remediation=(
            "Remove the fetch-and-eval pattern entirely. Extension code must be "
            "static and immutable at runtime. If updates are needed, bundle them "
            "through the extension store review process — never pull and execute "
            "remote code. If dynamic data from a server is genuinely required, "
            "fetch it as data (JSON), validate it against a strict schema, and "
            "never pass it to any code-execution primitive."
        ),
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
    ),
    dict(
        rule_id="NET-DNR-DYNAMIC-RULE",
        pattern=re.compile(r"chrome\.declarativeNetRequest\.(updateDynamicRules|updateSessionRules)\s*\("),
        resolution=Resolution.NONE,
        title="Dynamic declarativeNetRequest rules updated at runtime",
        detail="updateDynamicRules/updateSessionRules modifies the active network ruleset at runtime. If the rule content is influenced by a message payload, storage value, or remote config (rather than hardcoded/static), an attacker who can control that input can modify what the extension blocks or redirects for the user.",
        remediation="Confirm the rules being added are built from static/bundled data only, never from external messages, remote responses, or user-controlled storage values.",
        cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="H", A="N"),
    ),
    dict(
        rule_id="NET-WEBREQUEST-HEADER-HOOK",
        pattern=re.compile(r"chrome\.webRequest\.(onBeforeSendHeaders|onHeadersReceived)\.addListener"),
        resolution=Resolution.BLOCK,
        title="webRequest header modification hook",
        detail="onBeforeSendHeaders and onHeadersReceived can inspect and modify every HTTP request/response header -- including Authorization, Cookie, and security headers like Content-Security-Policy and Strict-Transport-Security. If this hook modifies security headers in ways that weaken them (removing CSP, stripping HSTS, adding CORS wildcards), it becomes an active downgrade vector.",
        remediation="Confirm that any header modifications strengthen (not weaken) the security posture. Specifically: never remove CSP/HSTS/X-Frame-Options, and never broaden CORS to wildcards.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N"),
    ),
    dict(
        rule_id="NET-CLEARTEXT-HTTP",
        pattern=re.compile(r"""["'`](http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[A-Za-z0-9._-]+[^"'`]{0,100})["'`]"""),
        resolution=Resolution.NONE,
        title="Hardcoded cleartext HTTP endpoint",
        detail="A non-localhost http:// URL is hardcoded in the extension source. Traffic to this endpoint is unencrypted and observable/modifiable by anyone on the path (network observer, ISP, rogue Wi-Fi, MitM). Auth tokens, session cookies, and API payloads sent over this connection are readable.",
        remediation="Replace all non-localhost http:// URLs with https://. If the server doesn't support HTTPS, that's a separate issue that needs addressing on the server side first.",
        cvss=CVSSVector(AV="A", AC="H", PR="N", UI="N", S="U", C="H", I="L", A="N"),
    ),
    dict(
        rule_id="NET-PROXY-USAGE",
        pattern=re.compile(r"chrome\.proxy\.settings\.(set|clear)\s*\("),
        resolution=Resolution.NONE,
        title="chrome.proxy.settings modification",
        detail="The extension modifies the system proxy settings, which routes all browser traffic through a different proxy. If this is triggered by external input (a message, a remote config, user-provided URL), an attacker who controls that input can redirect traffic to an arbitrary server.",
        remediation="Confirm that proxy settings are never set from untrusted/external input and that any proxy URL is hardcoded and audited.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N"),
    ),
]

RULE_SPECS: list[RuleSpec] = [
    RuleSpec(r["rule_id"], r["pattern"], scope=FileScope.JS_NONVENDOR, resolution=r["resolution"])
    for r in _RULES
]

# Used by _check_header_hook to search resolved handler bodies
_SECURITY_HDR_RE = SECURITY_HEADERS


class NetworkPolicyAuditorModule(BaseModule):
    SKILL_NAME = "Network Policy Auditor"
    SKILL_TYPE = SkillType.ACTIVE
    CATEGORY = "E13"
    DESCRIPTION = "declarativeNetRequest rules, header hooks, cleartext HTTP, proxy manipulation"
    RULE_SPECS = RULE_SPECS

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        self._findings = []
        for rule in _RULES:
            if rule["rule_id"] == "NET-WEBREQUEST-HEADER-HOOK":
                self._check_header_hook(ctx, rule)
            elif rule["rule_id"] == "NET-RCE-FETCH-EVAL":
                self._check_rce_fetch_eval(ctx, rule)
            else:
                self._generic(ctx, rule)
        return self._findings

    def _check_rce_fetch_eval(self, ctx: AnalysisContext, rule: dict, max_line_distance: int = 6) -> None:
        """
        A fetch(remote-url) is an RCE, not just a cleartext-transport issue, if an
        eval call/reference appears in the same promise chain. We don't re-scan
        text with a fresh regex here -- we cross-reference the MatchSpans that
        DYN-EVAL and DYN-EVAL-REFERENCE (Dynamic Code Sight) already found in the
        same file, and require them to be within a small number of LINES of the
        fetch call. A promise chain written as consecutive .then() calls is
        always a handful of lines, so this stays precise without needing to know
        the language's real statement boundaries.
        """
        eval_spans = ctx.index.get("DYN-EVAL") + ctx.index.get("DYN-EVAL-REFERENCE")
        eval_by_file: dict[str, list[int]] = {}
        for s in eval_spans:
            eval_by_file.setdefault(s.file, []).append(s.line)

        for span in ctx.index.get(rule["rule_id"]):
            nearby_eval_lines = [
                ln for ln in eval_by_file.get(span.file, [])
                if abs(ln - span.line) <= max_line_distance
            ]
            if not nearby_eval_lines:
                continue  # fetch exists but no eval nearby -- NET-CLEARTEXT-HTTP already covers the plain case

            text = ctx.index.file_text(span.file)
            self._add(Finding(
                id=rule["rule_id"],
                title=rule["title"],
                category="E13",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description=rule["detail"],
                technical_detail=(
                    rule["detail"] +
                    f"\n\nfetch() call at line {span.line}; eval reference found at line(s) "
                    f"{sorted(set(nearby_eval_lines))} in the same file."
                ),
                cvss=rule["cvss"],
                evidence=[span.snippet, f"eval reference at line(s) {sorted(set(nearby_eval_lines))}"],
                file=span.file, line=span.line,
                context=extract_snippet(text, span.line, before=1, after=max(nearby_eval_lines) - span.line + 1),
                remediation=rule["remediation"],
                verification=Verification(
                    title="Confirm the fetch response reaches eval unmodified",
                    steps=[
                        f"Open {span.file} and read from line {span.line} through line {max(nearby_eval_lines)}.",
                        "Confirm the fetch response (or a value derived from it) is the argument eval receives -- if so, this is confirmed RCE, not just a suspicious pattern.",
                        "Check whether the URL is HTTP (trivial MitM) or HTTPS (requires server compromise instead).",
                    ],
                ),
            ))

    def _generic(self, ctx: AnalysisContext, rule: dict) -> None:
        for span in ctx.index.get(rule["rule_id"]):
            url_note = ""
            if rule["rule_id"] == "NET-CLEARTEXT-HTTP" and span.groups:
                url_note = f": {span.groups[0][:80]}"
            text = ctx.index.file_text(span.file)
            self._add(Finding(
                id=rule["rule_id"],
                title=rule["title"] + url_note,
                category="E13",
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

    def _check_header_hook(self, ctx: AnalysisContext, rule: dict) -> None:
        for span in ctx.index.get(rule["rule_id"]):
            body = span.block.text if span.block else ""
            modifies_security_header = bool(body and _SECURITY_HDR_RE.search(body))
            text = ctx.index.file_text(span.file)
            self._add(Finding(
                id=rule["rule_id"],
                title=rule["title"] + (" — security header referenced in handler" if modifies_security_header else ""),
                category="E13",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description=rule["detail"],
                technical_detail=(
                    f"{rule['detail']} The resolved handler body references security-relevant header name(s) -- "
                    "confirm modifications are strengthening, not weakening." if modifies_security_header else rule["detail"]
                ),
                cvss=(
                    CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N")
                    if modifies_security_header else
                    CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="L", A="N")
                ),
                evidence=[span.snippet],
                file=span.file, line=span.line,
                context=extract_snippet(text, span.line),
                remediation=rule["remediation"],
                verification=Verification(
                    title="Inspect the handler body",
                    steps=[
                        f"Open {span.file} at line {span.line} and read the full header-modification callback.",
                        "Confirm no security headers (CSP, HSTS, X-Frame-Options, Authorization) are removed or weakened.",
                        "If CORS headers are modified, confirm Access-Control-Allow-Origin is never set to '*' for authenticated endpoints.",
                    ],
                ),
            ))
