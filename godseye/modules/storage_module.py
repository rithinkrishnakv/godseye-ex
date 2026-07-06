"""
modules/storage_module.py

[PASSIVE] Credential & Storage Sight
Covers E5 - Insecure Data Storage.
Uses publicly documented secret-shape patterns (the same style of regex
used by widely available tools like gitleaks/detect-secrets) to flag
likely hardcoded credentials, plus heuristics for sensitive-looking data
being persisted to chrome.storage without any apparent encryption step.

The chrome.storage.set({...}) body is resolved via the tokenizer's
string/comment-aware brace matcher (Resolution.OBJECT_LITERAL), not a
fixed character window -- the old `[^}]{0,300}` approach would silently
truncate at the first '}' it saw, which is wrong the moment the stored
object contains any nested object/array/template literal of its own.
"""

from __future__ import annotations
import re

from ..models import Finding, CVSSVector, SkillType, Verification
from ..engine.base_module import BaseModule
from ..engine.loader import AnalysisContext
from ..engine.tokenizer import RuleSpec, FileScope, Resolution
from ..engine.snippet import extract_snippet, extract_masked_snippet

SECRET_RULES = [
    dict(id="CRED-AWS-ACCESS-KEY", pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"), title="Likely AWS access key ID"),
    dict(id="CRED-GOOGLE-API-KEY", pattern=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), title="Likely Google API key"),
    dict(id="CRED-STRIPE-KEY", pattern=re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{24,}\b"), title="Likely live Stripe secret key"),
    dict(id="CRED-GITHUB-TOKEN", pattern=re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), title="Likely GitHub access token"),
    dict(id="CRED-SLACK-TOKEN", pattern=re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), title="Likely Slack token"),
    dict(id="CRED-JWT", pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), title="Embedded JWT"),
    dict(id="CRED-GENERIC-ASSIGN", pattern=re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[=:]\s*[\"'`][A-Za-z0-9_\-/+]{16,}[\"'`]"), title="Hardcoded credential-shaped assignment"),
]

SENSITIVE_NAME_RE = re.compile(r"(?i)\b(password|secret|token|api[_-]?key|session[_-]?id|auth)\b")
STORAGE_SET_RULE_ID = "STORAGE-SET-CALL"
STORAGE_SET_RE = re.compile(r"chrome\.storage\.(local|sync)\.set\s*\(")
LOCALSTORAGE_SET_RULE_ID = "LOCALSTORAGE-SET-CALL"
LOCALSTORAGE_SET_RE = re.compile(r"\blocalStorage\.setItem\s*\(\s*[\"'`]([^\"'`]+)[\"'`]")

RULE_SPECS: list[RuleSpec] = (
    [RuleSpec(r["id"], r["pattern"], scope=scope) for r in SECRET_RULES for scope in (FileScope.JS_NONVENDOR, FileScope.HTML)]
    + [
        RuleSpec(STORAGE_SET_RULE_ID, STORAGE_SET_RE, scope=FileScope.JS_NONVENDOR, resolution=Resolution.OBJECT_LITERAL),
        RuleSpec(LOCALSTORAGE_SET_RULE_ID, LOCALSTORAGE_SET_RE, scope=FileScope.JS_NONVENDOR),
    ]
)


class CredentialStorageSightModule(BaseModule):
    SKILL_NAME = "Credential & Storage Sight"
    SKILL_TYPE = SkillType.PASSIVE
    CATEGORY = "E5"
    DESCRIPTION = "Hardcoded secrets and unencrypted sensitive-data storage"
    RULE_SPECS = RULE_SPECS

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        self._findings = []
        self._scan_secrets(ctx)
        self._scan_storage(ctx)
        return self._findings

    def _scan_secrets(self, ctx: AnalysisContext) -> None:
        for rule in SECRET_RULES:
            for span in ctx.index.get(rule["id"]):
                text = ctx.index.file_text(span.file)
                self._add(Finding(
                    id=rule["id"],
                    title=rule["title"],
                    category="E5",
                    skill_name=self.SKILL_NAME,
                    skill_type=self.SKILL_TYPE,
                    description=f"{rule['title']} found hardcoded in the extension bundle.",
                    technical_detail="Anything shipped inside the extension package is extractable by unpacking the .crx/.xpi -- it is not a secret once it ships to users.",
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="L", A="N"),
                    evidence=["[redacted -- credential-shaped string matched, value not reproduced]"],
                    file=span.file, line=span.line,
                    context=extract_masked_snippet(text, span.line, text[span.start:span.end]),
                    remediation="Rotate this credential immediately if it's real, then move it server-side: have the extension call your backend, and have the backend hold the secret.",
                    verification=Verification(
                        title="Confirm and rotate",
                        steps=[f"Open {span.file} at line {span.line} and confirm whether the matched string is a live credential.",
                               "If real, rotate/revoke it with the issuing provider regardless of whether you also fix the code."],
                    ),
                ))

    def _scan_storage(self, ctx: AnalysisContext) -> None:
        for span in ctx.index.get(STORAGE_SET_RULE_ID):
            if span.block is None or not SENSITIVE_NAME_RE.search(span.block.text):
                continue
            text = ctx.index.file_text(span.file)
            self._add(Finding(
                id="STORAGE-SENSITIVE-CHROME-STORAGE",
                title="Sensitive-looking key written to chrome.storage without visible encryption",
                category="E5",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description="A key named like a credential (password/token/secret/session/auth) is being written to chrome.storage.",
                technical_detail="chrome.storage.local/sync is not encrypted at rest by default; anything written here is plaintext on disk and readable by anything with the same level of access as the extension (e.g. another extension during a chrome.storage bug, or anyone with filesystem access to the profile).",
                # UI:N -- writing to storage is the vulnerability itself (a static data-at-rest
                # exposure), not the later step of someone reading it back out. UI:R would
                # conflate the leak with a downstream exploit step that may not even be needed.
                cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                evidence=[span.block.text.strip()[:120]],
                file=span.file, line=span.line,
                context=extract_snippet(text, span.line),
                remediation="Avoid persisting raw credentials client-side. If you must, encrypt before writing and consider a short TTL/refresh-token pattern instead of a long-lived secret.",
            ))

        for span in ctx.index.get(LOCALSTORAGE_SET_RULE_ID):
            key = span.groups[0] if span.groups else ""
            if not key or not SENSITIVE_NAME_RE.search(key):
                continue
            text = ctx.index.file_text(span.file)
            self._add(Finding(
                id="STORAGE-SENSITIVE-LOCALSTORAGE",
                title="Sensitive-looking key written to localStorage (content-script context)",
                category="E5",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description=f"localStorage.setItem('{key}', ...) found in a script that may run in page context.",
                technical_detail="If this executes as a content script, the data lands in the *page's* localStorage, not an isolated extension store -- it becomes readable by that page's own JavaScript and any XSS on that page.",
                # UI:N -- same reasoning as above. If a content script calls this unconditionally
                # on load, the leak to page-readable storage requires no user action at all.
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="N", A="N"),
                evidence=[f"localStorage.setItem('{key}', ...)"],
                file=span.file, line=span.line,
                context=extract_snippet(text, span.line),
                remediation="Use chrome.storage.local from the background/extension context instead of page localStorage for anything sensitive.",
            ))
