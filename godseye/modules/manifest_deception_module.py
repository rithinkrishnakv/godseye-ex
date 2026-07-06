"""
modules/manifest_deception_module.py

[UNIQUE] Manifest Deception Sight
Covers E11 - Manifest/Code Mismatch & Hidden Capability.

A manifest.json is a claim, not a guarantee. This module looks for the
specific ways that claim can be misleading:

  - capabilities exposed to the WEB (not just the extension) via
    web_accessible_resources, which is a real, recurring vulnerability
    class in browser extensions -- not a theoretical one
  - permissions requested at RUNTIME via optional_permissions instead of
    install-time, a known technique for getting past store review with a
    minimal-looking manifest and then asking for more later
  - a permission that's declared but never actually used anywhere in the
    visible source (a "reserved" capability worth asking about)
  - code that calls a chrome.* API whose permission was never declared
    (dead code, or a missing declaration -- either way, worth a look)
  - a few smaller, well-documented evasion tricks: pinned extension IDs
    via the "key" field, devtools_page, frame-injection via
    match_about_blank, name impersonation of a well-known extension, and
    non-standard manifest keys

Everything here is still static: reading manifest.json and source text,
cross-referencing them against each other. No code from the extension is
executed.
"""

from __future__ import annotations
import re
from typing import Any

from ..models import Finding, CVSSVector, SkillType, Verification
from ..engine.base_module import BaseModule
from ..engine.loader import AnalysisContext
from .manifest_module import HIGH_RISK_PERMISSIONS, MEDIUM_RISK_PERMISSIONS, HOST_WILDCARD_PATTERNS

SENSITIVE_RESOURCE_RE = re.compile(
    r"(?i)\.(json|db|sqlite3?|key|pem|env|map|ya?ml|bak|backup|p12|pfx|crt)$|secret|credential|private|config\."
)

# perm -> a regex that, if found in source, indicates the permission is actually being used.
# Deliberately conservative: only permissions with a reasonably unambiguous API surface.
PERMISSION_API_PATTERNS: dict[str, re.Pattern] = {
    "tabs": re.compile(r"chrome\.tabs\."),
    "cookies": re.compile(r"chrome\.cookies\."),
    "history": re.compile(r"chrome\.history\."),
    "webRequest": re.compile(r"chrome\.webRequest\."),
    "downloads": re.compile(r"chrome\.downloads\."),
    "management": re.compile(r"chrome\.management\."),
    "declarativeNetRequest": re.compile(r"chrome\.declarativeNetRequest\."),
    "scripting": re.compile(r"chrome\.scripting\."),
    "debugger": re.compile(r"chrome\.debugger\."),
    "proxy": re.compile(r"chrome\.proxy\."),
    "nativeMessaging": re.compile(r"chrome\.runtime\.(connectNative|sendNativeMessage)\s*\("),
    "geolocation": re.compile(r"navigator\.geolocation\."),
    "clipboardRead": re.compile(r"navigator\.clipboard\.readText\s*\(|execCommand\(\s*['\"]paste['\"]"),
    "clipboardWrite": re.compile(r"navigator\.clipboard\.writeText\s*\(|execCommand\(\s*['\"]copy['\"]"),
}

# Top-level manifest.json keys documented by Chrome (MV2+MV3) and Firefox.
# Generous on purpose -- this only flags genuinely unrecognized keys, not
# every browser-specific or recently-added field.
STANDARD_MANIFEST_KEYS = {
    "manifest_version", "name", "version", "version_name", "description", "icons",
    "action", "browser_action", "page_action", "background", "chrome_settings_overrides",
    "chrome_url_overrides", "commands", "content_scripts", "content_security_policy",
    "cross_origin_embedder_policy", "cross_origin_opener_policy", "declarative_net_request",
    "default_locale", "devtools_page", "externally_connectable", "host_permissions",
    "incognito", "key", "minimum_chrome_version", "oauth2", "omnibox",
    "optional_permissions", "optional_host_permissions", "options_page", "options_ui",
    "permissions", "requirements", "sandbox", "short_name", "storage", "tts_engine",
    "update_url", "web_accessible_resources", "content_capabilities", "automation",
    "file_browser_handlers", "input_components", "platforms", "system_indicator",
    "current_locale", "applications", "browser_specific_settings", "sidebar_action",
    "theme", "user_scripts", "replacement_web_app", "homepage_url", "offline_enabled",
    "protocol_handlers", "author", "differential_fingerprint", "export", "import",
    "minimum_opera_version", "signature", "spellcheck", "nacl_modules",
}

# A short list of widely-known extensions, used only to flag names that are
# SUSPICIOUSLY CLOSE to (but not identical to) one of these -- not to claim
# any particular extension IS or ISN'T legitimate.
POPULAR_EXTENSION_NAMES = [
    "LastPass", "MetaMask", "Grammarly", "Honey", "AdBlock", "AdBlock Plus",
    "uBlock Origin", "Dark Reader", "Google Translate", "Capital One Shopping",
    "Pocket", "Evernote Web Clipper", "1Password", "Bitwarden", "Momentum",
]


def _normalize_name(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


class ManifestDeceptionModule(BaseModule):
    SKILL_NAME = "Manifest Deception Sight"
    SKILL_TYPE = SkillType.UNIQUE
    CATEGORY = "E11"
    DESCRIPTION = "Manifest/code mismatches and known store-review-evasion tricks"

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        self._findings = []
        m = ctx.manifest
        rel = ctx.manifest_path.name
        js_text = "\n".join(f.text for f in ctx.js_files())

        self._check_web_accessible_resources(m, rel)
        self._check_optional_permission_ratchet(m, rel)
        self._check_permission_code_mismatch(m, rel, js_text)
        self._check_fixed_key(m, rel)
        self._check_devtools_page(m, rel)
        self._check_frame_injection_trick(m, rel)
        self._check_name_impersonation(m, rel)
        self._check_unknown_keys(m, rel)

        return self._findings

    def _check_web_accessible_resources(self, m: dict, rel: str) -> None:
        war = m.get("web_accessible_resources")
        if not war:
            return
        mv = m.get("manifest_version")

        if mv == 2 and isinstance(war, list):
            resources = [r for r in war if isinstance(r, str)]
            if not resources:
                return
            wildcard = any(r.strip() in ("*", "<all_urls>") for r in resources)
            sensitive = [r for r in resources if SENSITIVE_RESOURCE_RE.search(r)]
            self._add(Finding(
                id="MANDEC-WAR-MV2-EXPOSURE",
                title=f"web_accessible_resources exposes {len(resources)} resource(s) to ALL web origins (MV2)",
                category="E11",
                skill_name=self.SKILL_NAME, skill_type=self.SKILL_TYPE,
                description="Manifest V2's web_accessible_resources has no per-origin scoping -- every listed resource is fetchable by any website via chrome-extension://<id>/<path>.",
                technical_detail="This is a real, recurring vulnerability class: any HTML page listed here runs with the extension's origin if loaded via chrome-extension://, and any JS/data file is readable by any site that knows (or guesses) the extension ID. " + (f"Includes sensitive-looking file(s): {', '.join(sensitive)}." if sensitive else ""),
                cvss=CVSSVector(AV="N", AC="L" if wildcard or sensitive else "H", PR="N", UI="N", S="C", C="H" if sensitive else "L", I="L", A="N"),
                evidence=[f"web_accessible_resources: {resources[:8]}"],
                file=rel,
                remediation="Migrate to Manifest V3, which supports per-origin scoping via 'matches'. In the meantime, list only the minimum resources actually needed, and never list pages that handle postMessage without strict origin checks.",
                verification=Verification(
                    title="Confirm what's actually exposed",
                    steps=["List manifest.json's web_accessible_resources.",
                           "For each entry, open chrome-extension://<extension-id>/<resource> directly in a browser tab from outside the extension and confirm what loads."],
                ),
            ))
            return

        if isinstance(war, list):
            for entry in war:
                if not isinstance(entry, dict):
                    continue
                resources = [r for r in entry.get("resources", []) or [] if isinstance(r, str)]
                matches = entry.get("matches", []) or []
                if not resources:
                    continue
                wildcard_origin = any(p in HOST_WILDCARD_PATTERNS for p in matches)
                wildcard_resource = any(r.strip() in ("*", "**/*") for r in resources)
                sensitive = [r for r in resources if SENSITIVE_RESOURCE_RE.search(r)]

                if wildcard_origin or wildcard_resource:
                    self._add(Finding(
                        id="MANDEC-WAR-WILDCARD",
                        title=f"web_accessible_resources exposed to all origins ({len(resources)} resource(s))",
                        category="E11",
                        skill_name=self.SKILL_NAME, skill_type=self.SKILL_TYPE,
                        description="A web_accessible_resources entry matches every website (wildcard 'matches') or exposes every file in a directory (wildcard 'resources').",
                        technical_detail="Any page on any site can load these resources via chrome-extension://<id>/<path>. If any exposed HTML page receives postMessage without a strict origin check, this is a direct path for a malicious website to reach extension-privileged code.",
                        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H" if sensitive else "L", I="L", A="N"),
                        evidence=[f"matches: {matches}", f"resources: {resources[:8]}"],
                        file=rel,
                        remediation="Scope 'matches' to the specific origins that legitimately need this resource, and list only the specific files required -- never a wildcard.",
                    ))
                elif resources:
                    self._add(Finding(
                        id="MANDEC-WAR-SCOPED",
                        title=f"web_accessible_resources exposes {len(resources)} resource(s) to {len(matches)} origin(s)",
                        category="E11",
                        skill_name=self.SKILL_NAME, skill_type=self.SKILL_TYPE,
                        description="Resources are exposed to specific origins rather than everyone -- lower risk, but still worth confirming the scope is intentional.",
                        technical_detail="Anything listed here is fetchable by the matched origins via chrome-extension://<id>/<path>, bypassing the extension's own access controls for that file.",
                        cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="C", C="L", I="N", A="N"),
                        evidence=[f"matches: {matches}", f"resources: {resources[:8]}"],
                        file=rel,
                        remediation="Confirm every matched origin is one this extension actually needs to share resources with.",
                    ))

                if sensitive:
                    self._add(Finding(
                        id="MANDEC-WAR-SENSITIVE-FILE",
                        title=f"Sensitive-looking file(s) exposed via web_accessible_resources",
                        category="E11",
                        skill_name=self.SKILL_NAME, skill_type=self.SKILL_TYPE,
                        description=f"File(s) matching credential/config/database naming patterns are listed as web-accessible: {', '.join(sensitive)}.",
                        technical_detail="If any of these actually contain secrets, keys, or a local database, they become readable by whatever origins this entry matches.",
                        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="N", A="N"),
                        evidence=sensitive,
                        file=rel,
                        remediation="Remove sensitive files from web_accessible_resources entirely -- they should never need to be web-reachable. Store secrets server-side instead.",
                    ))

    def _check_optional_permission_ratchet(self, m: dict, rel: str) -> None:
        optional_perms = set(m.get("optional_permissions", []) or [])
        optional_hosts = set(m.get("optional_host_permissions", []) or [])
        risky_optional = optional_perms & (set(HIGH_RISK_PERMISSIONS) | set(MEDIUM_RISK_PERMISSIONS))
        wildcard_optional_host = any(p in HOST_WILDCARD_PATTERNS for p in optional_hosts)

        if risky_optional or wildcard_optional_host:
            self._add(Finding(
                id="MANDEC-OPTIONAL-PERMISSION-RATCHET",
                title="Sensitive permission(s) requested at runtime instead of install time",
                category="E11",
                skill_name=self.SKILL_NAME, skill_type=self.SKILL_TYPE,
                description=f"optional_permissions/optional_host_permissions includes: {', '.join(sorted(risky_optional)) or '<all_urls>-equivalent host access'}.",
                technical_detail="Requesting sensitive capability via optional_permissions instead of the install-time permissions list is a documented technique for keeping the install-time manifest looking minimal (which gets lighter store scrutiny and a less alarming permission prompt) and then asking for the real capability later, after install, when fewer reviewers and users are paying attention.",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="H", I="L", A="N"),
                evidence=[f"optional_permissions: {sorted(optional_perms)}", f"optional_host_permissions: {sorted(optional_hosts)}"],
                file=rel,
                remediation="If this capability is core to the extension's function, declare it as a normal install-time permission so it's visible up front. Reserve optional_permissions for genuinely optional features.",
                verification=Verification(
                    title="Check when the permission is actually requested",
                    steps=["Search the source for chrome.permissions.request() and confirm what triggers it and how soon after install."],
                ),
            ))

    def _check_permission_code_mismatch(self, m: dict, rel: str, js_text: str) -> None:
        perms = set(m.get("permissions", []) or [])
        host_perms = set(m.get("host_permissions", []) or [])
        optional_perms = set(m.get("optional_permissions", []) or [])
        combined = perms | host_perms
        sensitive_combined = combined & set(PERMISSION_API_PATTERNS)

        for perm in sorted(sensitive_combined):
            pattern = PERMISSION_API_PATTERNS[perm]
            if not pattern.search(js_text):
                self._add(Finding(
                    id=f"MANDEC-UNUSED-PERMISSION-{perm.upper()}",
                    title=f"Permission '{perm}' declared but no matching API usage found in visible source",
                    category="E11",
                    skill_name=self.SKILL_NAME, skill_type=self.SKILL_TYPE,
                    description=f"The manifest declares '{perm}', but no call matching its known API surface was found anywhere in the scanned JS.",
                    technical_detail="This is a heuristic, not proof of absence -- the API could be called via dynamic property access, from a file type this scanner doesn't parse, or behind a feature flag. But an unused sensitive permission is also exactly what a reserved-for-later capability looks like: declared now, quietly activated in a future update that gets less scrutiny than the initial listing.",
                    cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                    evidence=[f"'{perm}' declared; no match for its known API pattern in scanned source"],
                    file=rel,
                    remediation=f"If '{perm}' isn't currently used, remove it until it is. If it's used somewhere this scanner can't see, that's worth documenting.",
                ))

        for perm, pattern in PERMISSION_API_PATTERNS.items():
            if perm in combined or perm in optional_perms:
                continue
            match = pattern.search(js_text)
            if match:
                self._add(Finding(
                    id=f"MANDEC-UNDECLARED-API-{perm.upper()}",
                    title=f"Code references a '{perm}' API but the permission isn't declared",
                    category="E11",
                    skill_name=self.SKILL_NAME, skill_type=self.SKILL_TYPE,
                    description=f"Source code calls an API associated with the '{perm}' permission, which is neither in permissions/host_permissions nor optional_permissions.",
                    technical_detail="Most likely this is dead code (a leftover call that will throw at runtime) or a permission that should have been declared but wasn't. Either way, the manifest's permission list doesn't fully describe what the code attempts to do.",
                    cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="N", I="N", A="N"),
                    evidence=[match.group(0)],
                    file=rel,
                    remediation="Confirm whether this call path is reachable. If it is, declare the permission (or move it to optional_permissions and request it explicitly). If it's dead code, remove it.",
                ))

    def _check_fixed_key(self, m: dict, rel: str) -> None:
        if m.get("key"):
            self._add(Finding(
                id="MANDEC-FIXED-KEY",
                title="Manifest pins a fixed extension ID via the 'key' field",
                category="E11",
                skill_name=self.SKILL_NAME, skill_type=self.SKILL_TYPE,
                description="The manifest includes a 'key' field, which forces this extension to have a specific, predetermined extension ID rather than one derived normally.",
                technical_detail="This is normal during development (to get a stable ID before publishing), but in a shipped extension it's also how an attacker pins their extension's ID to match one that's allowlisted elsewhere -- e.g. in another extension's externally_connectable.ids, or in a native messaging host's allowed-origins list.",
                cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="L", A="N"),
                evidence=["'key' field present in manifest.json"],
                file=rel,
                remediation="Confirm this is a deliberate, documented choice (e.g. enterprise-managed deployment) and not an attempt to match a specific allowlisted ID elsewhere.",
                verification=Verification(
                    title="Check what ID this produces",
                    steps=["Load the extension unpacked in chrome://extensions and note the extension ID.",
                           "Search for that exact ID in any other extension's externally_connectable.ids or in native messaging host manifests you have access to."],
                ),
            ))

    def _check_devtools_page(self, m: dict, rel: str) -> None:
        if m.get("devtools_page"):
            self._add(Finding(
                id="MANDEC-DEVTOOLS-PAGE",
                title="devtools_page declared",
                category="E11",
                skill_name=self.SKILL_NAME, skill_type=self.SKILL_TYPE,
                description="The extension registers a DevTools page.",
                technical_detail="DevTools pages can inspect the network requests, DOM, and resources of whatever page the developer has open in DevTools -- broad capability that's rarely needed outside genuine developer-tooling extensions.",
                cvss=CVSSVector(AV="L", AC="H", PR="N", UI="R", S="U", C="L", I="N", A="N"),
                evidence=["'devtools_page' present in manifest.json"],
                file=rel,
                remediation="Confirm this extension's stated purpose is developer tooling. If not, this is worth asking about.",
            ))

    def _check_frame_injection_trick(self, m: dict, rel: str) -> None:
        for i, cs in enumerate(m.get("content_scripts", []) or []):
            if cs.get("match_about_blank") and cs.get("all_frames"):
                self._add(Finding(
                    id="MANDEC-FRAME-INJECTION-TRICK",
                    title="content_scripts entry injects into about:blank AND all frames",
                    category="E11",
                    skill_name=self.SKILL_NAME, skill_type=self.SKILL_TYPE,
                    description=f"content_scripts[{i}] sets both match_about_blank and all_frames.",
                    technical_detail="This combination ensures the content script also runs inside about:blank iframes (often used for sandboxed widgets, ads, or payment forms) in addition to every regular frame on the page -- a broader injection surface than most legitimate use cases need, and one that's harder for a page author to defend against since about:blank frames don't always go through the same CSP as the parent.",
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="L", A="N"),
                    evidence=[f"content_scripts[{i}]: match_about_blank=true, all_frames=true"],
                    file=rel,
                    remediation="Confirm injecting into about:blank frames is actually required. If not, remove match_about_blank.",
                ))

    def _check_name_impersonation(self, m: dict, rel: str) -> None:
        name = str(m.get("name", "")).strip()
        if not name or name.startswith("__MSG_"):
            return
        normalized = _normalize_name(name)
        if not normalized:
            return
        for popular in POPULAR_EXTENSION_NAMES:
            norm_popular = _normalize_name(popular)
            if normalized == norm_popular:
                # Identical after case/punctuation normalization but not a literal string match --
                # e.g. "Lastpass" vs "LastPass". Worth flagging: exact-name copies of popular
                # extensions are a real impersonation pattern, not just close-typo squatting.
                exact_but_not_literal = name != popular
                self._add(Finding(
                    id="MANDEC-NAME-IMPERSONATION",
                    title=f"Extension name exactly matches well-known extension '{popular}'",
                    category="E11",
                    skill_name=self.SKILL_NAME, skill_type=self.SKILL_TYPE,
                    description=f"'{name}' is name-identical (case/punctuation aside) to the well-known extension '{popular}'.",
                    technical_detail="This scanner has no way to verify whether this is the genuine extension or a same-named copy -- that requires checking the actual store listing/publisher, not the manifest. Flagged here because exact-name copies of popular extensions are a real, documented impersonation pattern, not just a coincidence to wave off.",
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="L", A="N"),
                    evidence=[f"manifest name: '{name}'  vs. known extension: '{popular}'"],
                    file=rel,
                    remediation="Verify this extension's publisher/source against the official listing for the genuine extension before trusting it.",
                ))
                return
            dist = _levenshtein(normalized, norm_popular)
            if 1 <= dist <= 2 and abs(len(normalized) - len(norm_popular)) <= 3:
                self._add(Finding(
                    id="MANDEC-NAME-IMPERSONATION",
                    title=f"Extension name is suspiciously similar to '{popular}'",
                    category="E11",
                    skill_name=self.SKILL_NAME, skill_type=self.SKILL_TYPE,
                    description=f"'{name}' differs from the well-known extension '{popular}' by only a small edit distance.",
                    technical_detail="This is exactly the naming pattern used by copycat/impersonation extensions trying to look like a trusted, popular one in store search results. It is also exactly what happens by coincidence with short, common, or genuinely similar product names -- this finding only means 'verify, don't assume.'",
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="L", A="N"),
                    evidence=[f"manifest name: '{name}'  vs. known extension: '{popular}'  (edit distance {dist})"],
                    file=rel,
                    remediation="Confirm this is the genuine, intentionally-named extension and not a copycat. If you're the developer and this is a coincidence, consider how distinct your listing is from the more popular one.",
                ))
                return  # one hit is enough; don't pile on for every close popular name

    def _check_unknown_keys(self, m: dict, rel: str) -> None:
        unknown = sorted(set(m.keys()) - STANDARD_MANIFEST_KEYS)
        # Locale-style keys and underscore-prefixed private keys are common and benign.
        unknown = [k for k in unknown if not k.startswith("_")]
        if unknown:
            self._add(Finding(
                id="MANDEC-UNKNOWN-MANIFEST-KEY",
                title=f"Non-standard manifest key(s): {', '.join(unknown)}",
                category="E11",
                skill_name=self.SKILL_NAME, skill_type=self.SKILL_TYPE,
                description=f"manifest.json contains key(s) not in the standard Chrome/Firefox manifest schema: {', '.join(unknown)}.",
                technical_detail="Often this is harmless -- a build tool artifact, a forward-looking field from a newer spec, or a vendor-specific extension. Occasionally it's a leftover debug flag or a custom field whose purpose isn't documented anywhere. Worth a quick look since it's outside what this scanner (or the browser) treats as meaningful.",
                cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="N", I="N", A="N"),
                evidence=unknown,
                file=rel,
                remediation="Confirm the purpose of each non-standard key. Remove build-tool leftovers before shipping.",
            ))
