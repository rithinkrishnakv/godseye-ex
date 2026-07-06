"""
modules/manifest_module.py

[PASSIVE] Manifest Sight
Reads manifest.json only. Covers:
  E1 - Overprivileged Permissions & Host Access
  E9 - Update & Distribution Integrity

Each permission has its OWN CVSS vector tuned to what it actually enables
(clipboardRead is a credential-theft vector; history is privacy-only --
they are not the same risk, so they no longer share one flattened score).
"""

from __future__ import annotations
from typing import Any

from ..models import Finding, CVSSVector, SkillType, Verification
from ..engine.base_module import BaseModule
from ..engine.loader import AnalysisContext

HOST_WILDCARD_PATTERNS = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*")
SENSITIVE_PERMISSION_SURFACE_THRESHOLD = 3

# perm -> (why, tuned CVSS vector)
HIGH_RISK_PERMISSIONS: dict[str, tuple[str, CVSSVector]] = {
    "nativeMessaging": (
        "Allows the extension to exchange arbitrary messages with a native binary on the host OS, escaping the browser sandbox entirely.",
        CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="L", A="N"),
    ),
    "debugger": (
        "Grants access to the Chrome DevTools Protocol for any tab -- effectively full read/write over page content, JS execution, and network traffic.",
        CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
    ),
    "proxy": (
        "Lets the extension redirect, intercept, or block all network traffic for the browser -- a full MitM position.",
        CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
    ),
    "webRequestBlocking": (
        "Allows synchronous interception and modification of every network request before it's sent.",
        CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
    ),
}

MEDIUM_RISK_PERMISSIONS: dict[str, tuple[str, CVSSVector]] = {
    "scripting": (
        "Can inject arbitrary JS/CSS into pages.",
        CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="H", A="N"),
    ),
    "clipboardRead": (
        "Can read clipboard contents -- a common destination for copied passwords, OTP codes, and crypto wallet seed phrases. Closer to an immediate credential-theft vector than a privacy concern.",
        CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    ),
    "cookies": (
        "Can read and write cookies for any host it has access to -- including session cookies, enabling session hijacking.",
        CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="L", A="N"),
    ),
    "management": (
        "Can enumerate, enable, or disable other installed extensions -- including security-relevant ones.",
        CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="H", A="N"),
    ),
    "tabs": (
        "Can read URLs, titles, and metadata for all open tabs.",
        CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
    ),
    "history": (
        "Can read the user's full browsing history -- a privacy concern, but read-only and not itself a credential/session vector.",
        CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
    ),
    "webRequest": (
        "Can observe network request metadata for every request.",
        CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
    ),
    "declarativeNetRequest": (
        "Can rewrite or block network requests via static/dynamic rules.",
        CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="L", A="N"),
    ),
    "downloads": (
        "Can initiate and manage file downloads, writing files to disk.",
        CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="L", A="N"),
    ),
    "clipboardWrite": (
        "Can write to the clipboard -- usable for clipboard-hijacking attacks (e.g. silently replacing a copied crypto address).",
        CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="L", A="N"),
    ),
    "geolocation": (
        "Can access the user's physical location.",
        CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    ),
    "storage": (
        "Can persist arbitrary local/sync data. Low risk on its own -- Credential & Storage Sight flags what's actually stored in it.",
        CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="N"),
    ),
}


def _match_patterns(manifest: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key in ("host_permissions", "permissions"):
        out.extend(p for p in manifest.get(key, []) or [] if isinstance(p, str) and ("://" in p or p == "<all_urls>"))
    for cs in manifest.get("content_scripts", []) or []:
        out.extend(cs.get("matches", []) or [])
    return out


class ManifestSightModule(BaseModule):
    SKILL_NAME = "Manifest Sight"
    SKILL_TYPE = SkillType.PASSIVE
    CATEGORY = "E1"
    DESCRIPTION = "Permission, host-access, CSP, and update-integrity risk in manifest.json"

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        self._findings = []
        m = ctx.manifest
        rel = ctx.manifest_path.name

        perms = set(m.get("permissions", []) or [])
        host_perms = set(m.get("host_permissions", []) or [])
        combined = perms | host_perms

        sensitive_hits: list[str] = []

        for perm, (why, vector) in HIGH_RISK_PERMISSIONS.items():
            if perm in combined:
                sensitive_hits.append(perm)
                self._add(Finding(
                    id=f"MANIFEST-PERM-{perm.upper()}",
                    title=f"High-impact permission declared: {perm}",
                    category="E1",
                    skill_name=self.SKILL_NAME,
                    skill_type=self.SKILL_TYPE,
                    description=f"The manifest requests '{perm}', one of the highest-impact permissions available to an extension.",
                    technical_detail=why,
                    cvss=vector,
                    evidence=[f'"{perm}" present in permissions array'],
                    file=rel,
                    remediation=f"Confirm '{perm}' is strictly necessary for core functionality; if not, remove it. If it is, document why in your store listing and privacy policy.",
                    references=["https://developer.chrome.com/docs/extensions/reference/permissions-list"],
                    verification=Verification(
                        title="Confirm the permission is actually declared",
                        steps=[
                            "Open chrome://extensions, enable Developer Mode, and click 'Details' on the extension.",
                            f"Check the 'Permissions' section for '{perm}'.",
                        ],
                    ),
                ))

        for perm, (why, vector) in MEDIUM_RISK_PERMISSIONS.items():
            if perm in combined:
                sensitive_hits.append(perm)
                self._add(Finding(
                    id=f"MANIFEST-PERM-{perm.upper()}",
                    title=f"Sensitive permission declared: {perm}",
                    category="E1",
                    skill_name=self.SKILL_NAME,
                    skill_type=self.SKILL_TYPE,
                    description=f"The manifest requests '{perm}'.",
                    technical_detail=why,
                    cvss=vector,
                    evidence=[f'"{perm}" present in permissions array'],
                    file=rel,
                    remediation=f"Scope usage of '{perm}' as narrowly as the API allows (e.g. activeTab instead of tabs where possible).",
                    verification=Verification(
                        title="Confirm the permission is actually declared",
                        steps=[f"Check manifest.json's permissions array for '{perm}'."],
                    ),
                ))

        if len(sensitive_hits) >= SENSITIVE_PERMISSION_SURFACE_THRESHOLD:
            self._add(Finding(
                id="MANIFEST-BROAD-PERMISSION-SURFACE",
                title=f"Broad permission surface ({len(sensitive_hits)} sensitive permissions)",
                category="E1",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description=f"{len(sensitive_hits)} sensitive permissions declared together: {', '.join(sorted(sensitive_hits))}.",
                technical_detail="No single pairwise permission combo may stand out, but three or more sensitive permissions together amount to a broad data-collection/control surface -- and, combined with any code-level sink elsewhere in this report, a much more reachable one. This finding exists specifically so that breadth of access doesn't go unscored just because it doesn't match one specific named combo.",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="L", A="N"),
                evidence=[f"sensitive permissions: {', '.join(sorted(sensitive_hits))}"],
                file=rel,
                remediation="Review whether every one of these permissions is load-bearing for the extension's stated purpose. Drop what isn't; disclose what is.",
            ))

        if any(p in HOST_WILDCARD_PATTERNS for p in _match_patterns(m)):
            self._add(Finding(
                id="MANIFEST-HOST-WILDCARD",
                title="Unrestricted host access (<all_urls> or equivalent)",
                category="E1",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description="The extension (via host_permissions or a content script match pattern) can run on every site the user visits.",
                technical_detail="Wildcard host access means any bug elsewhere in the extension (an injection flaw, an unvalidated message handler) is reachable from literally any website, including a malicious one.",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="L", A="N"),
                evidence=["Wildcard match pattern found in host_permissions / content_scripts"],
                file=rel,
                remediation="Replace wildcard matches with the specific domains the extension needs to function on.",
                verification=Verification(
                    title="Confirm host scope",
                    steps=["Check host_permissions and every content_scripts[].matches array in manifest.json."],
                ),
            ))

        self._check_csp(m, rel)
        self._check_externally_connectable(m, rel)
        self._check_update_integrity(m, rel)

        if m.get("manifest_version") == 2:
            self._add(Finding(
                id="MANIFEST-MV2",
                title="Manifest V2 (deprecated)",
                category="E9",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description="This extension uses Manifest V2, which Chrome is phasing out.",
                technical_detail="MV2 lacks several MV3 hardening defaults, including tighter remote-code restrictions on background pages.",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="N"),
                evidence=['"manifest_version": 2'],
                file=rel,
                remediation="Plan a migration to Manifest V3.",
            ))

        return self._findings

    def _check_csp(self, m: dict, rel: str) -> None:
        csp = m.get("content_security_policy")
        csp_str = csp if isinstance(csp, str) else " ".join(str(v) for v in (csp or {}).values())

        if "unsafe-eval" in csp_str:
            self._add(Finding(
                id="MANIFEST-CSP-UNSAFE-EVAL",
                title="CSP permits 'unsafe-eval'",
                category="E4",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description="The declared content_security_policy allows eval()-style dynamic code execution.",
                technical_detail="This removes one of the platform's strongest built-in defenses against script-injection turning into code execution inside the extension's privileged context.",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="L", A="N"),
                evidence=["'unsafe-eval' present in content_security_policy"],
                file=rel,
                remediation="Remove 'unsafe-eval' and refactor any code relying on eval()/new Function().",
            ))
        if "unsafe-inline" in csp_str:
            self._add(Finding(
                id="MANIFEST-CSP-UNSAFE-INLINE",
                title="CSP permits 'unsafe-inline'",
                category="E4",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description="Inline scripts/styles are allowed by the declared CSP.",
                technical_detail="Weakens protection against injected markup turning into executing script.",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"),
                evidence=["'unsafe-inline' present in content_security_policy"],
                file=rel,
                remediation="Move inline scripts/styles to external files and drop 'unsafe-inline'.",
            ))

    def _check_externally_connectable(self, m: dict, rel: str) -> None:
        ec = m.get("externally_connectable")
        if not ec:
            return
        ids = ec.get("ids", [])
        matches = ec.get("matches", [])
        if "*" in ids:
            self._add(Finding(
                id="MANIFEST-EXTCONN-WILDCARD-IDS",
                title="externally_connectable.ids allows '*'",
                category="E2",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description="Any other installed extension can message this one directly.",
                technical_detail="chrome.runtime.sendMessage from an arbitrary extension ID will reach this extension's onMessageExternal handlers.",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="L", I="L", A="N"),
                evidence=['"ids": ["*"] in externally_connectable'],
                file=rel,
                remediation="Restrict 'ids' to the specific extension IDs that legitimately need access.",
            ))
        if any(p in HOST_WILDCARD_PATTERNS for p in matches):
            self._add(Finding(
                id="MANIFEST-EXTCONN-WILDCARD-MATCHES",
                title="externally_connectable.matches is unrestricted",
                category="E2",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description="Any website can message this extension directly.",
                technical_detail="window.postMessage-style external messaging from any origin reaches this extension's external message handlers.",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"),
                evidence=["Wildcard match in externally_connectable.matches"],
                file=rel,
                remediation="Scope 'matches' to specific trusted origins only.",
            ))

    def _check_update_integrity(self, m: dict, rel: str) -> None:
        update_url = m.get("update_url")
        if update_url and "clients2.google.com" not in update_url and "addons.mozilla.org" not in update_url:
            self._add(Finding(
                id="MANIFEST-CUSTOM-UPDATE-URL",
                title="Custom update_url (self-hosted updates)",
                category="E9",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description=f"Extension updates are served from a non-store URL: {update_url}",
                technical_detail="If that update server or its DNS/TLS is ever compromised, every install of this extension can be pushed a malicious update -- a single point of supply-chain failure outside the store's review process.",
                cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="C", C="H", I="H", A="N"),
                evidence=[f'"update_url": "{update_url}"'],
                file=rel,
                remediation="Distribute through the Chrome Web Store / addons.mozilla.org where possible; if self-hosting is required, enforce TLS, signed update manifests, and tight access control on the update server.",
            ))
