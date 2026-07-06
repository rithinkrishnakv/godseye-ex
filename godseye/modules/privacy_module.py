"""
modules/privacy_module.py

[PASSIVE] Privacy Sentinel
Covers E8 - Privacy & Data Handling.
Looks at permission *combinations* that together amount to broad
surveillance capability, even if each permission looks reasonable alone.
"""

from __future__ import annotations

from ..models import Finding, CVSSVector, SkillType
from ..engine.base_module import BaseModule
from ..engine.loader import AnalysisContext

SURVEILLANCE_COMBOS = [
    (
        {"tabs", "webRequest"},
        "TABS+WEBREQUEST",
        "tabs + webRequest together",
        "tabs gives URLs/titles for every open tab; webRequest adds full request/response metadata for every network request. Combined, the extension can build a complete browsing profile.",
    ),
    (
        {"tabs", "history"},
        "TABS+HISTORY",
        "tabs + history together",
        "Live tab state plus full navigation history gives near-complete visibility into a user's browsing behavior, past and present.",
    ),
    (
        {"clipboardRead", "tabs"},
        "CLIPBOARD+TABS",
        "clipboardRead + tabs together",
        "Clipboard contents combined with knowledge of which site is active lets an extension correlate copied data (often credentials or codes) with the page it was copied from.",
    ),
]


class PrivacySentinelModule(BaseModule):
    SKILL_NAME = "Privacy Sentinel"
    SKILL_TYPE = SkillType.PASSIVE
    CATEGORY = "E8"
    DESCRIPTION = "Permission combinations that add up to broad data-collection capability"

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        self._findings = []
        perms = set(ctx.manifest.get("permissions", []) or [])

        for required, suffix, label, why in SURVEILLANCE_COMBOS:
            if required.issubset(perms):
                self._add(Finding(
                    id=f"PRIVACY-COMBO-{suffix}",
                    title=f"Privacy-sensitive permission combination: {label}",
                    category="E8",
                    skill_name=self.SKILL_NAME,
                    skill_type=self.SKILL_TYPE,
                    description=f"The manifest declares {label}.",
                    technical_detail=why,
                    cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                    evidence=[f"permissions include: {', '.join(sorted(required))}"],
                    file=ctx.manifest_path.name,
                    remediation="If this data collection isn't core to the extension's stated purpose, drop one of the permissions. If it is, disclose the combination explicitly in the privacy policy.",
                ))

        if "geolocation" in perms:
            self._add(Finding(
                id="PRIVACY-GEOLOCATION",
                title="geolocation permission declared",
                category="E8",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description="The extension can access the user's physical location.",
                technical_detail="One of the most sensitive permissions available; store policies generally require a clear, specific justification.",
                cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
                evidence=['"geolocation" in permissions'],
                file=ctx.manifest_path.name,
                remediation="Confirm geolocation is essential to core functionality and disclosed clearly to the user at the point of use.",
            ))

        return self._findings
