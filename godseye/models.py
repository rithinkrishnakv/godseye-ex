"""
models.py -- core data types shared across every GODSEYE: EX module.

Includes a standard CVSS v3.1 base-score implementation (the published
FIRST.org formula) so every finding gets an objective, comparable score
instead of an author's gut feeling.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
import math


class SkillType(str, Enum):
    PASSIVE = "PASSIVE"   # reads the manifest only
    ACTIVE = "ACTIVE"     # scans source for risky patterns
    UNIQUE = "UNIQUE"     # cross-references external knowledge (known-vulnerable libs, etc.)
    HIDDEN = "HIDDEN"     # supply-chain / indirect surface, easy to miss in manual review


# ---------------------------------------------------------------------------
# CVSS v3.1 base score (FIRST.org published formula)
# ---------------------------------------------------------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}


@dataclass(frozen=True)
class CVSSVector:
    AV: str  # Attack Vector: N/A/L/P
    AC: str  # Attack Complexity: L/H
    PR: str  # Privileges Required: N/L/H
    UI: str  # User Interaction: N/R
    S: str   # Scope: U/C
    C: str   # Confidentiality impact: N/L/H
    I: str   # Integrity impact: N/L/H
    A: str   # Availability impact: N/L/H

    def base_score(self) -> float:
        pr_table = _PR_CHANGED if self.S == "C" else _PR_UNCHANGED
        exploitability = 8.22 * _AV[self.AV] * _AC[self.AC] * pr_table[self.PR] * _UI[self.UI]

        isc_base = 1 - ((1 - _CIA[self.C]) * (1 - _CIA[self.I]) * (1 - _CIA[self.A]))
        if self.S == "U":
            impact = 6.42 * isc_base
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15

        if impact <= 0:
            return 0.0

        raw = (impact + exploitability) if self.S == "U" else 1.08 * (impact + exploitability)
        return math.ceil(min(raw, 10.0) * 10) / 10

    def vector_string(self) -> str:
        return f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}/UI:{self.UI}/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}"


# ---------------------------------------------------------------------------
# Rank system -- same F -> SSS scale used in earlier appraisal-style tools,
# driven purely by the CVSS base score (and a chain/supply-chain escalation
# flag), not by anything execution-derived.
# ---------------------------------------------------------------------------

RANK_TABLE = [
    (0.0, "F", "Informational"),
    (3.0, "D", "Hardening"),
    (5.0, "C", "Low"),
    (7.0, "B", "Medium"),
    (9.0, "A", "High"),
    (9.5, "S", "Critical"),
    (10.0, "SS", "Devastating"),
]


def rank_for_score(cvss_score: float, is_chain: bool = False, is_extinction: bool = False) -> tuple[str, str]:
    if is_extinction:
        return "SSS", "Extinction"
    if is_chain and cvss_score >= 9.0:
        return "SS", "Devastating"
    rank, label = "F", "Informational"
    for threshold, r, l in RANK_TABLE:
        if cvss_score >= threshold:
            rank, label = r, l
    return rank, label


@dataclass
class Verification:
    """
    A benign, non-weaponized way for a reviewer to confirm a finding is real.
    Deliberately NOT an exploit: no payload delivery, no bypass of a security
    control, no data exfiltration. Things like "open chrome://extensions and
    check X" or a read-only grep/console probe belong here.
    """
    title: str
    steps: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class Finding:
    id: str
    title: str
    category: str          # one of the Extension Security Top 10 codes, e.g. "E2"
    skill_name: str
    skill_type: SkillType
    description: str
    technical_detail: str
    cvss: CVSSVector
    evidence: list[str] = field(default_factory=list)
    file: str = ""
    line: int = 1
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    verification: Verification | None = None
    chain_ids: list[str] = field(default_factory=list)   # populated if part of a detected chain
    is_chain_finding: bool = False
    is_extinction: bool = False
    occurrence_count: int = 1
    all_lines: list[int] = field(default_factory=list)
    context: list[tuple[int, str]] = field(default_factory=list)
    context: list[tuple[int, str]] = field(default_factory=list)  # (line_no, line_text) snippet around the hit

    @property
    def score(self) -> float:
        return self.cvss.base_score()

    @property
    def rank(self) -> str:
        r, _ = rank_for_score(self.score, is_chain=self.is_chain_finding, is_extinction=self.is_extinction)
        return r

    @property
    def rank_label(self) -> str:
        _, label = rank_for_score(self.score, is_chain=self.is_chain_finding, is_extinction=self.is_extinction)
        return label


@dataclass
class AppraisalResult:
    target: str
    extension_name: str
    extension_version: str
    manifest_version: int | None
    findings: list[Finding] = field(default_factory=list)
    modules_run: list[str] = field(default_factory=list)
    modules_skipped: list[str] = field(default_factory=list)
    vendor_files: list[str] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        rank_order = {"SSS": 0, "SS": 1, "S": 2, "A": 3, "B": 4, "C": 5, "D": 6, "F": 7}
        return sorted(self.findings, key=lambda f: (rank_order.get(f.rank, 8), -f.score))

    def overall_grade(self) -> str:
        if not self.findings:
            return "A+"
        worst = self.sorted_findings()[0]
        return worst.rank
