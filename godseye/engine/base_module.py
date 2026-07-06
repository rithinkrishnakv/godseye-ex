"""
engine/base_module.py

Every analysis module is a small, isolated class: it gets a read-only
AnalysisContext and returns a list of Finding objects. No module ever
writes files, makes network calls, or executes anything from the target
extension -- that invariant is what keeps this a static-analysis tool.

Modules that need to find text patterns in source declare their patterns
as RULE_SPECS (engine.tokenizer.RuleSpec). The loader collects RULE_SPECS
from every registered module and tokenizes each file exactly once before
any module runs; modules then read pre-computed matches via
`ctx.index.get(rule_id)` instead of looping over files and calling
`pattern.finditer()` themselves. Modules with no text patterns (e.g. ones
that only read manifest.json) simply leave RULE_SPECS empty.
"""

from __future__ import annotations
from abc import ABC, abstractmethod

from ..models import Finding, SkillType
from .loader import AnalysisContext
from .tokenizer import RuleSpec


class BaseModule(ABC):
    SKILL_NAME: str = "Unnamed Skill"
    SKILL_TYPE: SkillType = SkillType.ACTIVE
    CATEGORY: str = "E0"
    DESCRIPTION: str = ""
    RULE_SPECS: list[RuleSpec] = []

    def __init__(self) -> None:
        self._findings: list[Finding] = []

    def _add(self, finding: Finding) -> None:
        self._findings.append(finding)

    @abstractmethod
    def run(self, ctx: AnalysisContext) -> list[Finding]:
        ...
