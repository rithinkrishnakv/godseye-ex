"""
modules/taint_module.py

[UNIQUE] Taint Analysis Engine
Covers E17 - Data-Flow / Source-to-Sink Taint Flows.

Two analyses in one module because they share the same infrastructure:

1. INTRA-BLOCK TAINT TRACING
   Uses the resolved handler bodies from the tokenizer (span.block) to
   check whether untrusted data from known sources (message payloads,
   URL params, storage reads) flows into dangerous sinks (innerHTML, eval,
   executeScript) within the same handler without a sanitizer in between.

2. CROSS-CONTEXT BRIDGE MATRIX
   Reads the manifest to classify every file by context (content script,
   background, popup), then maps message send/receive patterns to build
   privilege-escalation chain evidence: web page → content script →
   background handler → privileged API.
"""

from __future__ import annotations
import re

from ..models import Finding, CVSSVector, SkillType, Verification
from ..engine.base_module import BaseModule
from ..engine.loader import AnalysisContext
from ..engine.tokenizer import RuleSpec, FileScope, Resolution
from ..engine.taint_tracer import trace_block, TaintFlow
from ..engine.context_bridge import analyze_bridge, classify_files
from ..engine.snippet import extract_snippet

# Anchor rules whose resolved blocks feed the taint tracer.
# We reuse the blocks already resolved by the Messaging Sentinel's rules.
ANCHOR_RULES: list[RuleSpec] = [
    RuleSpec("TAINT-ANCHOR-ON-MESSAGE", re.compile(r"chrome\.runtime\.onMessage(?:External)?\.addListener"),
             scope=FileScope.JS_NONVENDOR, resolution=Resolution.BLOCK),
    RuleSpec("TAINT-ANCHOR-POSTMESSAGE", re.compile(r'addEventListener\s*\(\s*[\'"]message[\'"]'),
             scope=FileScope.JS_NONVENDOR, resolution=Resolution.BLOCK),
    RuleSpec("TAINT-ANCHOR-FETCH-THEN", re.compile(r'\.then\s*\('),
             scope=FileScope.JS_NONVENDOR, resolution=Resolution.BLOCK),
]

RULE_SPECS: list[RuleSpec] = ANCHOR_RULES

# CVSS per taint flow type
_TAINT_CVSS = {
    "TAINT-DOM-XSS":          CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N"),
    "TAINT-EVAL-SINK":        CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"),
    "TAINT-EXEC-SCRIPT-SINK": CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N"),
    "TAINT-DOCUMENT-WRITE":   CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="L", A="N"),
    "TAINT-SCRIPT-SRC":       CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N"),
    "TAINT-OPEN-REDIRECT":    CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="L", I="L", A="N"),
    "TAINT-NATIVE-MSG":       CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
}
_DEFAULT_CVSS = CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="H", I="H", A="N")

_BRIDGE_CVSS = {
    "content→background":  CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N"),
    "popup→background":    CVSSVector(AV="N", AC="H", PR="N", UI="R", S="U", C="H", I="L", A="N"),
}


class TaintAnalysisEngineModule(BaseModule):
    SKILL_NAME = "Taint Analysis Engine"
    SKILL_TYPE = SkillType.UNIQUE
    CATEGORY = "E17"
    DESCRIPTION = "Source-to-sink data-flow tracing and cross-context privilege escalation matrix"
    RULE_SPECS = RULE_SPECS

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        self._findings = []
        self._run_taint_tracer(ctx)
        self._run_bridge_matrix(ctx)
        return self._findings

    # ── 1. Intra-block taint tracing ─────────────────────────────────────────

    def _run_taint_tracer(self, ctx: AnalysisContext) -> None:
        seen: set[tuple[str, str, int, int]] = set()

        for rule_id in ("TAINT-ANCHOR-ON-MESSAGE", "TAINT-ANCHOR-POSTMESSAGE", "TAINT-ANCHOR-FETCH-THEN"):
            for span in ctx.index.get(rule_id):
                if span.block is None:
                    continue
                flows: list[TaintFlow] = trace_block(
                    span.block.text,
                    span.file,
                    span.block.start_line,
                )
                for flow in flows:
                    if flow.sanitized:
                        continue  # sanitizer present -- don't surface
                    key = (flow.rule_id, flow.file, flow.source_line, flow.sink_line)
                    if key in seen:
                        continue
                    seen.add(key)
                    text = ctx.index.file_text(span.file)
                    cvss = _TAINT_CVSS.get(flow.rule_id, _DEFAULT_CVSS)
                    self._add(Finding(
                        id=flow.rule_id,
                        title=f"Taint flow: {flow.source_type} → {flow.sink_label}",
                        category="E17",
                        skill_name=self.SKILL_NAME,
                        skill_type=self.SKILL_TYPE,
                        description=(
                            f"Untrusted data from source '{flow.source_type}' flows into "
                            f"'{flow.sink_label}' within the same handler block without a "
                            f"visible sanitizer in between."
                        ),
                        technical_detail=(
                            f"Source at line {flow.source_line}: {flow.source_snippet!r}\n"
                            f"Sink at line {flow.sink_line}: {flow.sink_snippet!r}\n"
                            "No sanitizer pattern (DOMPurify, textContent, encodeURIComponent, etc.) "
                            "was found between the source and sink in the resolved handler body. "
                            "This is a heuristic analysis -- confirm the data actually flows "
                            "from source to sink without intermediate transformation."
                        ),
                        cvss=cvss,
                        evidence=[
                            f"SOURCE ({flow.source_type}): {flow.source_snippet}",
                            f"SINK   ({flow.sink_label}): {flow.sink_snippet}",
                        ],
                        file=flow.file,
                        line=flow.source_line,
                        context=extract_snippet(text, flow.source_line),
                        remediation=(
                            "Sanitize or validate the data before it reaches the sink. "
                            "For DOM sinks: use DOMPurify.sanitize() or textContent. "
                            "For eval/executeScript: never pass external data as code strings. "
                            "For redirects: validate against an allowlist of trusted URLs."
                        ),
                        verification=Verification(
                            title="Trace the data flow manually",
                            steps=[
                                f"Open {flow.file} and find the handler starting near line {span.line}.",
                                f"At line {flow.source_line}, confirm the source expression reads from untrusted input.",
                                f"At line {flow.sink_line}, confirm the sink uses that value directly.",
                                "Check whether any transformation between those lines effectively neutralizes the input.",
                            ],
                        ),
                    ))

    # ── 2. Cross-context bridge matrix ───────────────────────────────────────

    def _run_bridge_matrix(self, ctx: AnalysisContext) -> None:
        file_contexts = classify_files(ctx.manifest, ctx.files)
        file_texts = {f.rel_path: f.text for f in ctx.js_files()}

        violations = analyze_bridge(file_contexts, file_texts)
        for v in violations:
            cvss = _BRIDGE_CVSS.get(v.escalation_level, _DEFAULT_CVSS)
            self._add(Finding(
                id=v.chain_id,
                title=f"Cross-context bridge: {v.escalation_level}",
                category="E17",
                skill_name=self.SKILL_NAME,
                skill_type=self.SKILL_TYPE,
                description=v.description,
                technical_detail=v.technical_detail,
                cvss=cvss,
                evidence=[
                    f"SEND: {v.from_file}:{v.from_line} ({v.from_pattern})",
                    f"RECV: {v.to_file}:{v.to_line} ({v.to_pattern})",
                    f"SINK: {v.sink_file}:{v.sink_line} ({v.sink_label})",
                ],
                file=v.from_file,
                line=v.from_line,
                remediation=(
                    "Validate sender.id in the background onMessage handler before performing "
                    "any privileged action. Treat every message as untrusted regardless of origin. "
                    "Ensure no message payload is passed directly to privileged APIs -- schema-check "
                    "and allowlist all expected actions."
                ),
                verification=Verification(
                    title="Trace the full message path",
                    steps=[
                        f"Confirm {v.from_file} is a {v.from_ctx} (check manifest.json content_scripts).",
                        f"In {v.from_file}:{v.from_line}, find what triggers the send and whether it can be influenced by page content.",
                        f"In {v.to_file}:{v.to_line}, find the onMessage handler and check sender.id validation.",
                        f"In {v.sink_file}:{v.sink_line}, confirm the privileged action ({v.sink_label}) is not reachable with attacker-controlled arguments.",
                    ],
                ),
            ))
