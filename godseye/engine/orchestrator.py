"""
engine/orchestrator.py

Runs every registered module against an AnalysisContext, then runs chain
detection over the combined findings. This is the only place that knows
about the full module list.

Tokenization happens exactly once here, before any module runs: RULE_SPECS
are collected from every module class and handed to the loader, which
builds the shared SourceIndex. Modules then only ever read from that
index -- they never independently re-scan file text.

Each module's run() is wrapped in a try/except: a bug or an unexpected
input in one module must not take down the whole scan. A failed module
is logged and treated as contributing zero findings, not as a crash.
"""

from __future__ import annotations
import time
from typing import Callable

from ..models import AppraisalResult
from .loader import AnalysisContext, load
from .chains import detect_chains
from .aggregate import aggregate_findings
from .logging_config import get_logger

log = get_logger("orchestrator")

from ..modules.manifest_module import ManifestSightModule
from ..modules.manifest_deception_module import ManifestDeceptionModule
from ..modules.messaging_module import MessagingSentinelModule
from ..modules.injection_module import InjectionSightModule
from ..modules.dynamic_code_module import DynamicCodeSightModule
from ..modules.storage_module import CredentialStorageSightModule
from ..modules.supply_chain_module import SupplyChainSentinelModule
from ..modules.native_bridge_module import NativeBridgeSightModule
from ..modules.privacy_module import PrivacySentinelModule
from ..modules.hardening_module import HardeningSightModule
from ..modules.crypto_module import CryptoEntropyAuditorModule
from ..modules.network_policy_module import NetworkPolicyAuditorModule
from ..modules.context_leakage_module import ContextLeakageAuditorModule
from ..modules.tab_injection_module import TabInjectionControllerModule
from ..modules.cors_module import ExternalCORSAuditorModule
from ..modules.taint_module import TaintAnalysisEngineModule

ALL_MODULES = [
    ManifestSightModule,
    ManifestDeceptionModule,
    MessagingSentinelModule,
    InjectionSightModule,
    DynamicCodeSightModule,
    CredentialStorageSightModule,
    SupplyChainSentinelModule,
    NativeBridgeSightModule,
    PrivacySentinelModule,
    HardeningSightModule,
    CryptoEntropyAuditorModule,
    NetworkPolicyAuditorModule,
    ContextLeakageAuditorModule,
    TabInjectionControllerModule,
    ExternalCORSAuditorModule,
    TaintAnalysisEngineModule,
]


def list_modules() -> list[dict]:
    return [
        {
            "name": m.SKILL_NAME,
            "type": m.SKILL_TYPE.value,
            "category": m.CATEGORY,
            "description": m.DESCRIPTION,
        }
        for m in ALL_MODULES
    ]


def _collect_rule_specs(modules: list[type]) -> list:
    specs = []
    for m in modules:
        specs.extend(getattr(m, "RULE_SPECS", []) or [])
    return specs


def scan(
    target_path: str,
    skip: list[str] | None = None,
    include_vendor: bool = False,
    on_module_done: Callable[[str, str, str, int | None, float, bool], None] | None = None,
) -> AppraisalResult:
    """
    on_module_done, if given, is called after each module as:
        (skill_name, skill_type, category, finding_count_or_None, elapsed_seconds, was_skipped)
    Purely a progress hook -- the engine never imports a UI library itself.
    """
    skip_set = {s.lower() for s in (skip or [])}
    rule_specs = _collect_rule_specs(ALL_MODULES)
    ctx: AnalysisContext = load(target_path, include_vendor=include_vendor, rule_specs=rule_specs)

    try:
        result = AppraisalResult(
            target=target_path,
            extension_name=ctx.name,
            extension_version=ctx.version,
            manifest_version=ctx.manifest_version,
            vendor_files=ctx.vendor_file_paths,
        )

        for module_cls in ALL_MODULES:
            instance = module_cls()
            if instance.SKILL_NAME.lower() in skip_set:
                result.modules_skipped.append(instance.SKILL_NAME)
                if on_module_done:
                    on_module_done(instance.SKILL_NAME, instance.SKILL_TYPE.value, instance.CATEGORY, None, 0.0, True)
                continue

            start = time.perf_counter()
            try:
                findings = instance.run(ctx)
            except Exception:
                log.warning("module %r raised during run() -- treating as zero findings for this scan", instance.SKILL_NAME, exc_info=True)
                findings = []
            elapsed = time.perf_counter() - start

            result.findings.extend(findings)
            result.modules_run.append(instance.SKILL_NAME)
            if on_module_done:
                on_module_done(instance.SKILL_NAME, instance.SKILL_TYPE.value, instance.CATEGORY, len(findings), elapsed, False)

        result.findings = aggregate_findings(result.findings)
        result.findings.extend(detect_chains(result.findings))
        return result
    finally:
        ctx.cleanup()
