# Contributing to GODSEYE: EX

Thanks for looking under the hood. This project is a static analysis engine for
browser extensions, and it's built to make adding a new detection cheap: the
tokenizer, block resolver, and index are shared infrastructure, so a new module
is usually just a list of patterns and a `run()` method.

## Project layout

```
godseye/
  models.py                    # Finding, CVSSVector (real CVSS v3.1 base score), rank scale
  engine/
    loader.py                  # reads .crx/.xpi/.zip/dir -> AnalysisContext
    tokenizer.py                # RuleSpec registry + brace-aware block resolver
    string_unpacker.py           # pre-processor: hex escapes, concat, bracket notation
    alias_tracker.py              # const safeLog = eval -> flags safeLog() calls
    taint_tracer.py                # source -> sink tracing within resolved blocks
    context_bridge.py               # cross-context privilege escalation matrix
    chains.py                        # risk-class correlation rules
    aggregate.py                      # de-duplicates repeated identical hits
    vendor_detect.py                   # heuristic vendor/minified file exclusion
    diff.py                             # version-to-version comparison
  modules/                                # one file per detection module
  report/                                  # console (rich), HTML, JSON, SARIF renderers
  cli.py                                    # scan / diff / info / list-modules
tests/
  test_godseye.py                            # unit + fixture-based regression tests
sample_extensions/
  */                                          # synthetic fixtures the tests scan
```

## Setup

```bash
git clone https://github.com/rithinkrishnakv/godseye-ex
cd godseye-ex
pip install -e .
python -m unittest discover tests
```

All 57 tests should pass before you start, and should still pass before you open a PR.

## Adding a detection module

Every module declares its patterns at the class level. The loader collects
`RULE_SPECS` from every module before any module runs, tokenizes each file
exactly once, and hands modules a read-only `ctx.index` to query — your new
patterns cost zero extra file I/O.

```python
from godseye.engine.base_module import BaseModule
from godseye.engine.loader import AnalysisContext
from godseye.engine.tokenizer import RuleSpec, FileScope, Resolution
from godseye.models import Finding, CVSSVector, SkillType
import re

class MyModule(BaseModule):
    SKILL_NAME = "My Skill"
    SKILL_TYPE = SkillType.ACTIVE
    CATEGORY = "E3"                    # see docs/extension_security_top10.md for the taxonomy
    DESCRIPTION = "What this finds"

    RULE_SPECS = [
        # Plain match
        RuleSpec("MY-RULE", re.compile(r"dangerous_pattern"),
                 scope=FileScope.JS_NONVENDOR),
        # Anchor: resolve the enclosing function body (not a fixed char window)
        RuleSpec("MY-ANCHOR", re.compile(r"addListener\("),
                 scope=FileScope.JS_NONVENDOR, resolution=Resolution.BLOCK),
        # Storage object: resolve the next balanced {...}
        RuleSpec("MY-STORE", re.compile(r"storage\.set\s*\("),
                 scope=FileScope.JS_NONVENDOR, resolution=Resolution.OBJECT_LITERAL),
    ]

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        self._findings = []
        for span in ctx.index.get("MY-ANCHOR"):
            body = span.block.text if span.block else ""
            # body is the actual resolved handler body, not a char-count window
            if "bad_pattern" in body:
                self._add(Finding(id="MY-RULE", ...))
        return self._findings
```

Then register the class in `ALL_MODULES` in `engine/orchestrator.py`.

`FileScope` options: `JS_NONVENDOR` (the common case), `JS_ALL` (include vendor/minified
files — only Supply Chain Sentinel uses this, since fingerprinting vendor libraries is
its job), `HTML`.

`Resolution` options: `NONE` (just record the match), `BLOCK` (resolve the enclosing
function/arrow body — for listener registrations), `OBJECT_LITERAL` (resolve the next
balanced `{...}` — for calls like `chrome.storage.set({...})`).

## Adding a chain rule

Chains correlate findings that are individually moderate but, together, indicate a
worse situation. They're pure set-intersection logic in `engine/chains.py` — no new
scanning happens.

1. Add your finding ID(s) to an existing entry in `RISK_CLASSES`, or add a new risk
   class if it doesn't fit an existing one.
2. Add a `ChainRule` to `CHAIN_RULES` naming the risk classes it `requires`. Set
   `same_file=True` if the correlated findings should only fire when they're in the
   same file (higher confidence than a cross-file correlation).

## Testing

Add fixtures under `sample_extensions/<name>/` (a `manifest.json` plus whatever JS/HTML
exercises your new rule), then add a test class in `tests/test_godseye.py` that calls
`scan()` on it and asserts your finding ID shows up — see `TestV3NewModules` or
`TestManifestDeception` for the existing pattern. Include a negative-control case where
your pattern should *not* fire, the way `TestFetchEvalNegativeControl` does — a rule that
only has positive tests hasn't been shown not to false-positive.

```bash
python -m unittest discover tests -v
```

## What this project won't merge

This tool draws a hard line at static analysis: it reads source and reports findings,
and it never executes, fuzzes, or exploits the target extension. PRs that add live
execution, PoC/exploit generation, or anything that sends network traffic to or on
behalf of a scanned extension are out of scope regardless of the stated purpose.

## Style notes

- Keep new modules' remediation text specific and actionable, not generic ("sanitize
  your input") — say what to actually do.
- Every `Finding` should include a `Verification` block where a human can meaningfully
  confirm the issue without executing anything.
- Match the existing CVSS vectors' reasoning in `models.py`'s `CVSSVector` — the score
  should reflect the actual mechanism (e.g. a static data-at-rest leak is `UI:N`; don't
  conflate it with a downstream exploit step that needs interaction).
