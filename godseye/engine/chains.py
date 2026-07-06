"""
engine/chains.py

Vulnerability chain detection -- v2.

The original version matched on exact finding IDs (e.g. requiring
literally "MANIFEST-PERM-COOKIES"), which meant a logically equivalent
situation using a different permission, or a different specific listener
shape, was invisible to the chain detector even when the underlying risk
was identical. A real-world target (DVBE) demonstrated this: it combined
three sensitive permissions with a real DOM sink and triggered nothing,
because no chain rule happened to require *that exact* permission name.

This version matches on RISK CLASSES -- groups of finding-ID prefixes
that represent the same kind of exposure -- so "any sensitive permission"
or "any unvalidated message handler" can satisfy a chain, not just one
specific named instance. Still pure correlation over findings a normal
scan already produced; no new scanning, no new execution.
"""

from __future__ import annotations
from dataclasses import dataclass

from ..models import Finding, CVSSVector, SkillType

# risk class name -> finding-ID prefixes that belong to it
RISK_CLASSES: dict[str, list[str]] = {
    "host_exposure": ["MANIFEST-HOST-WILDCARD", "MANIFEST-BROAD-PERMISSION-SURFACE", "MANDEC-WAR-WILDCARD", "MANDEC-WAR-MV2-EXPOSURE"],
    "dom_sink": ["INJ-"],
    "unvalidated_messaging": [
        "MSG-ON-MESSAGE-EXTERNAL-NO-CHECK",
        "MSG-ON-CONNECT-EXTERNAL",
        "MSG-POSTMESSAGE-NO-ORIGIN-CHECK",
        "MSG-ON-MESSAGE-NO-SENDER-CHECK",
    ],
    "remote_code": ["DYN-REMOTE-IMPORTSCRIPTS", "DYN-DYNAMIC-SCRIPT-TAG", "SUPPLY-REMOTE-RESOURCE"],
    "csp_weak": ["MANIFEST-CSP-UNSAFE-EVAL"],
    "dynamic_exec": ["DYN-EVAL", "DYN-NEW-FUNCTION", "DYN-SETTIMEOUT-STRING"],
    "extconn_open": ["MANIFEST-EXTCONN-WILDCARD-IDS", "MANIFEST-EXTCONN-WILDCARD-MATCHES"],
    "sensitive_permission": ["MANIFEST-PERM-", "MANIFEST-BROAD-PERMISSION-SURFACE"],
    "credential_exposure": ["CRED-", "STORAGE-SENSITIVE-"],
    "native_bridge": ["NATIVE-PERMISSION-DECLARED", "NATIVE-CONNECT-CALL"],
    # New categories from v3 modules
    "broken_crypto": ["CRYPTO-BROKEN-ALGO-", "CRYPTO-BROKEN-DIGEST", "CRYPTO-CUSTOM-XOR", "CRYPTO-ECB-MODE"],
    "insecure_prng": ["CRYPTO-INSECURE-PRNG"],
    "context_leak": ["CTX-WINDOW-CHROME-ASSIGN", "CTX-CUSTOM-EVENT-CHROME-DATA", "CTX-POSTMESSAGE-CHROME-DATA", "CTX-EVAL-IN-PAGE-CONTEXT"],
    "tab_injection": ["TAB-EXECUTE-SCRIPT-"],
    "network_manipulation": ["NET-WEBREQUEST-HEADER-HOOK", "NET-DNR-DYNAMIC-RULE", "NET-PROXY-USAGE"],
    "remote_rce": ["NET-RCE-FETCH-EVAL", "DYN-EVAL-REFERENCE"],
}


@dataclass
class ChainRule:
    id: str
    title: str
    requires: list[str]          # risk class names, ALL must have at least one matching finding
    description: str
    technical_detail: str
    remediation: str
    cvss: CVSSVector
    same_file: bool = False      # if True, the matching findings must share a file
    is_extinction: bool = False


CHAIN_RULES: list[ChainRule] = [
    ChainRule(
        id="CHAIN-HOST-EXPOSURE-PLUS-MESSAGING",
        title="Broad exposure + unvalidated message handler",
        requires=["host_exposure", "unvalidated_messaging"],
        description="The extension is broadly exposed (wildcard host access, a wide sensitive-permission surface, or a web_accessible_resources page reachable by any website) AND has a message handler with no visible sender/origin validation.",
        technical_detail="Whatever site or extension can reach that handler isn't a small set -- it's anyone, given how broadly this extension is already exposed. This is also the real-world shape of the most common web_accessible_resources exploit: a malicious site loads the exposed page, then posts a crafted message to it.",
        remediation="Add sender/origin validation to every external or unvalidated message handler; treat this as the highest-priority fix in the report.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N"),
    ),
    ChainRule(
        id="CHAIN-HOST-EXPOSURE-PLUS-DOM-SINK",
        title="Broad exposure + DOM injection sink",
        requires=["host_exposure", "dom_sink"],
        description="The extension is broadly exposed (wildcard host access or a wide sensitive-permission surface) AND contains at least one DOM injection sink (innerHTML/document.write/etc.) in its own code.",
        technical_detail="A sink that would be low-priority in a narrowly-scoped extension becomes a website-reachable concern once the extension already runs everywhere and holds broad permissions. This is a heuristic correlation -- confirm manually that the sink is actually reachable from page-controlled data before treating it as proven.",
        remediation="Trace the sink's data source. If any part of it can come from page content, a message payload, or stored data influenced by a website, sanitize before assignment.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N"),
    ),
    ChainRule(
        id="CHAIN-CSP-EVAL-PLUS-REMOTE-CODE",
        title="CSP allows eval() + remote code is loaded at runtime",
        requires=["csp_weak", "remote_code"],
        description="The extension both weakens its own CSP to allow eval()-style execution AND pulls executable code from a remote host at runtime.",
        technical_detail="A compromised or MitM'd remote host can now ship code that runs with the extension's full privileges, with no CSP backstop.",
        remediation="Bundle dependencies locally and remove 'unsafe-eval' from the CSP. Treat any remaining remote code loading as a hard blocker for release.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
    ),
    ChainRule(
        id="CHAIN-CSP-EVAL-PLUS-DYNAMIC-EXEC",
        title="CSP allows eval() + eval()/new Function() is actually used",
        requires=["csp_weak", "dynamic_exec"],
        description="The CSP permits 'unsafe-eval' AND the code actually calls eval()/new Function()/a string-arg timer -- this isn't a defensive leftover, it's load-bearing.",
        technical_detail="A stricter CSP would break this code at runtime, which confirms the dynamic execution path is live, not dead code.",
        remediation="Refactor away from dynamic code construction, then tighten the CSP -- in that order, so removing 'unsafe-eval' doesn't break the extension.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="H", I="H", A="N"),
    ),
    ChainRule(
        id="CHAIN-EXTCONN-OPEN-PLUS-SENSITIVE-PERM",
        title="externally_connectable wildcard + sensitive permission",
        requires=["extconn_open", "sensitive_permission"],
        description="Any other installed extension (or, for wildcard matches, any website) can message this one, and this one holds at least one sensitive permission.",
        technical_detail="A malicious or compromised sender can potentially pivot through this extension's open messaging surface into capability it wasn't granted directly.",
        remediation="Restrict externally_connectable.ids/matches to specific trusted IDs/origins.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="L", A="N"),
    ),
    ChainRule(
        id="CHAIN-MESSAGING-DOM-SINK-SAME-FILE",
        title="Unvalidated message handler + DOM sink in the same file",
        requires=["unvalidated_messaging", "dom_sink"],
        same_file=True,
        description="A message handler with no validation and a DOM injection sink were both found in the same file -- the shape of a classic message-driven DOM XSS.",
        technical_detail="If the sink's input traces back to the message payload, any sender this handler accepts from can inject arbitrary markup/script into this context. Highest-confidence chain in this report because the co-location is direct evidence, not just a manifest-level correlation.",
        remediation="Validate the message sender/origin AND sanitize before the sink -- defense in depth, not either/or.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="U", C="H", I="H", A="N"),
    ),
    ChainRule(
        id="CHAIN-CREDENTIAL-PLUS-HOST-EXPOSURE",
        title="Hardcoded/stored credential + broad exposure",
        requires=["credential_exposure", "host_exposure"],
        description="A hardcoded credential or sensitive value in storage exists, and the extension also has broad host access or a wide permission surface.",
        technical_detail="If any other finding in this report ever lets an attacker read extension internals or messages, the broad exposure means that isn't limited to one site -- it's everywhere this extension runs.",
        remediation="Rotate/remove the credential and move it server-side; separately, narrow the permission/host surface to what's actually needed.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="L", A="N"),
    ),
    ChainRule(
        id="CHAIN-NATIVE-BRIDGE-PLUS-REMOTE-CODE",
        title="Native messaging bridge + remote code loading",
        requires=["native_bridge", "remote_code"],
        description="The extension can talk to a native OS-level process AND loads executable code from a remote host.",
        technical_detail="A compromised remote dependency doesn't just run in the browser sandbox here -- it potentially has a path to the native messaging host and whatever that host can do on the OS. The deepest escalation this tool can flag from static analysis alone.",
        remediation="Eliminate remote code loading entirely for any extension with native messaging access. This combination should block release until resolved.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
        is_extinction=True,
    ),
    ChainRule(
        id="CHAIN-BROKEN-CRYPTO-PLUS-CREDENTIAL",
        title="Broken cryptography + credential storage",
        requires=["broken_crypto", "credential_exposure"],
        description="A deprecated/broken cryptographic algorithm exists alongside credential storage. The crypto is likely being used to 'protect' the stored credential.",
        technical_detail="If the stored credential is encrypted with DES, RC4, a custom XOR scheme, or MD5/SHA-1 as a password hash, the protection is cosmetic. An attacker who can read the storage (rooted device, filesystem access, chrome.storage bug) can trivially break the encryption.",
        remediation="Replace the broken crypto with AES-256-GCM or a proper password hash (Argon2/bcrypt/PBKDF2 with sufficient iterations), AND confirm the key itself is not also stored insecurely.",
        cvss=CVSSVector(AV="L", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    ),
    ChainRule(
        id="CHAIN-INSECURE-PRNG-PLUS-CREDENTIAL",
        title="Math.random() used alongside credential/token generation",
        requires=["insecure_prng", "credential_exposure"],
        description="Math.random() (not a CSPRNG) is used in the same extension that also stores or generates tokens/credentials.",
        technical_detail="If Math.random() is used to generate session tokens, CSRF nonces, OTP codes, or encryption keys, an attacker with knowledge of the V8 PRNG state (recoverable from a handful of observed outputs) can predict all past and future outputs. This is not theoretical: V8's xorshift128+ is fully reversible.",
        remediation="Replace Math.random() with crypto.getRandomValues() for all security-relevant randomness.",
        cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    ),
    ChainRule(
        id="CHAIN-CONTEXT-LEAK-PLUS-DOM-SINK",
        title="Content script context leak + DOM injection sink in same file",
        requires=["context_leak", "dom_sink"],
        same_file=True,
        description="A content script that bridges chrome.* data to the page context also contains a DOM injection sink.",
        technical_detail="This is the highest-confidence context-leak shape: if the leaked chrome.* data flows into the innerHTML/document.write sink in the same file, an XSS in the page context can directly trigger privileged API execution. Co-location in the same file makes this higher-confidence than a cross-file correlation.",
        remediation="Eliminate the chrome.* bridge (never assign chrome.* data to window) AND sanitize the DOM sink independently -- treat these as two separate bugs, not one.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N"),
    ),
    ChainRule(
        id="CHAIN-TAB-INJECTION-PLUS-UNVALIDATED-MESSAGING",
        title="Cross-tab script injection + unvalidated message handler",
        requires=["tab_injection", "unvalidated_messaging"],
        description="The extension can inject scripts into arbitrary tabs AND has an unvalidated external/postMessage handler.",
        technical_detail="An attacker who can send a message to the unvalidated handler (via an externally_connectable path, or a postMessage with no origin check) may be able to trigger the executeScript call with attacker-controlled arguments -- tabId, injected code, or both. This is remote arbitrary-tab-code-injection if the handler doesn't validate.",
        remediation="Add sender validation to the message handler AND ensure executeScript arguments (especially tabId and any code string) are never built from message payloads.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="R", S="C", C="H", I="H", A="N"),
    ),
    ChainRule(
        id="CHAIN-NETWORK-MANIPULATION-PLUS-CREDENTIAL",
        title="Network traffic manipulation + credential exposure",
        requires=["network_manipulation", "credential_exposure"],
        description="The extension can intercept/modify network traffic AND contains exposed credentials.",
        technical_detail="An extension that can modify request headers or proxy traffic and also has hardcoded credentials is particularly dangerous if compromised: the credentials can be used server-side while the network hooks are used to intercept or tamper with the traffic those credentials authenticate.",
        remediation="Treat network-manipulation capability and stored credentials as independently high-priority issues. Rotating credentials does not fix the traffic-interception surface, and removing the network hooks does not fix the exposed credentials.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N"),
    ),
    ChainRule(
        id="CHAIN-REMOTE-RCE-PLUS-BROAD-PERMISSIONS",
        title="Confirmed network RCE + broad permission surface",
        requires=["remote_rce", "sensitive_permission"],
        description="A confirmed fetch()-to-eval remote code execution path exists AND the extension holds multiple sensitive permissions.",
        technical_detail=(
            "This is the single most severe pattern this tool can detect. It is not a "
            "chain of independently-moderate signals -- it is a proven code-execution "
            "primitive (network input becomes running code in the extension's own "
            "privileged context) combined with the exact capabilities that make that "
            "execution catastrophic. A network attacker (MitM on public Wi-Fi, DNS "
            "hijack, or compromise of the remote server) does not just get one payload "
            "run once -- they get standing remote code execution inside a context that "
            "can read cookies (session hijacking), history (surveillance), and clipboard "
            "(credential/seed-phrase theft), triggered with zero user interaction on "
            "every install or browser restart that re-fires the listener."
        ),
        remediation=(
            "This combination should block release immediately, not go on a backlog. "
            "Remove the fetch-to-eval pattern first (it is the root cause), then "
            "separately reduce the permission surface to only what is load-bearing."
        ),
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
        is_extinction=True,
    ),
]


def _class_matches(findings: list[Finding], class_name: str) -> list[Finding]:
    prefixes = RISK_CLASSES[class_name]
    return [f for f in findings if any(f.id.startswith(p) for p in prefixes)]


def detect_chains(findings: list[Finding]) -> list[Finding]:
    chain_findings: list[Finding] = []

    for rule in CHAIN_RULES:
        class_matches = [_class_matches(findings, c) for c in rule.requires]
        if not all(class_matches):
            continue

        if rule.same_file:
            files_per_class = [{f.file for f in matches if f.file} for matches in class_matches]
            common_files = set.intersection(*files_per_class) if all(files_per_class) else set()
            if not common_files:
                continue
            component_ids = sorted({
                f.id for matches in class_matches for f in matches if f.file in common_files
            })
        else:
            component_ids = sorted({f.id for matches in class_matches for f in matches})

        chain_findings.append(Finding(
            id=rule.id,
            title=f"\u26a1 CHAIN: {rule.title}",
            category="CHAIN",
            skill_name="Chain Detector",
            skill_type=SkillType.UNIQUE,
            description=rule.description,
            technical_detail=rule.technical_detail,
            cvss=rule.cvss,
            evidence=[f"Component findings: {', '.join(component_ids)}"],
            file="(cross-file correlation)" if not rule.same_file else next(iter(
                {f.file for matches in class_matches for f in matches if f.id in component_ids}
            ), ""),
            remediation=rule.remediation,
            chain_ids=component_ids,
            is_chain_finding=True,
            is_extinction=rule.is_extinction,
        ))

    return chain_findings
