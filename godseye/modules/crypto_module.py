"""
modules/crypto_module.py

[UNIQUE] Crypto & Entropy Auditor
Covers E12 - Broken/Weak Cryptographic Implementations.

Flags:
- Broken/deprecated symmetric algorithms (DES, RC4, Blowfish, 3DES)
- Broken digest functions (MD5, SHA-1) used in a security context
- Insecure PRNG (Math.random()) used in a security-relevant context
- Custom XOR-based "encryption" schemes
- Weak key derivation (no salt, insufficient iterations)
- ECB mode (always insecure for non-trivial data)
"""

from __future__ import annotations
import re

from ..models import Finding, CVSSVector, SkillType, Verification
from ..engine.base_module import BaseModule
from ..engine.loader import AnalysisContext
from ..engine.tokenizer import RuleSpec, FileScope
from ..engine.snippet import extract_snippet

_CRYPTO_RULES: list[dict] = [
    dict(
        rule_id="CRYPTO-BROKEN-ALGO-DES",
        pattern=re.compile(r"""["'`](DES|DESede|3DES|TripleDES|Blowfish|RC4|ARCFOUR|RC2)["'`]"""),
        title="Deprecated/broken symmetric algorithm",
        detail="DES (56-bit), 3DES, RC4, RC2, and Blowfish are all broken or deprecated. DES keyspace is exhausted in hours; RC4 has known biases; 3DES is deprecated by NIST (SP 800-131A rev2). None should be used in new code.",
        remediation="Replace with AES-256-GCM or ChaCha20-Poly1305 for authenticated encryption.",
        cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    ),
    dict(
        rule_id="CRYPTO-BROKEN-DIGEST",
        pattern=re.compile(r"""["'`](MD5|SHA-?1|SHA1)["'`]|createHash\(\s*["'`](md5|sha1|sha-1)["'`]\)""", re.IGNORECASE),
        title="Broken cryptographic hash function (MD5 / SHA-1)",
        detail="MD5 and SHA-1 are cryptographically broken -- collision attacks are practical. Acceptable for non-security checksums (e.g. file deduplication); NOT acceptable for password storage, digital signatures, or any integrity-checking with a security guarantee.",
        remediation="Use SHA-256 or SHA-3 for integrity/authenticity. For passwords use PBKDF2/bcrypt/scrypt/Argon2.",
        cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="L", A="N"),
    ),
    dict(
        rule_id="CRYPTO-INSECURE-PRNG",
        pattern=re.compile(r"Math\.random\s*\(\s*\)"),
        title="Math.random() — not a CSPRNG",
        detail="Math.random() is a pseudo-random number generator not designed for cryptographic use. In modern V8 it's an xorshift128+ variant, which has known output prediction weaknesses. Using it to generate tokens, nonces, keys, or session identifiers creates predictable values an attacker can brute-force.",
        remediation="Use crypto.getRandomValues() (browser) or the Web Crypto API for any security-relevant randomness.",
        cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="L", A="N"),
    ),
    dict(
        rule_id="CRYPTO-CUSTOM-XOR",
        pattern=re.compile(r"(?i)\bxor\b.*encrypt|encrypt.*\bxor\b|charCodeAt.*\^|\.charCodeAt\(\s*\w+\s*\)\s*\^"),
        title="Custom XOR-based encryption",
        detail="XOR with a fixed or short repeating key is not encryption -- it's trivially reversible once any known plaintext is available, and the key length is recoverable from ciphertext patterns (Kasiski examination / Index of Coincidence). It provides zero security against a competent attacker.",
        remediation="Replace all custom XOR schemes with a standard AEAD cipher (AES-256-GCM or ChaCha20-Poly1305) via the Web Crypto API.",
        cvss=CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    ),
    dict(
        rule_id="CRYPTO-ECB-MODE",
        pattern=re.compile(r"""["'`]AES-?ECB["'`]|AES/ECB/""", re.IGNORECASE),
        title="ECB mode (AES/ECB) detected",
        detail="ECB mode encrypts each block independently, so identical plaintext blocks produce identical ciphertext blocks. This leaks structure (the 'ECB penguin' effect) and is fundamentally insecure for any message longer than one block.",
        remediation="Use AES-GCM (authenticated, nonce-based) instead of ECB or CBC.",
        cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    ),
    dict(
        rule_id="CRYPTO-WEAK-KDF",
        pattern=re.compile(r"""PBKDF2|deriveKey|pbkdf2"""),
        title="Key derivation function detected (verify iteration count)",
        detail="A KDF call was found. This finding is informational only -- it confirms a KDF is being used, which is correct. What can't be verified statically is whether the iteration count is sufficient (OWASP recommends ≥600,000 for PBKDF2-SHA-256 as of 2024) or whether a salt is being supplied. Review the actual call arguments.",
        remediation="Confirm iteration count ≥ 100,000 (prefer 600,000+ with SHA-256) and that a cryptographically random salt is generated fresh for each derivation.",
        cvss=CVSSVector(AV="N", AC="H", PR="N", UI="N", S="U", C="L", I="N", A="N"),
    ),
]

RULE_SPECS: list[RuleSpec] = [
    RuleSpec(r["rule_id"], r["pattern"], scope=FileScope.JS_NONVENDOR)
    for r in _CRYPTO_RULES
]


class CryptoEntropyAuditorModule(BaseModule):
    SKILL_NAME = "Crypto & Entropy Auditor"
    SKILL_TYPE = SkillType.UNIQUE
    CATEGORY = "E12"
    DESCRIPTION = "Broken/deprecated cryptographic algorithms, weak PRNG, ECB mode, custom XOR schemes"
    RULE_SPECS = RULE_SPECS

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        self._findings = []
        for rule in _CRYPTO_RULES:
            for span in ctx.index.get(rule["rule_id"]):
                text = ctx.index.file_text(span.file)
                self._add(Finding(
                    id=rule["rule_id"],
                    title=rule["title"],
                    category="E12",
                    skill_name=self.SKILL_NAME,
                    skill_type=self.SKILL_TYPE,
                    description=rule["title"] + " found in extension source.",
                    technical_detail=rule["detail"],
                    cvss=rule["cvss"],
                    evidence=[span.snippet],
                    file=span.file, line=span.line,
                    context=extract_snippet(text, span.line),
                    remediation=rule["remediation"],
                    verification=Verification(
                        title="Confirm the call context",
                        steps=[
                            f"Open {span.file} at line {span.line}.",
                            "Confirm whether this call is in a security-relevant context (token generation, credential storage, signature verification) or a non-security one (file deduplication, display hash). The finding severity applies to the former.",
                        ],
                    ),
                ))
        return self._findings
