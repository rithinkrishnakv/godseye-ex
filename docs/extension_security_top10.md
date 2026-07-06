# GODSEYE: EX — Extension Security Coverage Matrix

There is no official "OWASP Browser Extension Top 10." This is GODSEYE: EX's own taxonomy,
built from publicly documented extension security research and the Chrome/Firefox platform docs.
Treat it as this tool's coverage map, not an industry standard.

| Code | Category | What it covers |
|------|----------|----------------|
| E1  | Overprivileged Permissions & Host Access | Broad/high-impact permissions, `<all_urls>`, wildcard host/content-script matches |
| E2  | Insecure Cross-Context Messaging | `onMessage`/`onMessageExternal`/`onConnectExternal`, `window.postMessage`, `externally_connectable` |
| E3  | Content Script Injection / DOM XSS | `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `dangerouslySetInnerHTML` |
| E4  | Dynamic Code Execution | `eval`, `new Function`, string-arg `setTimeout`/`setInterval`, CSP `unsafe-eval`/`unsafe-inline`, remote `importScripts`, dynamic `<script>` creation |
| E5  | Insecure Data Storage | Hardcoded credentials, sensitive keys in `chrome.storage` or page `localStorage` |
| E6  | Supply Chain & Remote Dependencies | Remote-hosted scripts/styles, bundled libraries with known public advisories |
| E7  | Native Messaging & OS Bridge Exposure | `nativeMessaging` permission, `connectNative`/`sendNativeMessage` calls |
| E8  | Privacy & Data Handling | Permission combinations that add up to broad surveillance capability, undisclosed analytics |
| E9  | Update & Distribution Integrity | Manifest V2 deprecation, self-hosted `update_url` |
| E10 | Hardening & Defense-in-Depth Gaps | Debug leftovers (`console.log` of secrets, stray `debugger;`), security-flagged TODOs |
| E11 | Manifest/Code Mismatch & Hidden Capability | `web_accessible_resources` exposure, `optional_permissions` ratcheting, permission/code cross-reference, fixed `key`, name impersonation |
| E12 | Broken/Weak Cryptography | Deprecated algorithms (DES, RC4, 3DES), MD5/SHA-1 digests, `Math.random()` PRNG, custom XOR, ECB mode, weak KDF |
| E13 | Network Policy & Traffic Manipulation | Dynamic `declarativeNetRequest` rules, `webRequest` header hooks, cleartext HTTP, proxy manipulation |
| E14 | Context Leakage (Content Script / Page Boundary) | `window.X = chrome.*`, `CustomEvent` with privileged data, `postMessage` of chrome.* data, DOM script injection |
| E15 | Cross-Tab Script Injection | `chrome.scripting.executeScript`, `chrome.tabs.executeScript` with dynamic targets or code strings |
| E16 | Permissive CORS & Cross-Origin Policy | `Access-Control-Allow-Origin: *`, `no-cors` fetch timing oracle, `withCredentials`, COEP/COOP misconfiguration |

## Module → category map

| Module | Type | Categories |
|--------|------|------------|
| Manifest Sight | PASSIVE | E1, E4 (CSP), E9 |
| Manifest Deception Sight | UNIQUE | E11 |
| Messaging Sentinel | ACTIVE | E2 |
| Injection Sight | ACTIVE | E3 |
| Dynamic Code Sight | ACTIVE | E4 |
| Credential & Storage Sight | PASSIVE | E5 |
| Supply Chain Sentinel | HIDDEN | E6, E8 (analytics) |
| Native Bridge Sight | UNIQUE | E7 |
| Privacy Sentinel | PASSIVE | E8 |
| Hardening Sight | ACTIVE | E10 |
| Crypto & Entropy Auditor | UNIQUE | E12 |
| Network Policy Auditor | ACTIVE | E13 |
| Context Leakage Auditor | UNIQUE | E14 |
| Tab Injection Controller | ACTIVE | E15 |
| External CORS Auditor | ACTIVE | E16 |

## Chain rules (14 total)

Chains correlate findings that are individually moderate but, together, indicate a
concretely worse situation. All chain detection is pure set-intersection logic
over findings already produced by the 15 modules -- no additional scanning.

| Chain | Requires | Rank |
|-------|----------|------|
| Broad exposure + unvalidated messaging | host_exposure + unvalidated_messaging | SS |
| Broad exposure + DOM sink | host_exposure + dom_sink | SS |
| CSP allows eval + remote code | csp_weak + remote_code | SS |
| CSP allows eval + eval in code | csp_weak + dynamic_exec | B |
| externally_connectable wildcard + sensitive permission | extconn_open + sensitive_permission | SS |
| Unvalidated messaging + DOM sink (same file) | unvalidated_messaging + dom_sink (same file) | B |
| Credential + broad exposure | credential_exposure + host_exposure | SS |
| Native bridge + remote code | native_bridge + remote_code | **SSS (Extinction)** |
| Broken crypto + credential | broken_crypto + credential_exposure | A |
| Math.random + credential | insecure_prng + credential_exposure | A |
| Context leak + DOM sink (same file) | context_leak + dom_sink (same file) | SS |
| Tab injection + unvalidated messaging | tab_injection + unvalidated_messaging | SS |
| Network manipulation + credential | network_manipulation + credential_exposure | SS |
| WAR exposure + unvalidated messaging | host_exposure (WAR) + unvalidated_messaging | SS |

## Rank scale

| Rank | CVSS | Meaning |
|------|------|---------|
| F | 0.0 | Informational |
| D | < 3.0 | Hardening debt |
| C | < 5.0 | Needs investigation |
| B | < 7.0 | Concrete moderate-impact pattern |
| A | < 9.0 | High-impact pattern (single signal) |
| S | < 9.5 | Critical-impact pattern (single signal) |
| SS | — | Chain: corroborating signals compound the risk |
| SSS | — | Extinction: remote code reaches an OS-level bridge |
