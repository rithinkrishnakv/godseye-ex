"""
tests/test_godseye.py -- run with: python -m unittest discover tests
"""

from __future__ import annotations
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from godseye.models import CVSSVector, rank_for_score
from godseye.engine.orchestrator import scan
from godseye.engine.diff import diff

SAMPLES = Path(__file__).resolve().parents[1] / "sample_extensions"


class TestCVSS(unittest.TestCase):
    def test_known_critical_vector(self):
        # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> well-known 9.8 base score
        v = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H")
        self.assertEqual(v.base_score(), 9.8)

    def test_zero_impact_is_zero(self):
        v = CVSSVector(AV="N", AC="L", PR="N", UI="N", S="U", C="N", I="N", A="N")
        self.assertEqual(v.base_score(), 0.0)

    def test_rank_thresholds(self):
        self.assertEqual(rank_for_score(0.0)[0], "F")
        self.assertEqual(rank_for_score(4.0)[0], "D")
        self.assertEqual(rank_for_score(5.5)[0], "C")
        self.assertEqual(rank_for_score(9.2)[0], "A")
        self.assertEqual(rank_for_score(9.8)[0], "S")
        self.assertEqual(rank_for_score(9.0, is_chain=True)[0], "SS")
        self.assertEqual(rank_for_score(5.0, is_extinction=True)[0], "SSS")


class TestScanV1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = scan(str(SAMPLES / "risky-notes-v1"))

    def test_metadata(self):
        self.assertEqual(self.result.extension_name, "Risky Notes")
        self.assertEqual(self.result.extension_version, "1.0.0")
        self.assertEqual(self.result.manifest_version, 3)

    def test_expected_findings_present(self):
        ids = {f.id for f in self.result.findings}
        for expected in (
            "MANIFEST-HOST-WILDCARD",
            "MANIFEST-CSP-UNSAFE-EVAL",
            "MANIFEST-PERM-TABS",
            "MANIFEST-PERM-COOKIES",
            "MSG-POSTMESSAGE-NO-ORIGIN-CHECK",
            "INJ-INNERHTML",
            "CRED-AWS-ACCESS-KEY",
            "CRED-GENERIC-ASSIGN",
            "STORAGE-SENSITIVE-CHROME-STORAGE",
        ):
            self.assertIn(expected, ids, f"expected finding {expected} missing")

    def test_chains_detected(self):
        ids = {f.id for f in self.result.findings}
        self.assertIn("CHAIN-CREDENTIAL-PLUS-HOST-EXPOSURE", ids)
        self.assertIn("CHAIN-MESSAGING-DOM-SINK-SAME-FILE", ids)
        self.assertIn("CHAIN-HOST-EXPOSURE-PLUS-DOM-SINK", ids)
        chain = next(f for f in self.result.findings if f.id == "CHAIN-CREDENTIAL-PLUS-HOST-EXPOSURE")
        self.assertTrue(chain.is_chain_finding)
        self.assertEqual(chain.rank, "SS")

    def test_no_native_messaging_findings_on_v1(self):
        ids = {f.id for f in self.result.findings}
        self.assertNotIn("NATIVE-PERMISSION-DECLARED", ids)
        self.assertNotIn("CHAIN-NATIVE-BRIDGE-PLUS-REMOTE-CODE", ids)


class TestScanV2Extinction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = scan(str(SAMPLES / "risky-notes-v2"))

    def test_extinction_chain_present(self):
        chain = next((f for f in self.result.findings if f.id == "CHAIN-NATIVE-BRIDGE-PLUS-REMOTE-CODE"), None)
        self.assertIsNotNone(chain)
        self.assertEqual(chain.rank, "SSS")

    def test_external_message_chain_present(self):
        ids = {f.id for f in self.result.findings}
        self.assertIn("CHAIN-HOST-EXPOSURE-PLUS-MESSAGING", ids)


class TestDiff(unittest.TestCase):
    def test_diff_flags_regression(self):
        old = scan(str(SAMPLES / "risky-notes-v1"))
        new = scan(str(SAMPLES / "risky-notes-v2"))
        d = diff(old, new)
        self.assertTrue(d.regressed)
        added_ids = {f.id for f in d.added}
        self.assertIn("CHAIN-NATIVE-BRIDGE-PLUS-REMOTE-CODE", added_ids)
        removed_ids = {f.id for f in d.removed}
        self.assertIn("MANIFEST-PERM-COOKIES", removed_ids)


class TestLoaderFormats(unittest.TestCase):
    def test_zip_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / "ext.zip"
            shutil.make_archive(str(zip_path.with_suffix("")), "zip", str(SAMPLES / "risky-notes-v1"))
            result = scan(str(zip_path))
            self.assertEqual(result.extension_name, "Risky Notes")
            self.assertTrue(any(f.id == "MANIFEST-HOST-WILDCARD" for f in result.findings))


class TestVendorExclusionAndPermissionFixes(unittest.TestCase):
    """Regression coverage for the three issues identified against a real
    DVBE-shaped target: vendor-file noise, the missed permission-combo
    chain, and flattened per-permission severity."""

    @classmethod
    def setUpClass(cls):
        cls.result = scan(str(SAMPLES / "dvbe-like"))

    def test_vendor_file_excluded_from_pattern_scan(self):
        self.assertIn("jquery-2.2.4.min.js", self.result.vendor_files)
        jquery_findings = [f for f in self.result.findings if "jquery" in f.file.lower() and f.id.startswith("INJ-")]
        self.assertEqual(jquery_findings, [], "vendor jQuery should not produce INJ-* noise")

    def test_vendor_lib_still_fingerprinted_for_known_cves(self):
        ids = {f.id for f in self.result.findings}
        self.assertIn("SUPPLY-VULNERABLE-LIB-JQUERY", ids)

    def test_real_sink_in_popup_js_still_caught(self):
        hits = [f for f in self.result.findings if f.id == "INJ-INNERHTML"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].file, "popup.js")

    def test_broad_permission_surface_detected(self):
        hit = next((f for f in self.result.findings if f.id == "MANIFEST-BROAD-PERMISSION-SURFACE"), None)
        self.assertIsNotNone(hit, "cookies+history+clipboardRead should trip the broad-surface check")

    def test_permission_combo_now_escalates_to_chain(self):
        ids = {f.id for f in self.result.findings}
        self.assertIn("CHAIN-HOST-EXPOSURE-PLUS-DOM-SINK", ids,
                      "broad permission surface + real DOM sink should chain to SS, not stay flat at B")
        self.assertEqual(self.result.overall_grade(), "SS")

    def test_permissions_have_differentiated_cvss(self):
        by_id = {f.id: f for f in self.result.findings}
        clipboard = by_id["MANIFEST-PERM-CLIPBOARDREAD"]
        history = by_id["MANIFEST-PERM-HISTORY"]
        storage = by_id["MANIFEST-PERM-STORAGE"]
        # clipboardRead (credential-theft vector) must outscore history (read-only privacy)
        self.assertGreater(clipboard.score, history.score)
        # storage permission alone should be near-zero risk
        self.assertEqual(storage.score, 0.0)


class TestCodeContext(unittest.TestCase):
    """Findings should carry exact-location context for fast navigation,
    without ever reproducing a matched secret value."""

    @classmethod
    def setUpClass(cls):
        cls.v1 = scan(str(SAMPLES / "risky-notes-v1"))
        cls.dvbe = scan(str(SAMPLES / "dvbe-like"))

    def test_injection_finding_has_context_around_its_line(self):
        hit = next(f for f in self.dvbe.findings if f.id == "INJ-INNERHTML")
        self.assertTrue(hit.context)
        lines_in_context = [ln for ln, _ in hit.context]
        self.assertIn(hit.line, lines_in_context)
        hit_line_text = dict(hit.context)[hit.line]
        self.assertIn("innerHTML", hit_line_text)

    def test_secret_context_masks_the_credential(self):
        hit = next(f for f in self.v1.findings if f.id == "CRED-AWS-ACCESS-KEY")
        self.assertTrue(hit.context)
        hit_line_text = dict(hit.context)[hit.line]
        self.assertNotIn("AKIA", hit_line_text)
        self.assertIn("*", hit_line_text)

    def test_chain_findings_have_no_misleading_context(self):
        chain = next(f for f in self.dvbe.findings if f.is_chain_finding)
        self.assertEqual(chain.context, [])


class TestManifestDeception(unittest.TestCase):
    """Coverage for the 'attacker can lie in manifest.json' detection module."""

    @classmethod
    def setUpClass(cls):
        cls.result = scan(str(SAMPLES / "deceptive-manifest"))

    def test_war_wildcard_detected(self):
        ids = {f.id for f in self.result.findings}
        self.assertIn("MANDEC-WAR-WILDCARD", ids)
        self.assertIn("MANDEC-WAR-SENSITIVE-FILE", ids)

    def test_optional_permission_ratchet_detected(self):
        ids = {f.id for f in self.result.findings}
        self.assertIn("MANDEC-OPTIONAL-PERMISSION-RATCHET", ids)

    def test_fixed_key_detected(self):
        ids = {f.id for f in self.result.findings}
        self.assertIn("MANDEC-FIXED-KEY", ids)

    def test_devtools_page_detected(self):
        ids = {f.id for f in self.result.findings}
        self.assertIn("MANDEC-DEVTOOLS-PAGE", ids)

    def test_frame_injection_trick_detected(self):
        ids = {f.id for f in self.result.findings}
        self.assertIn("MANDEC-FRAME-INJECTION-TRICK", ids)

    def test_name_impersonation_detected_even_for_exact_normalized_match(self):
        hit = next((f for f in self.result.findings if f.id == "MANDEC-NAME-IMPERSONATION"), None)
        self.assertIsNotNone(hit, "'Lastpass' vs 'LastPass' should still be flagged, not silently skipped as 'probably genuine'")

    def test_unused_permission_cross_reference(self):
        ids = {f.id for f in self.result.findings}
        self.assertIn("MANDEC-UNUSED-PERMISSION-HISTORY", ids,
                      "'history' is declared but never called in this fixture's JS")

    def test_undeclared_api_cross_reference(self):
        ids = {f.id for f in self.result.findings}
        self.assertIn("MANDEC-UNDECLARED-API-MANAGEMENT", ids,
                      "background.js calls chrome.management.getAll() but 'management' isn't declared")

    def test_unknown_manifest_key_detected(self):
        hit = next((f for f in self.result.findings if f.id == "MANDEC-UNKNOWN-MANIFEST-KEY"), None)
        self.assertIsNotNone(hit)
        self.assertIn("x_internal_debug_flag", hit.evidence)

    def test_no_false_positive_on_clean_manifest(self):
        clean = scan(str(SAMPLES / "dvbe-like"))  # has no WAR/key/devtools/optional perms
        ids = {f.id for f in clean.findings}
        self.assertNotIn("MANDEC-WAR-WILDCARD", ids)
        self.assertNotIn("MANDEC-FIXED-KEY", ids)
        self.assertNotIn("MANDEC-DEVTOOLS-PAGE", ids)

    def test_unused_permission_is_a_real_signal_not_noise(self):
        # risky-notes-v1 declares tabs+cookies but background.js never calls either API.
        v1 = scan(str(SAMPLES / "risky-notes-v1"))
        ids = {f.id for f in v1.findings}
        self.assertIn("MANDEC-UNUSED-PERMISSION-TABS", ids)
        self.assertIn("MANDEC-UNUSED-PERMISSION-COOKIES", ids)


class TestV3NewModules(unittest.TestCase):
    """Coverage for the 5 new v3 modules: Crypto, Network, Context, Tab Injection, CORS."""

    @classmethod
    def setUpClass(cls):
        cls.result = scan(str(SAMPLES / "v3-new-module-fixture"))
        cls.ids = {f.id for f in cls.result.findings}

    def test_crypto_broken_algo(self):
        self.assertIn("CRYPTO-BROKEN-ALGO-DES", self.ids)

    def test_crypto_broken_digest(self):
        self.assertIn("CRYPTO-BROKEN-DIGEST", self.ids)

    def test_crypto_insecure_prng(self):
        self.assertIn("CRYPTO-INSECURE-PRNG", self.ids)

    def test_crypto_custom_xor(self):
        self.assertIn("CRYPTO-CUSTOM-XOR", self.ids)

    def test_network_dynamic_dnr(self):
        self.assertIn("NET-DNR-DYNAMIC-RULE", self.ids)

    def test_network_proxy_usage(self):
        self.assertIn("NET-PROXY-USAGE", self.ids)

    def test_network_webrequest_header_hook(self):
        self.assertIn("NET-WEBREQUEST-HEADER-HOOK", self.ids)

    def test_cors_wildcard_header(self):
        self.assertIn("CORS-WILDCARD-HEADER-SET", self.ids)

    def test_cors_no_cors_mode(self):
        self.assertIn("CORS-NO-CORS-MODE-FETCH", self.ids)

    def test_cors_xhr_with_credentials(self):
        self.assertIn("CORS-XHR-WITH-CREDENTIALS", self.ids)

    def test_context_window_chrome_assign(self):
        self.assertIn("CTX-WINDOW-CHROME-ASSIGN", self.ids)

    def test_context_custom_event_chrome(self):
        self.assertIn("CTX-CUSTOM-EVENT-CHROME-DATA", self.ids)

    def test_context_postmessage_chrome(self):
        self.assertIn("CTX-POSTMESSAGE-CHROME-DATA", self.ids)

    def test_tab_injection_dynamic(self):
        self.assertIn("TAB-EXECUTE-SCRIPT-MV3", self.ids)

    def test_chain_tab_injection_plus_messaging(self):
        self.assertIn("CHAIN-TAB-INJECTION-PLUS-UNVALIDATED-MESSAGING", self.ids)

    def test_no_vendor_noise_on_new_modules(self):
        # None of the new crypto/network rules should fire from vendor files
        vendor_hits = [f for f in self.result.findings
                       if f.id.startswith(("CRYPTO-", "NET-", "CTX-", "TAB-", "CORS-"))
                       and any(v in f.file for v in self.result.vendor_files)]
        self.assertEqual(vendor_hits, [])


class TestFetchToEvalRCE(unittest.TestCase):
    """
    Regression coverage for a real engine blind spot: .then(eval) evades a
    plain \\beval\\s*\\( regex entirely, and a hardcoded http:// URL piped into
    that eval was being scored as a lone CVSS 5.9 'cleartext HTTP' finding
    instead of the network-RCE it actually is. Three fixes, tested together:
      1. DYN-EVAL-REFERENCE catches eval passed by reference (.then(eval))
      2. NET-RCE-FETCH-EVAL cross-references a nearby eval reference with a
         remote fetch() call in the same file
      3. CHAIN-REMOTE-RCE-PLUS-BROAD-PERMISSIONS escalates that confirmed RCE
         to SSS (Extinction) when combined with a broad permission surface
    """

    @classmethod
    def setUpClass(cls):
        cls.result = scan(str(SAMPLES / "dvbe-rce-fixture"))
        cls.ids = {f.id for f in cls.result.findings}

    def test_eval_reference_detected(self):
        self.assertIn("DYN-EVAL-REFERENCE", self.ids,
                       ".then(eval) must be caught even though it never calls eval(...)")

    def test_eval_reference_line_is_correct(self):
        hit = next(f for f in self.result.findings if f.id == "DYN-EVAL-REFERENCE")
        self.assertEqual(hit.file, "background.js")
        self.assertEqual(hit.line, 4)

    def test_fetch_to_eval_rce_detected(self):
        self.assertIn("NET-RCE-FETCH-EVAL", self.ids)
        hit = next(f for f in self.result.findings if f.id == "NET-RCE-FETCH-EVAL")
        self.assertGreaterEqual(hit.score, 9.5, "confirmed RCE must not be scored as a low-severity finding")

    def test_extinction_chain_fires(self):
        self.assertIn("CHAIN-REMOTE-RCE-PLUS-BROAD-PERMISSIONS", self.ids)
        chain = next(f for f in self.result.findings if f.id == "CHAIN-REMOTE-RCE-PLUS-BROAD-PERMISSIONS")
        self.assertEqual(chain.rank, "SSS")
        self.assertEqual(chain.score, 10.0)

    def test_overall_grade_is_extinction(self):
        self.assertEqual(self.result.overall_grade(), "SSS")

    def test_chain_components_include_the_actual_permissions(self):
        chain = next(f for f in self.result.findings if f.id == "CHAIN-REMOTE-RCE-PLUS-BROAD-PERMISSIONS")
        self.assertTrue(any("COOKIES" in c for c in chain.chain_ids))
        self.assertTrue(any("HISTORY" in c for c in chain.chain_ids))
        self.assertTrue(any("CLIPBOARDREAD" in c for c in chain.chain_ids))


class TestFetchEvalNegativeControl(unittest.TestCase):
    """A fetch() with no eval nearby, and an eval() with no fetch nearby, must
    NOT be escalated to the RCE finding or the Extinction chain -- proves the
    line-proximity cross-reference isn't just flagging every file that
    happens to contain both patterns anywhere."""

    @classmethod
    def setUpClass(cls):
        cls.result = scan(str(SAMPLES / "negative-control"))
        cls.ids = {f.id for f in cls.result.findings}

    def test_plain_cleartext_still_flagged_normally(self):
        self.assertIn("NET-CLEARTEXT-HTTP", self.ids)
        hit = next(f for f in self.result.findings if f.id == "NET-CLEARTEXT-HTTP")
        self.assertLess(hit.score, 7.0, "unrelated cleartext HTTP shouldn't inherit RCE severity")

    def test_plain_eval_still_flagged_normally(self):
        self.assertIn("DYN-EVAL", self.ids)

    def test_no_false_positive_rce(self):
        self.assertNotIn("NET-RCE-FETCH-EVAL", self.ids)
        self.assertNotIn("CHAIN-REMOTE-RCE-PLUS-BROAD-PERMISSIONS", self.ids)

    def test_no_extinction_grade(self):
        self.assertNotEqual(self.result.overall_grade(), "SSS")


if __name__ == "__main__":
    unittest.main()
