import copy
from email.message import EmailMessage
import json
import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from backend.analyzers.auth_analyzer import analyze_authentication
from backend.analyzers.domain_alignment import compare_domains, organizational_domain
from backend.analyzers.email_parser import parse_email
from backend.analyzers.fusion_engine import calculate_final_risk
from backend.analyzers.header_analyzer import analyze_sender_identity


ALL_PASS = "spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com"


def email_data(clauses=ALL_PASS, **extra):
    return {"from": "Sender <sender@example.com>",
            "authentication_results": ["mx.receiver.net; " + clauses],
            "received": ["from outbound.example.com by mx.receiver.net; Thu, 3 Sep 2026 12:00:00 +0000"],
            **extra}


def types(result):
    return {finding["type"] for finding in result["findings"]}


class AuthenticationStatusTests(unittest.TestCase):
    def test_all_major_spf_statuses(self):
        for status, weight in (("pass", 0), ("fail", 30), ("softfail", 15),
                               ("neutral", 0), ("none", 0), ("temperror", 0), ("permerror", 0)):
            with self.subTest(status=status):
                result = analyze_authentication(email_data(ALL_PASS.replace("spf=pass", f"spf={status}")))
                self.assertEqual(result["spf"], status)
                self.assertEqual(result["risk_score"], weight)
                self.assertTrue(result["reports"][0]["methods"][0]["known_result"])
                if status != "pass":
                    self.assertIn("SPF_" + status.upper(), types(result))

    def test_dkim_statuses_and_existing_none_weight(self):
        for status, weight in (("pass", 0), ("fail", 30), ("none", 10),
                               ("temperror", 0), ("permerror", 0), ("neutral", 0), ("policy", 0)):
            with self.subTest(status=status):
                result = analyze_authentication(email_data(ALL_PASS.replace("dkim=pass", f"dkim={status}")))
                self.assertEqual(result["dkim"], status)
                self.assertEqual(result["risk_score"], weight)
                if status != "pass":
                    self.assertIn("DKIM_" + status.upper(), types(result))

    def test_dmarc_statuses(self):
        for status in ("pass", "fail", "bestguesspass", "none", "temperror", "permerror"):
            with self.subTest(status=status):
                result = analyze_authentication(email_data(ALL_PASS.replace("dmarc=pass", f"dmarc={status}")))
                self.assertEqual(result["dmarc"], status)
                self.assertEqual(result["risk_score"], 40 if status == "fail" else 0)
                if status == "bestguesspass":
                    self.assertIn("DMARC_BESTGUESSPASS", types(result))
                    self.assertEqual(result["evidence_state"], "inconclusive")

    def test_unknown_results_are_retained_and_flagged(self):
        for method in ("spf", "dkim", "dmarc"):
            for status in ("vendor-unknown", "passive", "failish"):
                with self.subTest(method=method, status=status):
                    result = analyze_authentication(email_data(ALL_PASS.replace(f"{method}=pass", f"{method}={status}")))
                    self.assertEqual(result[method], status)
                    self.assertEqual(result["evidence_state"], "inconclusive")
                    self.assertIn(method.upper() + "_INCONCLUSIVE", types(result))

    def test_failure_scores_are_compatible_and_capped(self):
        self.assertEqual(analyze_authentication(email_data("spf=fail; dkim=none; dmarc=fail"))["risk_score"], 80)
        self.assertEqual(analyze_authentication(email_data("spf=fail; dkim=fail; dmarc=fail"))["risk_score"], 100)

    def test_errors_are_not_reported_as_verified_failures(self):
        result = analyze_authentication(email_data("spf=temperror; dkim=permerror; dmarc=none"))
        self.assertEqual(result["risk_score"], 0)
        self.assertFalse(any(kind.endswith("_FAIL") for kind in types(result)))
        self.assertFalse(result["verification"]["independently_verified"])

    def test_case_folding_whitespace_comments_and_method_versions(self):
        result = analyze_authentication(email_data(
            'SPF / 1 = PASS (nested (spf=fail)) smtp . mailfrom = "Bounce@MAIL.Example.COM";\r\n'
            '\tDKIM=PASS header.d=EXAMPLE.COM.; DMARC=PASS header.from=Example.com'))
        self.assertEqual((result["spf"], result["dkim"], result["dmarc"]), ("pass", "pass", "pass"))
        self.assertEqual(result["alignment"]["spf"][0]["identity_domain"], "mail.example.com")
        self.assertFalse(result["reports"][0]["malformed"])

    def test_comments_and_quoted_reasons_cannot_inject_passes(self):
        result = analyze_authentication(email_data(
            'spf=fail (nested (spf=pass; dkim=pass)); dkim=fail reason="spf=pass; dmarc=pass"; dmarc=fail'))
        self.assertEqual((result["spf"], result["dkim"], result["dmarc"]), ("fail", "fail", "fail"))
        self.assertEqual(result["risk_score"], 100)

    def test_quoted_authserv_id_and_semicolon_escaped_reason(self):
        data = email_data(authentication_results=[
            '"MX.Receiver.NET" 1; spf=pass reason="semi; quote \\" spf=fail" smtp.mailfrom=example.com'.replace('\\\\"', '\\"')])
        result = analyze_authentication(data)
        self.assertEqual(result["spf"], "pass")
        self.assertEqual(result["evidence_confidence"]["source"], "receiver_inferred")

    def test_unknown_methods_remain_separate(self):
        result = analyze_authentication(email_data("x-spf=pass; arc=pass; spf=fail"))
        self.assertEqual(result["spf"], "fail")
        self.assertEqual([e["method"] for e in result["reports"][0]["methods"]], ["x-spf", "arc", "spf"])

    def test_missing_authentication_results(self):
        for value in (None, [], ""):
            with self.subTest(value=value):
                result = analyze_authentication(email_data(authentication_results=value))
                self.assertEqual([result[m] for m in ("spf", "dkim", "dmarc")], ["unknown"] * 3)
                self.assertEqual(result["evidence_state"], "inconclusive")
                self.assertEqual(result["risk_score"], 0)

    def test_explicit_no_results_does_not_invent_checks(self):
        result = analyze_authentication(email_data("none"))
        self.assertTrue(result["reports"][0]["no_result"])
        self.assertEqual(result["spf"], "unknown")
        self.assertEqual(result["reports"][0]["methods"], [])

    def test_malformed_headers_are_safe_and_preserve_raw_evidence(self):
        for raw in ("not a header", "mx.receiver.net", "mx.receiver.net; spf=",
                    'mx.receiver.net; spf=pass reason="unterminated; dkim=pass',
                    "mx.receiver.net; (unterminated spf=pass", "mx.receiver.net; spf=<script>",
                    "mx.receiver.net; spf=passdkim=pass"):
            with self.subTest(raw=raw):
                result = analyze_authentication(email_data(authentication_results=[raw]))
                self.assertEqual(result["spf"], "unknown")
                self.assertEqual(result["reports"][0]["raw"], raw)
                self.assertIn("AUTH_RESULTS_MALFORMED", types(result))

    def test_duplicate_identity_properties_are_ambiguous(self):
        result = analyze_authentication(email_data("spf=pass smtp.mailfrom=example.com smtp.mailfrom=evil.net"))
        self.assertEqual(result["spf"], "unknown")
        self.assertIsNone(result["alignment"]["spf"][0]["identity_domain"])
        self.assertEqual(result["reports"][0]["methods"][0]["properties"]["smtp.mailfrom"], ["example.com", "evil.net"])

    def test_unsupported_versions_retain_reported_tokens_but_not_pass_semantics(self):
        for raw in ("mx.receiver.net 2; spf=pass", "mx.receiver.net; spf/2=pass"):
            with self.subTest(raw=raw):
                result = analyze_authentication(email_data(authentication_results=[raw]))
                self.assertEqual(result["spf"], "unknown")
                self.assertEqual(result["reports"][0]["methods"][0]["result"], "pass")


class AuthenticationSourceTests(unittest.TestCase):
    def test_exact_receiver_match_is_inferred_not_verified(self):
        result = analyze_authentication(email_data())
        self.assertEqual(result["evidence_confidence"]["source"], "receiver_inferred")
        self.assertEqual(result["evidence_confidence"]["level"], "medium")
        self.assertFalse(result["verification"]["source_authenticity_verified"])

    def test_external_reporter_is_untrusted(self):
        result = analyze_authentication(email_data(authentication_results=["attacker.net; " + ALL_PASS]))
        self.assertEqual(result["evidence_confidence"]["source"], "untrusted")
        self.assertIn("AUTH_UNTRUSTED_SOURCE", types(result))

    def test_receiver_association_requires_exact_match(self):
        result = analyze_authentication(email_data(authentication_results=["evil.mx.receiver.net; " + ALL_PASS]))
        self.assertEqual(result["evidence_confidence"]["source"], "untrusted")

    def test_received_comment_does_not_select_reporter(self):
        data = email_data(received=["from sender.net (by mx.receiver.net) by real.receiver.net; date"])
        result = analyze_authentication(data)
        self.assertEqual(result["evidence_confidence"]["source"], "untrusted")

    def test_receiver_failure_is_not_overwritten_by_injected_pass(self):
        result = analyze_authentication(email_data(authentication_results=[
            "attacker.net; " + ALL_PASS, "mx.receiver.net; spf=fail; dkim=fail; dmarc=fail"]))
        self.assertEqual(result["selected_report_indices"], [1])
        self.assertEqual(result["risk_score"], 100)
        self.assertIn("AUTH_OTHER_REPORTERS", types(result))

    def test_receiver_pass_is_not_overwritten_by_upstream_failure(self):
        result = analyze_authentication(email_data(authentication_results=[
            "upstream.net; spf=fail", "mx.receiver.net; " + ALL_PASS]))
        self.assertEqual(result["spf"], "pass")
        self.assertEqual(len(result["reports"]), 2)

    def test_missing_receiver_method_is_not_filled_from_unrelated_report(self):
        result = analyze_authentication(email_data(authentication_results=[
            "mx.receiver.net; spf=pass", "upstream.net; dmarc=pass; dkim=pass"]))
        self.assertEqual(result["dkim"], "unknown")
        self.assertEqual(result["dmarc"], "unknown")

    def test_same_reporter_separate_method_headers_are_combined(self):
        result = analyze_authentication(email_data(authentication_results=[
            "mx.receiver.net; spf=pass", "mx.receiver.net; dkim=pass", "mx.receiver.net; dmarc=pass"]))
        self.assertEqual(result["selected_report_indices"], [0, 1, 2])
        self.assertEqual([result[m] for m in ("spf", "dkim", "dmarc")], ["pass"] * 3)

    def test_same_reporter_conflicting_checks_are_not_silently_safe(self):
        result = analyze_authentication(email_data(authentication_results=[
            "mx.receiver.net; spf=pass smtp.mailfrom=example.com",
            "mx.receiver.net; spf=fail smtp.mailfrom=example.com"]))
        self.assertEqual(result["spf"], "mixed")
        self.assertEqual(result["risk_score"], 30)
        self.assertIn("SPF_MULTIPLE_RESULTS", types(result))

    def test_trusted_reporter_must_be_explicit_caller_configuration(self):
        data = email_data(authentication_results=["gateway.internal; " + ALL_PASS],
                          trusted_authserv_ids=["gateway.internal"])
        self.assertEqual(analyze_authentication(data)["evidence_confidence"]["source"], "untrusted")
        configured = analyze_authentication(data, trusted_authserv_ids=["gateway.internal"])
        self.assertEqual(configured["evidence_confidence"]["source"], "configured_receiver")
        self.assertFalse(configured["verification"]["source_authenticity_verified"])

    def test_first_report_is_conservative_fallback_without_receiver_context(self):
        result = analyze_authentication(email_data(received=[], authentication_results=[
            "first.net; spf=fail", "second.net; spf=pass"]))
        self.assertEqual(result["spf"], "fail")
        self.assertEqual(result["evidence_confidence"]["level"], "low")

    def test_parser_supports_single_string_input_without_character_iteration(self):
        result = analyze_authentication(email_data(authentication_results="mx.receiver.net; " + ALL_PASS))
        self.assertEqual(result["spf"], "pass")
        self.assertEqual(len(result["reports"]), 1)


class AuthenticationAlignmentTests(unittest.TestCase):
    def test_legitimate_sender_has_exact_alignment(self):
        result = analyze_authentication(email_data())
        self.assertTrue(result["alignment"]["spf"][0]["strict"])
        self.assertTrue(result["alignment"]["dkim"][0]["strict"])
        self.assertTrue(result["alignment"]["dmarc"]["aligned_pass_observed"])
        self.assertEqual(result["risk_score"], 0)

    def test_spf_mailfrom_mismatch_is_visible_without_inventing_dmarc_failure(self):
        result = analyze_authentication(email_data(ALL_PASS.replace("smtp.mailfrom=example.com", "smtp.mailfrom=other.net")))
        self.assertIn("FROM_SPF_MISMATCH", types(result))
        self.assertFalse(result["alignment"]["dmarc"]["spf_pass_aligned"])
        self.assertEqual(result["dmarc"], "pass")
        self.assertTrue(result["alignment"]["dmarc"]["dkim_pass_aligned"])

    def test_dkim_signing_mismatch(self):
        result = analyze_authentication(email_data(ALL_PASS.replace("header.d=example.com", "header.d=other.net")))
        self.assertIn("FROM_DKIM_MISMATCH", types(result))
        self.assertFalse(result["alignment"]["dmarc"]["dkim_pass_aligned"])

    def test_subdomains_share_organizational_alignment(self):
        result = analyze_authentication(email_data(
            "spf=pass smtp.mailfrom=bounce@mailer.example.co.uk; dkim=pass header.d=sign.example.co.uk; dmarc=pass header.from=example.co.uk",
            **{"from": "sender@example.co.uk"}))
        for method in ("spf", "dkim"):
            self.assertTrue(result["alignment"][method][0]["relaxed"])
            self.assertFalse(result["alignment"][method][0]["strict"])
        self.assertNotIn("FROM_SPF_MISMATCH", types(result))
        self.assertNotIn("FROM_DKIM_MISMATCH", types(result))
        self.assertEqual(result["alignment"]["historical_policy_mode"], "unknown")

    def test_different_organizations_under_co_uk_do_not_align(self):
        comparison = compare_domains("bank.co.uk", "attacker.co.uk")
        self.assertFalse(comparison["relaxed"])

    def test_private_suffix_tenants_do_not_align(self):
        self.assertFalse(compare_domains("alice.github.io", "bob.github.io")["relaxed"])
        self.assertTrue(compare_domains("mail.alice.github.io", "alice.github.io")["relaxed"])

    def test_psl_wildcard_exception_is_respected(self):
        self.assertEqual(organizational_domain("mail.city.kawasaki.jp"), "city.kawasaki.jp")
        self.assertTrue(compare_domains("mail.city.kawasaki.jp", "city.kawasaki.jp")["relaxed"])

    def test_public_suffix_alone_does_not_establish_alignment(self):
        self.assertIsNone(compare_domains("co.uk", "co.uk")["relaxed"])
        self.assertIsNone(compare_domains("github.io", "github.io")["relaxed"])

    def test_unknown_suffixes_do_not_get_guessed_organizations(self):
        self.assertIsNone(organizational_domain("a.organization.unregistered-suffix"))
        self.assertIsNone(compare_domains("a.organization.unregistered-suffix", "b.organization.unregistered-suffix")["relaxed"])
        self.assertTrue(compare_domains("organization.test", "organization.test")["strict"])

    def test_idna_case_and_trailing_dots_normalize(self):
        comparison = compare_domains("BÜCHER.de.", "mail.xn--bcher-kva.de")
        self.assertTrue(comparison["relaxed"])

    def test_invalid_or_missing_identities_leave_alignment_unknown(self):
        for identity in ("999.999.999.999", "192.0.2.1", "[2001:db8::1]", "https://example.com/", "", None):
            with self.subTest(identity=identity):
                self.assertEqual(compare_domains("example.com", identity)["status"], "unknown")

    def test_envelope_from_and_helo_identities(self):
        for property_name in ("envelope-from", "smtp.envelope-from", "smtp.mailfrom"):
            with self.subTest(property_name=property_name):
                result = analyze_authentication(email_data(f'spf=pass {property_name}="bounce@mail.example.com" smtp.helo=out.example.net'))
                identity = result["alignment"]["spf"][0]["identities"]
                self.assertEqual(identity["mailfrom_domain"], "mail.example.com")
                self.assertEqual(identity["helo_domain"], "out.example.net")

    def test_helo_pass_cannot_override_mailfrom_fail(self):
        result = analyze_authentication(email_data("spf=pass smtp.helo=example.com; spf=fail smtp.mailfrom=other.net"))
        self.assertEqual(result["spf"], "fail")
        self.assertEqual(len(result["reports"][0]["methods"]), 2)
        self.assertIsNone(result["alignment"]["dmarc"]["spf_pass_aligned"])

    def test_null_mailfrom_and_helo_are_not_assumed_dmarc_alignment(self):
        for clause in ("spf=pass smtp.mailfrom=<> smtp.helo=example.com", "spf=pass smtp.helo=example.com"):
            with self.subTest(clause=clause):
                result = analyze_authentication(email_data(clause))
                self.assertEqual(result["spf"], "pass")
                self.assertIsNone(result["alignment"]["dmarc"]["spf_pass_aligned"])

    def test_return_path_is_not_a_reported_spf_identity(self):
        result = analyze_authentication(email_data("spf=pass", return_path="bounce@example.com"))
        self.assertIsNone(result["alignment"]["spf"][0]["identity_domain"])

    def test_dkim_d_alias(self):
        result = analyze_authentication(email_data("dkim=pass d=example.com"))
        self.assertEqual(result["alignment"]["dkim"][0]["identity_domain"], "example.com")

    def test_multiple_signatures_keep_each_result_and_any_aligned_pass(self):
        result = analyze_authentication(email_data("dkim=fail header.d=forwarder.net; dkim=pass header.d=example.com"))
        self.assertEqual(result["dkim"], "pass")
        self.assertEqual(len(result["alignment"]["dkim"]), 2)
        self.assertTrue(result["alignment"]["dmarc"]["dkim_pass_aligned"])

    def test_aligned_failed_signature_does_not_validate_an_unaligned_pass(self):
        result = analyze_authentication(email_data("dkim=fail header.d=example.com; dkim=pass header.d=forwarder.net; dmarc=pass"))
        self.assertEqual(result["dkim"], "pass")
        self.assertFalse(result["alignment"]["dmarc"]["dkim_pass_aligned"])
        self.assertIn("DMARC_ALIGNMENT_UNSUPPORTED", types(result))

    def test_conflicting_same_signature_domain_results_are_mixed(self):
        result = analyze_authentication(email_data("dkim=fail header.d=example.com; dkim=pass header.d=example.com"))
        self.assertEqual(result["dkim"], "mixed")
        self.assertEqual(result["risk_score"], 30)

    def test_unknown_signature_result_cannot_be_hidden_by_pass(self):
        result = analyze_authentication(email_data("dkim=mystery header.d=other.net; dkim=pass header.d=example.com"))
        self.assertEqual(result["dkim"], "mixed")

    def test_dmarc_header_from_does_not_replace_visible_from(self):
        result = analyze_authentication(email_data(ALL_PASS.replace("header.from=example.com", "header.from=other.net")))
        self.assertEqual(result["alignment"]["from_domain"], "example.com")
        self.assertEqual(result["dmarc"], "pass")
        self.assertIn("DMARC_FROM_MISMATCH", types(result))

    def test_duplicate_or_multi_author_from_is_ambiguous(self):
        for extra in ({"from_headers": ["sender@example.com", "other@other.net"]},
                      {"from": "sender@example.com, other@other.net"}):
            with self.subTest(extra=extra):
                result = analyze_authentication(email_data(**extra))
                self.assertIsNone(result["alignment"]["from_domain"])
                self.assertIn("AUTH_FROM_AMBIGUOUS", types(result))

    def test_related_reply_to_and_return_path_are_not_sender_mismatches(self):
        result = analyze_sender_identity({"from": "sender@example.co.uk", "reply_to": "help@support.example.co.uk", "return_path": "bounce@mail.example.co.uk"})
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["findings"], [])

    def test_unrelated_sender_mismatch_weights_remain_unchanged(self):
        result = analyze_sender_identity({"from": "sender@example.com", "reply_to": "help@example.net", "return_path": "bounce@example.org"})
        self.assertEqual(result["risk_score"], 70)
        self.assertEqual(types(result), {"FROM_REPLY_TO_MISMATCH", "FROM_RETURN_PATH_MISMATCH"})

    def test_unknown_suffix_sender_differences_keep_existing_detection(self):
        result = analyze_sender_identity({"from": "sender@one.test", "reply_to": "other@two.test"})
        self.assertIn("FROM_REPLY_TO_MISMATCH", types(result))


class AuthenticationBehaviorTests(unittest.TestCase):
    def fusion(self, auth=None, sender=None, ai=None, reputation=None, attachments=None, relay=None):
        return calculate_final_risk(
            sender or {"risk_score": 0}, auth if auth is not None else analyze_authentication(email_data()),
            relay or {"hops": []}, ai or {"phishing_probability": 0}, reputation, attachments,
        )

    def assert_behavior_warning(self, result, signal):
        context = result["authentication_context"]
        self.assertEqual(context["finding"]["type"], "AUTH_PASS_SUSPICIOUS_BEHAVIOR")
        self.assertIn(signal, context["behavioral_signals"])
        self.assertIn("Authentication passed, but behavioral evidence remains suspicious.", context["finding"]["message"])
        self.assertIn(context["finding"]["message"], result["reasons"])
        self.assertFalse(context["account_compromise_proven"])
        self.assertNotEqual(result["verdict"], "LIKELY SAFE")

    def test_pass_plus_reply_to_mismatch_is_flagged(self):
        sender = analyze_sender_identity(email_data(reply_to="payments@other.net"))
        result = self.fusion(sender=sender)
        self.assert_behavior_warning(result, "sender_identity")
        self.assertEqual(result["risk_score"], 18)
        self.assertEqual(result["verdict"], "REVIEW REQUIRED")

    def test_pass_plus_ai_phishing_language_is_flagged(self):
        result = self.fusion(ai={"phishing_probability": 85})
        self.assert_behavior_warning(result, "ai_phishing_language")
        self.assertEqual(result["risk_score"], 0)

    def test_pass_plus_suspicious_url_domain_reputation_is_flagged(self):
        result = self.fusion(reputation={"domains": [{"status": "success", "domain": "landing.other.net", "analysis_stats": {"malicious": 2}}]})
        self.assert_behavior_warning(result, "domain_or_ip_reputation")
        self.assertEqual(result["reputation_bonus"], 10)

    def test_pass_plus_attachment_reputation_is_flagged(self):
        result = self.fusion(attachments=[{"status": "success", "analysis_stats": {"suspicious": 1}}])
        self.assert_behavior_warning(result, "attachment_reputation")
        self.assertEqual(result["attachment_bonus"], 5)

    def test_pass_plus_relay_mismatch_is_flagged(self):
        result = self.fusion(relay={"hops": [{"chain_status": "MISMATCH"}]})
        self.assert_behavior_warning(result, "relay_chain")
        self.assertEqual(result["relay_bonus"], 10)

    def test_pass_does_not_discount_other_evidence_scores(self):
        sender, ai = {"risk_score": 70}, {"phishing_probability": 90}
        passed = self.fusion(sender=sender, ai=ai)
        unknown = self.fusion(auth=analyze_authentication(email_data(authentication_results=[])), sender=sender, ai=ai)
        self.assertEqual(passed["risk_score"], unknown["risk_score"])
        self.assertEqual(passed["risk_score"], 32)

    def test_missing_authentication_does_not_get_likely_safe_label(self):
        result = self.fusion(auth=analyze_authentication(email_data(authentication_results=[])))
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertTrue(any("do not establish safety" in reason for reason in result["reasons"]))

    def test_unknown_status_does_not_get_likely_safe_label(self):
        result = self.fusion(auth=analyze_authentication(email_data(ALL_PASS.replace("spf=pass", "spf=vendor-unknown"))))
        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_untrusted_passes_remain_inconclusive_without_behavioral_signals(self):
        result = self.fusion(auth=analyze_authentication(email_data(received=[])))
        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_reported_dmarc_pass_without_supporting_identities_is_inconclusive(self):
        auth = analyze_authentication(email_data(ALL_PASS.replace("smtp.mailfrom=example.com", "smtp.mailfrom=other.net").replace("header.d=example.com", "header.d=other.net")))
        result = self.fusion(auth=auth)
        self.assertEqual(auth["dmarc"], "pass")
        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_bestguesspass_is_not_claimed_as_passed_method(self):
        result = self.fusion(auth=analyze_authentication(email_data("dmarc=bestguesspass")), ai={"phishing_probability": 90})
        self.assertEqual(result["authentication_context"]["reported_pass_methods"], [])
        self.assertIsNone(result["authentication_context"]["finding"])

    def test_partial_pass_warning_is_qualified(self):
        result = self.fusion(auth=analyze_authentication(email_data("spf=pass")), ai={"phishing_probability": 90})
        self.assertTrue(result["authentication_context"]["finding"]["message"].startswith("Some authentication checks passed"))

    def test_pass_without_behavioral_signals_has_no_bec_finding(self):
        result = self.fusion()
        self.assertIsNone(result["authentication_context"]["finding"])
        self.assertEqual(result["risk_score"], 0)

    def test_failed_checks_do_not_receive_pass_warning(self):
        auth = analyze_authentication(email_data("spf=fail; dkim=fail; dmarc=fail"))
        result = self.fusion(auth=auth, ai={"phishing_probability": 90})
        self.assertIsNone(result["authentication_context"]["finding"])

    def test_fusion_keeps_inputs_immutable_and_accepts_old_saved_auth_schema(self):
        auth = {"spf": "pass", "dkim": "pass", "dmarc": "pass", "risk_score": 0, "findings": []}
        before = copy.deepcopy(auth)
        result = self.fusion(auth=auth, sender={"risk_score": 70})
        self.assertEqual(auth, before)
        self.assert_behavior_warning(result, "sender_identity")

    def test_conflicting_pass_and_fail_do_not_support_alignment(self):
        for method, identity in (("spf", "smtp.mailfrom"), ("dkim", "header.d")):
            with self.subTest(method=method):
                auth = analyze_authentication(email_data(f"{method}=pass {identity}=example.com; {method}=fail {identity}=example.com"))
                self.assertIsNone(auth["alignment"]["dmarc"][f"{method}_pass_aligned"])


class AuthenticationIntegrationTests(unittest.TestCase):
    def test_parser_retains_signatures_and_duplicate_from_for_authentication_only(self):
        raw = (b"From: first@example.com\nFrom: second@other.net\n"
               b"DKIM-Signature: v=1; d=example.com; s=selector; b=not-a-signature\n"
               b"DKIM-Signature: v=1; d=other.net; s=selector; b=not-a-signature\n"
               b"Authentication-Results: mx.receiver.net; dkim=pass\n\nBody unchanged")
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.eml"
            path.write_bytes(raw)
            parsed = parse_email(path)
        result = analyze_authentication(parsed)
        self.assertEqual(parsed["body"], "Body unchanged")
        self.assertEqual(len(parsed["from_headers"]), 2)
        self.assertEqual(len(parsed["dkim_signatures"]), 2)
        self.assertEqual(result["alignment"]["declared_dkim_domains"], ["example.com", "other.net"])
        self.assertFalse(result["alignment"]["declared_dkim_domains_verified"])
        self.assertIsNone(result["alignment"]["dkim"][0]["identity_domain"])
        self.assertIsNone(result["alignment"]["from_domain"])

    def test_bare_signature_is_not_a_verified_or_reported_pass(self):
        auth = analyze_authentication(email_data(authentication_results=[], dkim_signatures=[
            "v=1; d=example.com; s=selector; b=not-a-signature"]))
        self.assertEqual(auth["dkim"], "unknown")
        self.assertEqual(auth["alignment"]["declared_dkim_domains"], ["example.com"])
        self.assertFalse(auth["alignment"]["dmarc"]["aligned_pass_observed"])

    def test_malformed_signature_domains_do_not_become_alignment_evidence(self):
        auth = analyze_authentication(email_data(dkim_signatures=[
            "v=1; d=example.com; d=other.net", "v=1; d=example.com (unterminated"]))
        self.assertEqual(auth["alignment"]["declared_dkim_domains"], [])

    def test_authentication_is_offline_and_does_not_mutate_dns_context(self):
        data = email_data("spf=fail; dkim=none; dmarc=fail", threat_intelligence={
            "spf": "v=spf1 +all", "dmarc": "v=DMARC1; p=none", "authentication_results": "pass"})
        before = copy.deepcopy(data)
        with patch("dns.resolver.resolve", side_effect=AssertionError("No DNS")), \
             patch("urllib.request.urlopen", side_effect=AssertionError("No HTTP")), \
             patch("requests.sessions.Session.request", side_effect=AssertionError("No PSL update")):
            auth = analyze_authentication(data)
        self.assertEqual(data, before)
        self.assertEqual((auth["spf"], auth["dmarc"]), ("fail", "fail"))
        self.assertFalse(auth["dns_policy_context"]["used_for_recorded_results"])
        self.assertFalse(auth["dns_policy_context"]["historical_policy_verified"])

    def test_fresh_process_alignment_uses_bundled_psl_without_network_or_cwd_cache(self):
        root = Path(__file__).resolve().parents[1]
        code = """
from unittest.mock import patch
with patch('requests.sessions.Session.request', side_effect=AssertionError('No network')), patch('socket.getaddrinfo', side_effect=AssertionError('No DNS')):
    from backend.analyzers.domain_alignment import compare_domains
    assert compare_domains('mail.example.co.uk', 'example.co.uk')['relaxed'] is True
    assert compare_domains('alice.github.io', 'bob.github.io')['relaxed'] is False
"""
        with TemporaryDirectory() as directory:
            environment = dict(os.environ, PYTHONPATH=str(root), TLDEXTRACT_CACHE=directory)
            process = subprocess.run([sys.executable, "-c", code], cwd=directory, env=environment,
                                     capture_output=True, text=True, timeout=30)
            self.assertEqual(list(Path(directory).iterdir()), [])
        self.assertEqual(process.returncode, 0, process.stderr)

    def test_bec_email_pipeline_storage_and_existing_dashboard(self):
        from backend.analyze import analyze_email
        from backend.case_store import CaseStore
        from streamlit.testing.v1 import AppTest
        root = Path(__file__).resolve().parents[1]
        with TemporaryDirectory() as directory:
            db = str(Path(directory) / "cases.sqlite3")
            message = EmailMessage()
            message["From"] = "Accounts <accounts@example.com>"
            message["Reply-To"] = "payments@example.net"
            message["Subject"] = "Urgent confidential wire transfer"
            message["Authentication-Results"] = "mx.receiver.net; " + ALL_PASS
            message["Received"] = "from mail.example.com by mx.receiver.net; Thu, 3 Sep 2026 12:00:00 +0000"
            message.set_content('Send payment immediately. Review https://billing.example.org/pay')
            path = Path(directory) / "synthetic-bec.eml"
            path.write_bytes(message.as_bytes())
            current_dns = [{"domain": "example.com", "dns_records": {"TXT": ["v=spf1 -all"]}}]
            with patch("backend.analyze.analyze_domains", return_value=current_dns), \
                 patch("backend.analyze.analyze_reputation", return_value={"domains": [], "ips": []}), \
                 patch("backend.analyze.analyze_attachment_reputation", return_value=[]), \
                 patch("urllib.request.urlopen", side_effect=AssertionError("No network")), \
                 patch("dns.resolver.resolve", side_effect=AssertionError("No DNS")):
                result = analyze_email(path)
            self.assertEqual(result["authentication"]["spf"], "pass")
            self.assertEqual(result["threat_intelligence"], current_dns)
            warning = result["final_assessment"]["authentication_context"]["finding"]["message"]
            self.assertIn("behavioral evidence remains suspicious", warning)
            self.assertIn(warning, result["final_assessment"]["reasons"])
            self.assertEqual(json.loads(json.dumps(result)), result)
            store = CaseStore(db)
            case_id = store.create_case("Synthetic authentication readiness")
            store.add_analysis(case_id, path.name, result)
            self.assertEqual(store.list_analyses(case_id)[0]["analysis"], result)
            with patch.dict(os.environ, {"SPOOFZERO_CASE_DB": db}):
                app = AppTest.from_file(str(root / "frontend/app.py"))
                app.session_state["spoofzero_result"] = result
                app.run()
                self.assertEqual(len(app.exception), 0, [e.message for e in app.exception])
                self.assertTrue(any(warning in item.value for item in app.markdown))
                self.assertIn("Raw Evidence", [tab.label for tab in app.tabs])
                for verdict in ("REVIEW REQUIRED", "INCONCLUSIVE"):
                    with self.subTest(verdict=verdict):
                        display_result = copy.deepcopy(result)
                        display_result["final_assessment"]["verdict"] = verdict
                        app.session_state["spoofzero_result"] = display_result
                        app.run()
                        self.assertEqual(len(app.exception), 0)
                        self.assertTrue(any('verdict-suspicious' in item.value and verdict in item.value
                                            for item in app.markdown))


if __name__ == "__main__":
    unittest.main()
