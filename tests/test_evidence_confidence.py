"""Assertion reliability stays separate from severity, scoring and availability."""
import unittest

from backend.evidence import normalize_findings
from backend.evidence_confidence import classify_confidence, summarize_confidence
from test_unified_assessment import make_analysis, fuse, nodes, vt


class EvidenceConfidenceTests(unittest.TestCase):
    def test_complete_hash_identity_is_high_but_never_maliciousness(self):
        data = make_analysis()
        data["attachments"]["attachments"] = [{"sha256": "a" * 64, "size_bytes": 1}]
        finding = nodes(fuse(data), "ATTACHMENT_SHA256")[0]
        self.assertEqual(finding["confidence"], "HIGH")
        self.assertIn("not a maliciousness", finding["confidence_explanation"])
        self.assertEqual((finding["evidence_role"], finding["applied_contribution"]), ("CONTEXTUAL", 0))

    def test_incomplete_attachment_cannot_have_high_hash_confidence(self):
        data = make_analysis()
        data["attachments"]["attachments"] = [{"sha256": "a" * 64, "size_bytes": 1, "status": "skipped"}]
        finding = nodes(fuse(data), "ATTACHMENT_SHA256")[0]
        self.assertIsNone(finding["confidence"])
        self.assertEqual(finding["evidence_role"], "UNAVAILABLE")

    def test_receiver_associated_authentication_is_medium_and_not_verified(self):
        for source in ("receiver_inferred", "configured_receiver"):
            data = make_analysis(20)
            data["authentication"]["evidence_confidence"]["source"] = source
            finding = nodes(fuse(data), "AUTHENTICATION_ASSESSMENT")[0]
            self.assertEqual(finding["confidence"], "MEDIUM")
            self.assertIn("not independently verified", finding["confidence_explanation"])

    def test_untrusted_or_conflicting_authentication_is_low(self):
        for source, conflict in (("untrusted", False), ("receiver_inferred", True)):
            confidence = classify_confidence("reported_authentication", "AVAILABLE",
                                             source=source, conflicting=conflict)
            self.assertEqual(confidence["level"], "LOW")

    def test_unknown_authentication_provenance_is_unclassified(self):
        for source in (None, "invented", {}, []):
            self.assertIsNone(classify_confidence("reported_authentication", "AVAILABLE", source=source)["level"])

    def test_relay_confidence_never_copies_trust_score(self):
        data = make_analysis()
        data["relay_trace"]["hops"] = [{"chain_status": "MISMATCH", "trust_score": 100}]
        result = fuse(data)
        self.assertEqual(result["relay_bonus"], 10)
        self.assertEqual(nodes(result, "RELAY_ASSESSMENT")[0]["confidence"], "LOW")
        self.assertEqual(result["evidence_confidence"]["level"], "LOW")

    def test_ml_probability_never_becomes_confidence_or_default_points(self):
        for probability in (0, 50, 100):
            data = make_analysis()
            data["ai_analysis"]["phishing_probability"] = probability
            finding = nodes(fuse(data), "ML_PHISHING_SIGNAL")[0]
            self.assertEqual(finding["confidence"], "LOW")
            self.assertEqual(finding["applied_contribution"], 0)
            self.assertIn("not evidence confidence", finding["confidence_explanation"])

    def test_geolocation_is_low_contextual_infrastructure_only(self):
        data = make_analysis()
        data["geo_analysis"] = {"service_status": "SUCCESS", "country": "Example", "risk_score": 100}
        finding = nodes(fuse(data), "GEOLOCATION_CONTEXT")[0]
        self.assertEqual((finding["confidence"], finding["evidence_role"], finding["applied_contribution"]),
                         ("LOW", "CONTEXTUAL", 0))
        self.assertIn("person", finding["confidence_explanation"])

    def test_successful_provider_is_medium_regardless_of_detection_total(self):
        data = make_analysis()
        data["reputation"]["domains"] = [vt(malicious=90)]
        result = fuse(data)
        self.assertEqual(nodes(result, "VT_OBSERVATION")[0]["confidence"], "MEDIUM")
        self.assertEqual(result["evidence_confidence"]["level"], "MEDIUM")

    def test_unavailable_observations_never_receive_confidence(self):
        for state in ("MISSING", "NOT_FOUND", "TIMEOUT", "ERROR", "SKIPPED", "UNAVAILABLE",
                      "RATE_LIMITED", "MALFORMED", "NOT_CHECKED", "NOT_APPLICABLE"):
            for assertion in ("hash", "provider", "reported_authentication", "geo", "ml"):
                with self.subTest(state=state, assertion=assertion):
                    self.assertIsNone(classify_confidence(assertion, state, source="receiver_inferred")["level"])

    def test_local_extraction_confidence_is_qualified_when_partial(self):
        self.assertEqual(classify_confidence("extraction", "AVAILABLE")["level"], "HIGH")
        self.assertEqual(classify_confidence("extraction", "PARTIAL")["level"], "LOW")

    def test_severity_labels_do_not_control_assertion_confidence(self):
        data = make_analysis(100)
        data["sender_identity"]["findings"] = [{"type": "FROM_REPLY_TO_MISMATCH", "severity": "CRITICAL"}]
        before = normalize_findings(data)
        data["sender_identity"]["findings"][0]["severity"] = "LOW"
        self.assertEqual(normalize_findings(data), before)
        result = fuse(data)
        self.assertEqual((result["risk_level"], result["evidence_confidence"]["level"]), ("CRITICAL", "MEDIUM"))

    def test_many_high_confidence_context_hashes_cannot_inflate_contributing_confidence(self):
        data = make_analysis()
        data["attachments"]["attachments"] = [{"sha256": format(i, "064x"), "size_bytes": 1} for i in range(20)]
        data["relay_trace"]["hops"] = [{"chain_status": "MISMATCH"}]
        result = fuse(data)
        self.assertEqual(result["evidence_confidence"]["level"], "LOW")
        self.assertEqual(result["evidence_confidence"]["contributing_count"], 1)

    def test_aggregate_uses_weakest_contributor_and_preserves_unclassified(self):
        findings = [{"evidence_role": "CONTRIBUTING", "confidence": level} for level in ("HIGH", "LOW")]
        self.assertEqual(summarize_confidence(findings)["level"], "LOW")
        findings.append({"evidence_role": "CONTRIBUTING", "confidence": None})
        self.assertIsNone(summarize_confidence(findings)["level"])

    def test_no_positive_contributors_is_unclassified_not_high_safety(self):
        result = fuse(make_analysis())
        self.assertIsNone(result["evidence_confidence"]["level"])
        self.assertEqual(result["evidence_confidence"]["contributing_count"], 0)
        self.assertEqual(result["risk_level"], "LOW")

    def test_correlation_reliability_is_low_relationship_context(self):
        confidence = classify_confidence("correlation", "AVAILABLE")
        self.assertEqual(confidence["level"], "LOW")
        self.assertIn("not maliciousness", confidence["explanation"])


if __name__ == "__main__":
    unittest.main()
