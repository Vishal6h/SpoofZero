"""Offline contracts for unified v3 assessment and historical compatibility."""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from backend.analyzers.fusion_engine import calculate_final_risk
from backend.case_reporting import (
    build_forensic_report, compare_analyses, report_html, report_json,
    verify_report_integrity, _integrity,
)
from backend.case_store import CaseStore, DB_SCHEMA_VERSION
from backend.evidence import Finding, normalize_findings
from backend.fusion_policy import (
    AIWeightAuthorization, CURRENT_FUSION_POLICY, VALIDATED_FUSION_V2,
    LEGACY_FUSION_V1, metadata_fingerprint, risk_level_for_score,
    snapshot_policy_version, has_unified_assessment,
)
from backend.risk_calibration import build_report, load_corpus, scenario_arguments
from frontend.ai_ui import assessment_overview, fusion_disclosure, risk_level_class, score_breakdown_rows
from ml.model_policy import legacy_output_metadata

ROOT = Path(__file__).resolve().parents[1]


def make_analysis(score=0):
    return {
        "email": {"sha256": sha256(b"controlled raw email").hexdigest(),
                  "from": "author@example.test", "processing": {"status": "COMPLETE"}},
        "sender_identity": {"from_domain": "example.test", "risk_score": score, "findings": []},
        "authentication": {
            "risk_score": score, "spf": "pass", "dkim": "pass", "dmarc": "pass", "findings": [],
            "evidence_state": "reported_results",
            "evidence_confidence": {"source": "receiver_inferred", "level": "medium"},
            "reports": [], "selected_report_indices": [],
        },
        "iocs": {"domains": [], "ips": [], "urls": [], "emails": []},
        "attachments": {"attachment_count": 0, "attachments": [], "processing": {"status": "COMPLETE"}},
        "reputation": {"domains": [], "ips": []}, "attachment_reputation": [], "threat_intelligence": [],
        "relay_trace": {"hops": [{"from_host": "a.test", "by_host": "b.test", "chain_status": "START"}],
                        "candidate_origin_ip": None},
        "ai_analysis": {"phishing_probability": 0, **legacy_output_metadata()},
        "geo_analysis": {"service_status": "SKIPPED", "status": "not_available"},
    }


def vt(value="ioc.test", kind="domain", malicious=1, suspicious=0):
    return {"type": kind, "value": value, "status": "success", "service_status": "SUCCESS",
            "analysis_stats": {"malicious": malicious, "suspicious": suspicious}}


def fuse(data, **kwargs):
    return calculate_final_risk(
        data["sender_identity"], data["authentication"], data["relay_trace"],
        data["ai_analysis"], data["reputation"], data["attachment_reputation"],
        evidence_context=data, **kwargs,
    )


def record(data, version=1):
    return {"analysis_id": str(version) * 32, "email_id": data["email"]["sha256"],
            "filename": "fixture.eml", "analyzed_at": "2026-09-15T00:00:00+00:00",
            "version": version, "is_latest": True, "analysis": data}


def report_for(data):
    return build_forensic_report({"case_id": "a" * 32, "name": "Fixture"}, [record(data)],
                                 generated_at="2026-09-15T00:00:00+00:00")


def nodes(assessment, code):
    return [f for f in assessment["normalized_findings"] if f["signal_code"] == code]


class NormalizedFindingTests(unittest.TestCase):
    def test_contract_has_typed_roles_versions_and_source_references(self):
        findings = fuse(make_analysis())["normalized_findings"]
        self.assertTrue(findings)
        for finding in findings:
            self.assertEqual(set(finding), set(Finding.__required_keys__))
            self.assertIn(finding["evidence_role"], {"CONTRIBUTING", "CONTEXTUAL", "UNAVAILABLE"})
            self.assertEqual(finding["scoring_policy_version"], CURRENT_FUSION_POLICY)
            self.assertTrue(all(p.startswith("/") for p in finding["source_paths"]))
        json.dumps(findings, allow_nan=False)

    def test_normalization_and_fusion_are_deterministic_without_mutating_input(self):
        data = make_analysis(18)
        data["reputation"]["domains"] = [vt(), vt()]
        before = deepcopy(data)
        self.assertEqual(normalize_findings(data), normalize_findings(data))
        self.assertEqual(fuse(data), fuse(data))
        self.assertEqual(data, before)

    def test_observation_ids_survive_provider_reordering(self):
        data = make_analysis()
        data["reputation"]["domains"] = [vt("a.test"), vt("b.test")]
        first = {f["finding_id"] for f in nodes(fuse(data), "VT_OBSERVATION")}
        data["reputation"]["domains"].reverse()
        self.assertEqual(first, {f["finding_id"] for f in nodes(fuse(data), "VT_OBSERVATION")})

    def test_duplicate_attachment_hashes_merge_without_stacking_points(self):
        data = make_analysis()
        digest = sha256(b"complete bytes").hexdigest()
        data["attachments"]["attachments"] = [
            {"sha256": digest, "filename": name, "size_bytes": 14} for name in ("private-one.bin", "private-two.bin")
        ]
        data["attachment_reputation"] = [vt(digest, "file_hash", 4)] * 2
        result = fuse(data)
        hashes = nodes(result, "ATTACHMENT_SHA256")
        self.assertEqual(len(hashes), 1)
        self.assertEqual(hashes[0]["occurrence_count"], 2)
        self.assertEqual(len(hashes[0]["source_paths"]), 2)
        self.assertIn("Repeated", hashes[0]["suppression_reason"])
        self.assertEqual(result["attachment_bonus"], 20)
        self.assertEqual(result["threat_score"], 20)

    def test_repeated_domains_ips_and_engine_counts_use_one_category_maximum(self):
        data = make_analysis()
        data["reputation"] = {"domains": [vt(malicious=90)] * 3,
                              "ips": [vt("192.0.2.1", "ip", 90)] * 2}
        result = fuse(data)
        contributors = [f for f in result["normalized_findings"] if f["evidence_role"] == "CONTRIBUTING"]
        self.assertEqual(len(contributors), 1)
        self.assertEqual(result["reputation_bonus"], 20)
        self.assertEqual(sum(f["applied_contribution"] for f in contributors), 20)

    def test_repeated_relay_mismatches_keep_one_bonus(self):
        data = make_analysis()
        data["relay_trace"]["hops"] = [{"chain_status": "MISMATCH"}] * 5
        result = fuse(data)
        self.assertEqual(result["relay_bonus"], 10)
        self.assertEqual(result["threat_score"], 10)
        self.assertEqual(nodes(result, "RELAY_CONTINUITY")[0]["occurrence_count"], 5)

    def test_related_identity_authentication_findings_are_annotated_without_new_deductions(self):
        data = make_analysis(40)
        data["sender_identity"]["findings"] = [{"type": "FROM_RETURN_PATH_MISMATCH"}]
        data["authentication"]["findings"] = [
            {"type": kind} for kind in ("FROM_SPF_MISMATCH", "FROM_DKIM_MISMATCH", "DMARC_FROM_MISMATCH")
        ]
        result = fuse(data)
        related = [f for f in result["normalized_findings"] if "sender_auth_identity" in f["related_groups"]]
        self.assertGreaterEqual(len(related), 6)
        self.assertEqual(result["threat_score"], 40)

    def test_repeated_auth_reports_and_conflict_are_visible(self):
        data = make_analysis(20)
        auth = data["authentication"]
        auth["spf"] = "mixed"
        auth["selected_report_indices"] = [0, 1]
        auth["reports"] = [{"header_index": i, "authserv_id": "receiver.test", "source": "receiver_inferred",
                            "methods": [{"method": "spf", "result": "pass", "usable": True}]} for i in (0, 1)]
        result = fuse(data)
        self.assertEqual(nodes(result, "AUTH_REPORT_SPF")[0]["occurrence_count"], 2)
        self.assertEqual(nodes(result, "REPORTED_SPF")[0]["availability"], "PARTIAL")
        self.assertEqual(result["evidence_confidence"]["level"], "LOW")
        self.assertTrue(result["review_required"])

    def test_derived_behavior_is_context_not_additional_points(self):
        data = make_analysis()
        data["ai_analysis"]["phishing_probability"] = 95
        result = fuse(data)
        self.assertEqual(result["threat_score"], 0)
        self.assertEqual(result["verdict"], "REVIEW REQUIRED")
        derived = nodes(result, "AUTH_PASS_SUSPICIOUS_BEHAVIOR")[0]
        self.assertEqual((derived["evidence_role"], derived["applied_contribution"]), ("CONTEXTUAL", 0))

    def test_dns_geo_urls_and_campaigns_never_add_points(self):
        data = make_analysis()
        data["iocs"]["urls"] = ["https://private.test/login?token=secret"]
        data["threat_intelligence"] = [{"domain": "example.test", "risk_score": 100,
                                        "dns": {"service_status": "SUCCESS"}, "rdap": {"service_status": "SUCCESS"}}]
        data["geo_analysis"] = {"service_status": "SUCCESS", "country": "Example", "asn": 123, "risk_score": 100}
        data["campaign_correlation"] = {"risk_score": 100, "campaigns": ["shared"]}
        result = fuse(data)
        self.assertEqual(result["threat_score"], 0)
        self.assertTrue(all(f["applied_contribution"] == 0 for f in result["normalized_findings"]))

    def test_known_iocs_hashes_and_origin_without_lookups_are_coverage_gaps(self):
        data = make_analysis()
        data["iocs"].update(domains=["private.test"], ips=["192.0.2.7"])
        data["relay_trace"]["candidate_origin_ip"] = "192.0.2.8"
        data["attachments"]["attachments"] = [{"sha256": "a" * 64, "size_bytes": 12}]
        result = fuse(data)
        codes = {f["signal_code"] for f in result["normalized_findings"]}
        self.assertTrue({"VT_DOMAIN_NOT_CHECKED", "VT_IP_NOT_CHECKED", "VT_HASH_NOT_CHECKED",
                         "DNS_RDAP_NOT_CHECKED"}.issubset(codes))
        self.assertEqual(len(nodes(result, "VT_IP_NOT_CHECKED")), 2)
        self.assertEqual(result["evidence_coverage"]["status"], "PARTIAL")
        self.assertTrue(result["review_required"])
        self.assertEqual(result["threat_score"], 0)

    def test_external_availability_states_remain_distinct(self):
        data = make_analysis()
        states = ["NOT_FOUND", "TIMEOUT", "SKIPPED", "RATE_LIMITED", "UNAVAILABLE"]
        data["reputation"]["domains"] = [
            {"value": str(index), "service_status": state} for index, state in enumerate(states)
        ]
        data["threat_intelligence"] = [{"domain": "example.test",
                                      "dns": {"service_status": "SUCCESS", "partial": True},
                                      "rdap": {"service_status": "TIMEOUT"}}]
        result = fuse(data)
        self.assertEqual({f["availability"] for f in nodes(result, "VT_OBSERVATION")}, set(states))
        self.assertEqual(nodes(result, "DNS_CONTEXT")[0]["availability"], "PARTIAL")
        self.assertTrue(all(f["confidence"] is None for f in nodes(result, "VT_OBSERVATION")))
        self.assertEqual(result["threat_score"], 0)

    def test_malformed_detection_counts_cannot_score_or_leak_nonfinite_json(self):
        for count in (True, -1, "9", float("nan"), float("inf"), None):
            with self.subTest(count=count):
                data = make_analysis()
                data["reputation"]["domains"] = [vt(malicious=count)]
                result = fuse(data)
                finding = nodes(result, "VT_OBSERVATION")[0]
                self.assertEqual((finding["availability"], finding["confidence"]), ("MALFORMED", None))
                self.assertEqual(result["reputation_bonus"], 0)
                json.dumps(result, allow_nan=False)

    def test_contradictory_success_and_timeout_cannot_score(self):
        data = make_analysis()
        data["reputation"]["domains"] = [{**vt(malicious=9), "service_status": "TIMEOUT"}]
        self.assertEqual(fuse(data)["reputation_bonus"], 0)

    def test_normalized_metadata_uses_references_instead_of_private_values(self):
        data = make_analysis()
        private = ["mailbox@private.test", "https://private.test/path?token=topsecret",
                   "private-filename.bin", "private raw header", "private message body", "private-ioc.test"]
        data["email"].update({"from": private[0], "raw_headers": private[3], "body": private[4]})
        data["iocs"].update(emails=[private[0]], urls=[private[1]], domains=[private[5]])
        data["attachments"]["attachments"] = [{"filename": private[2], "sha256": "a" * 64, "size_bytes": 1}]
        data["reputation"]["domains"] = [vt(private[5])]
        encoded = json.dumps(fuse(data)["normalized_findings"])
        for value in private:
            self.assertNotIn(value, encoded)


class VersionedAssessmentTests(unittest.TestCase):
    def test_all_exact_requested_risk_boundaries_and_aliases(self):
        for score, level in ((0, "LOW"), (20, "LOW"), (21, "GUARDED"), (40, "GUARDED"),
                             (41, "MEDIUM"), (60, "MEDIUM"), (61, "HIGH"), (80, "HIGH"),
                             (81, "CRITICAL"), (100, "CRITICAL")):
            with self.subTest(score=score):
                result = fuse(make_analysis(score))
                self.assertEqual(result["threat_score"], score)
                self.assertEqual(result["risk_score"], score)
                self.assertEqual(result["risk_level"], level)
                self.assertEqual(result["scoring_version"], CURRENT_FUSION_POLICY)
                self.assertTrue(has_unified_assessment(result))

    def test_band_function_never_coerces_or_rounds_invalid_input(self):
        for value in (-1, 101, True, None, "20", float("nan"), float("inf"), 20.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                risk_level_for_score(value)

    def test_malformed_base_signals_are_rejected(self):
        for value in (True, None, "20", float("nan"), float("inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                fuse(make_analysis(value))

    def test_all_frozen_corpus_inputs_preserve_v2_numeric_and_verdict_semantics(self):
        for scenario in load_corpus()["scenarios"]:
            with self.subTest(scenario=scenario["id"]):
                arguments = scenario_arguments(scenario)
                v2 = calculate_final_risk(**arguments, policy_version=VALIDATED_FUSION_V2)
                v3 = calculate_final_risk(**arguments)
                for field in ("risk_score", "verdict", "contributions", "base_weights",
                              "evidence_scores", "ai_numeric_contribution"):
                    self.assertEqual(v3[field], v2[field], field)
                self.assertEqual(v3["threat_score"], v2["risk_score"])

    def test_frozen_v2_report_stays_exact(self):
        expected = json.loads((ROOT / "data/calibration/fusion_v2_results.json").read_text())
        self.assertEqual(build_report(), expected)

    def test_explicit_v1_v2_keep_original_shapes_and_verdicts(self):
        for version in (LEGACY_FUSION_V1, VALIDATED_FUSION_V2):
            result = fuse(make_analysis(20), policy_version=version)
            self.assertEqual(snapshot_policy_version(result), version)
            for field in ("threat_score", "risk_level", "normalized_findings", "scoring_version"):
                self.assertNotIn(field, result)
        v2 = fuse(make_analysis(20), policy_version=VALIDATED_FUSION_V2)
        self.assertEqual((v2["risk_score"], v2["verdict"]), (20, "LOW RISK"))
        v3 = fuse(make_analysis(20))
        self.assertEqual((v3["risk_level"], v3["verdict"]), ("LOW", "LOW RISK"))

    def test_breakdown_and_findings_reconcile_rounding_and_global_cap(self):
        for base in (1, 18, 75, 100):
            data = make_analysis(base)
            data["sender_identity"]["risk_score"] = base - 1
            data["reputation"]["domains"] = [vt(malicious=9)]
            data["attachment_reputation"] = [vt("a" * 64, "file_hash", 9)]
            data["relay_trace"]["hops"] = [{"chain_status": "MISMATCH"}] * 3
            result = fuse(data)
            breakdown = result["score_breakdown"]
            findings_total = sum(f["applied_contribution"] for f in result["normalized_findings"])
            category_total = sum(c["applied_contribution"] for c in breakdown["categories"])
            self.assertAlmostEqual(findings_total, category_total)
            self.assertAlmostEqual(category_total, result["contributions"]["total_before_rounding_and_cap"])
            self.assertAlmostEqual(category_total + breakdown["rounding_and_cap_adjustment"], result["threat_score"])
            self.assertEqual(breakdown["total"], result["threat_score"])
        self.assertTrue(breakdown["cap_applied"])
        self.assertEqual(result["threat_score"], 100)

    def test_default_ml_is_zero_for_finite_nonfinite_and_malformed_outputs(self):
        for probability in (0, 50, 100, None, "99", float("nan"), float("inf"), True):
            data = make_analysis(18)
            data["ai_analysis"]["phishing_probability"] = probability
            result = fuse(data)
            self.assertEqual((result["threat_score"], result["ai_numeric_contribution"]), (18, 0))
            self.assertEqual(nodes(result, "ML_PHISHING_SIGNAL")[0]["applied_contribution"], 0)
            json.dumps(result, allow_nan=False)

    def test_ai_authorization_does_not_cross_policy_versions(self):
        from test_ai_fusion_safety import future_metadata, future_output
        metadata = future_metadata()
        approval = AIWeightAuthorization(
            model_version=metadata["model_version"], model_metadata_sha256=metadata_fingerprint(metadata),
            weight=0.10, approval_reference="fixture-approval", evaluation_reference="fixture-evaluation",
            fusion_policy_version=VALIDATED_FUSION_V2,
        )
        data = make_analysis()
        data["ai_analysis"] = future_output()
        kwargs = {"ai_model_metadata": metadata, "ai_authorization": approval}
        self.assertEqual(fuse(data, **kwargs)["ai_numeric_contribution"], 0)
        self.assertEqual(fuse(data, policy_version=VALIDATED_FUSION_V2, **kwargs)["ai_numeric_contribution"], 9)

    def test_low_score_partial_coverage_requires_review(self):
        data = make_analysis(18)
        data["reputation"]["domains"] = [{"value": "example.test", "service_status": "TIMEOUT"}]
        result = fuse(data)
        self.assertEqual((result["threat_score"], result["risk_level"]), (18, "LOW"))
        self.assertEqual(result["evidence_coverage"]["status"], "PARTIAL")
        self.assertTrue(result["review_required"])

    def test_missing_auth_provenance_is_not_confident_or_complete(self):
        data = make_analysis(18)
        data["authentication"].pop("evidence_confidence")
        result = fuse(data)
        self.assertIsNone(result["evidence_confidence"]["level"])
        self.assertEqual(result["evidence_coverage"]["status"], "PARTIAL")
        self.assertTrue(result["review_required"])

    def test_maintained_sample_remains_75_with_no_external_requests(self):
        from backend.demo import run_demo_analysis
        with patch("urllib.request.urlopen", side_effect=AssertionError("No HTTP")) as http, \
             patch("socket.getaddrinfo", side_effect=AssertionError("No DNS")) as dns:
            result = run_demo_analysis()["final_assessment"]
        self.assertEqual((result["risk_score"], result["threat_score"], result["risk_level"]), (75, 75, "HIGH"))
        self.assertEqual(result["evidence_confidence"]["level"], "LOW")
        self.assertEqual(result["evidence_coverage"]["status"], "PARTIAL")
        http.assert_not_called()
        dns.assert_not_called()


class PersistenceAndReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "cases.sqlite3"
        self.store = CaseStore(self.path)
        self.case_id = self.store.create_case("Fixture")
        self.data = make_analysis(18)
        self.data["final_assessment"] = fuse(self.data)

    def test_new_json_snapshot_round_trip_without_schema_migration(self):
        self.store.add_analysis(self.case_id, "fixture.eml", self.data)
        saved = self.store.list_analysis_history(self.case_id)[0]["analysis"]
        self.assertEqual(saved, self.data)
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
        self.assertEqual(DB_SCHEMA_VERSION, 1)

    def test_inconsistent_aliases_band_or_version_are_rejected_before_persistence(self):
        for key, value in (("threat_score", 99), ("risk_score", 99), ("risk_level", "CRITICAL"),
                           ("scoring_version", VALIDATED_FUSION_V2)):
            with self.subTest(key=key):
                data = deepcopy(self.data)
                data["final_assessment"][key] = value
                with self.assertRaisesRegex(ValueError, "inconsistent"):
                    self.store.add_analysis(self.case_id, "bad.eml", data)
        self.assertEqual(self.store.list_analysis_history(self.case_id), [])

    def test_historical_v2_json_remains_exact_after_appending_v3(self):
        old = deepcopy(self.data)
        old["final_assessment"] = fuse(old, policy_version=VALIDATED_FUSION_V2)
        self.store.add_analysis(self.case_id, "old.eml", old)
        with sqlite3.connect(self.path) as connection:
            before = connection.execute("SELECT analysis_json FROM analysis_versions").fetchone()[0]
        self.store.add_analysis(self.case_id, "new.eml", self.data, allow_reanalysis=True)
        history = self.store.list_analysis_history(self.case_id)
        self.assertEqual(history[0]["analysis"], old)
        self.assertEqual(history[1]["analysis"], self.data)
        with sqlite3.connect(self.path) as connection:
            after = connection.execute("SELECT analysis_json FROM analysis_versions ORDER BY version").fetchone()[0]
            self.assertEqual(before, after)
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE analysis_versions SET filename='changed'")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM analysis_versions")

    def test_privacy_filter_preserves_minimal_assessment_and_removes_secrets(self):
        self.data["email"].update({"from": "private@personal.test", "body": "body secret"})
        self.data["iocs"].update(emails=["private@personal.test"],
                                 urls=["https://user:password@private.test/path?token=topsecret"])
        self.data["attachments"]["attachments"] = [{"sha256": "a" * 64, "size_bytes": 1,
                                                    "filename": "private-name.bin"}]
        self.data["final_assessment"] = fuse(self.data)
        expected = deepcopy(self.data["final_assessment"])
        self.store.add_analysis(self.case_id, "private.eml", self.data, privacy_safe=True)
        saved = self.store.list_analyses(self.case_id)[0]["analysis"]
        self.assertEqual(saved["final_assessment"], expected)
        serialized = json.dumps(saved)
        for secret in ("private@personal.test", "body secret", "topsecret", "user:password"):
            self.assertNotIn(secret, serialized)
        self.assertEqual(saved["iocs"]["emails"], [])
        self.assertNotIn("private-name.bin", json.dumps(expected["normalized_findings"]))

    def test_risk_level_filter_only_matches_recorded_v3_bands(self):
        old_case = self.store.create_case("Historical")
        old = deepcopy(self.data)
        old["final_assessment"] = fuse(old, policy_version=VALIDATED_FUSION_V2)
        self.store.add_analysis(old_case, "old.eml", old)
        self.store.add_analysis(self.case_id, "new.eml", self.data)
        self.assertEqual([c["case_id"] for c in self.store.list_cases(risk_level="LOW")], [self.case_id])
        self.assertEqual(self.store.list_cases(risk_level="HIGH"), [])
        with self.assertRaises(ValueError):
            self.store.list_cases(risk_level="LIKELY SAFE")

    def test_report_projects_all_v3_fields_with_valid_integrity(self):
        report = report_for(self.data)
        self.assertEqual(report["report_version"], 3)
        risk = report["analyses"][0]["risk_assessment"]
        assessment = self.data["final_assessment"]
        for field in ("threat_score", "risk_level", "scoring_version", "evidence_confidence",
                      "evidence_coverage", "score_breakdown", "normalized_findings", "review_required"):
            self.assertEqual(risk[field], assessment[field], field)
        self.assertEqual(risk["assessment_contract_status"], "RECORDED")
        self.assertEqual({f["finding_id"] for f in risk["strongest_findings"]}, set(assessment["strongest_findings"]))
        self.assertTrue(verify_report_integrity(json.loads(report_json(report))))
        html = report_html(report)
        for label in ("SpoofZero Threat Score", "Evidence Confidence", "Evidence Coverage",
                      "Scoring version", "Score Breakdown", "Strongest Findings", "LOW"):
            self.assertIn(label, html)

    def test_historical_v2_report_is_readable_without_recalculation(self):
        self.data["final_assessment"] = fuse(self.data, policy_version=VALIDATED_FUSION_V2)
        before = deepcopy(self.data)
        report = report_for(self.data)
        risk = report["analyses"][0]["risk_assessment"]
        self.assertEqual(risk["score"], 18)
        self.assertEqual(risk["fusion_policy_version"], VALIDATED_FUSION_V2)
        self.assertIsNone(risk["threat_score"])
        self.assertIsNone(risk["risk_level"])
        self.assertIsNone(risk["evidence_confidence"])
        self.assertIn("not recorded in this historical snapshot", report_html(report))
        self.assertEqual(self.data, before)

    def test_pre_v3_report_shape_still_renders(self):
        self.data["final_assessment"] = fuse(self.data, policy_version=VALIDATED_FUSION_V2)
        report = report_for(self.data)
        risk = report["analyses"][0]["risk_assessment"]
        original_fields = {"score", "verdict", "fusion_policy_version", "contribution_ledger", "reasons"}
        for field in list(risk):
            if field not in original_fields:
                risk.pop(field)
        report["report_version"] = 2
        report["integrity"] = _integrity({k: v for k, v in report.items() if k != "integrity"})
        self.assertIn("18/100", report_html(report))

    def test_tampered_aliases_are_flagged_in_reports_without_choosing_a_score(self):
        self.data["final_assessment"]["threat_score"] = 99
        risk = report_for(self.data)["analyses"][0]["risk_assessment"]
        self.assertEqual(risk["assessment_contract_status"], "INVALID")
        self.assertIsNone(risk["score"])
        self.assertIsNone(risk["threat_score"])

    def test_report_comparison_tracks_confidence_independently_of_score(self):
        other = deepcopy(self.data)
        other["final_assessment"]["evidence_confidence"]["level"] = "LOW"
        comparison = compare_analyses(record(self.data), record(other, 2))
        self.assertEqual([change["field"] for change in comparison["changes"]], ["Evidence confidence"])
        self.assertEqual(comparison["changes"][0]["before"]["level"], "MEDIUM")
        self.assertEqual(comparison["changes"][0]["after"]["level"], "LOW")
        self.assertEqual(other["final_assessment"]["risk_score"], self.data["final_assessment"]["risk_score"])

    def test_new_report_metadata_is_html_escaped(self):
        self.data["final_assessment"]["normalized_findings"][0]["confidence_explanation"] = "<script>unsafe()</script>"
        html = report_html(report_for(self.data))
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

class UnifiedUITests(unittest.TestCase):
    def test_explicit_band_colors_and_neutral_unknown(self):
        expected = {"LOW": "verdict-safe", "GUARDED": "verdict-guarded", "MEDIUM": "verdict-suspicious",
                    "HIGH": "verdict-high", "CRITICAL": "verdict-critical"}
        for band, css in expected.items():
            self.assertEqual(risk_level_class(band), css)
        for unknown in ("OTHER", "", "LIKELY SAFE", None, []):
            self.assertEqual(risk_level_class(unknown), "verdict-unknown")

    def test_historical_v2_ui_keeps_its_score_and_disclosure(self):
        old = fuse(make_analysis(20), policy_version=VALIDATED_FUSION_V2)
        before = deepcopy(old)
        overview = assessment_overview(old)
        self.assertEqual(overview["score"], "20 / 100")
        self.assertEqual(overview["risk_level"], "NOT RECORDED")
        self.assertEqual(overview["coverage"], "NOT RECORDED")
        self.assertFalse(overview["unified"])
        self.assertEqual(fusion_disclosure(old)["policy"], "Validated Evidence v2")
        self.assertFalse(fusion_disclosure(old)["current"])
        self.assertEqual(old, before)

    def test_ui_rejects_divergent_aliases_and_hides_the_breakdown(self):
        result = fuse(make_analysis(18))
        result["threat_score"] = 99
        self.assertTrue(assessment_overview(result)["invalid"])
        self.assertEqual(assessment_overview(result)["score"], "Unavailable")
        self.assertEqual(score_breakdown_rows(result), [])

    def test_streamlit_shows_low_partial_review_and_evidence_details(self):
        from streamlit.testing.v1 import AppTest
        data = make_analysis(18)
        data["reputation"]["domains"] = [{"value": "example.test", "service_status": "TIMEOUT"}]
        data["final_assessment"] = fuse(data)
        with TemporaryDirectory() as directory, patch.dict(
            os.environ, {"SPOOFZERO_CASE_DB": str(Path(directory) / "cases.sqlite3")}
        ):
            app = AppTest.from_file(str(ROOT / "frontend/app.py"))
            app.session_state["spoofzero_result"] = data
            app.run()
            self.assertEqual(len(app.exception), 0, [item.message for item in app.exception])
            visible = "\n".join(item.value for item in list(app.markdown) + list(app.caption))
            for label in ("SpoofZero Threat Score", "18 / 100", "LOW", "Evidence coverage: PARTIAL",
                          "Review: REQUIRED", "Scoring version:", "Strongest contributing evidence"):
                self.assertIn(label, visible)
            self.assertIn("Assessment evidence and confidence", [expander.label for expander in app.expander])

class UnifiedEdgeCaseTests(unittest.TestCase):
    def test_duplicate_report_confidence_uses_weakest_provenance_independent_of_order(self):
        data = make_analysis()
        data["authentication"]["reports"] = [
            {"authserv_id": "receiver.test", "source": source,
             "methods": [{"method": "spf", "result": "pass", "usable": True}]}
            for source in ("receiver_inferred", "untrusted")
        ]
        first = nodes(fuse(data), "AUTH_REPORT_SPF")
        data["authentication"]["reports"].reverse()
        second = nodes(fuse(data), "AUTH_REPORT_SPF")
        self.assertEqual(first, second)
        self.assertEqual(first[0]["confidence"], "LOW")

    def test_missing_relay_data_requires_review_even_with_low_score(self):
        data = make_analysis()
        data["relay_trace"]["hops"] = []
        result = fuse(data)
        self.assertEqual(result["threat_score"], 0)
        self.assertEqual(result["evidence_coverage"]["status"], "PARTIAL")
        self.assertTrue(result["review_required"])

    def test_malformed_provider_error_type_is_not_generic_failure_or_safe(self):
        data = make_analysis()
        data["reputation"]["domains"] = [
            {"service_status": "ERROR", "error_type": "MALFORMED_RESPONSE", "value": "example.test"}
        ]
        result = fuse(data)
        self.assertEqual(nodes(result, "VT_OBSERVATION")[0]["availability"], "MALFORMED")
        self.assertIsNone(nodes(result, "VT_OBSERVATION")[0]["confidence"])

    def test_missing_nested_dns_rdap_results_do_not_inherit_aggregate_success(self):
        data = make_analysis()
        data["threat_intelligence"] = [{"domain": "example.test", "service_status": "SUCCESS", "dns": {}, "rdap": {}}]
        result = fuse(data)
        self.assertEqual(nodes(result, "DNS_CONTEXT")[0]["availability"], "MISSING")
        self.assertEqual(nodes(result, "RDAP_CONTEXT")[0]["availability"], "MISSING")
        self.assertEqual(result["evidence_coverage"]["status"], "PARTIAL")

    def test_malformed_processing_and_identity_metadata_stays_json_safe(self):
        data = make_analysis()
        data["email"]["processing"]["status"] = []
        data["attachments"]["processing"]["status"] = {}
        data["relay_trace"]["hops"][0]["from_host"] = float("nan")
        result = fuse(data)
        self.assertEqual(result["evidence_coverage"]["status"], "PARTIAL")
        json.dumps(result, allow_nan=False)

    def test_conflicting_v3_marker_cannot_downgrade_to_historical_fallback(self):
        data = make_analysis(18)
        data["final_assessment"] = fuse(data)
        data["final_assessment"]["fusion_policy_version"] = VALIDATED_FUSION_V2
        self.assertTrue(assessment_overview(data["final_assessment"])["invalid"])
        self.assertEqual(assessment_overview(data["final_assessment"])["score"], "Unavailable")
        self.assertEqual(report_for(data)["analyses"][0]["risk_assessment"]["assessment_contract_status"], "INVALID")
        with TemporaryDirectory() as directory:
            store = CaseStore(Path(directory) / "cases.sqlite3")
            case_id = store.create_case("Fixture")
            with self.assertRaisesRegex(ValueError, "inconsistent"):
                store.add_analysis(case_id, "bad.eml", data)

    def test_incomplete_or_inconsistent_contract_metadata_cannot_render_as_valid(self):
        for field, value in (("normalized_findings", [None]), ("evidence_confidence", "HIGH"),
                             ("evidence_coverage", None), ("review_required", "false"),
                             ("score_breakdown", {"total": 99})):
            data = make_analysis(18)
            data["final_assessment"] = fuse(data)
            data["final_assessment"][field] = value
            self.assertFalse(has_unified_assessment(data["final_assessment"]))
            self.assertIsNone(report_for(data)["analyses"][0]["risk_assessment"]["score"])

    def test_v3_validated_model_needs_matching_authorization_and_output(self):
        from test_ai_fusion_safety import future_metadata, future_output
        metadata = future_metadata()
        data = make_analysis(20)
        data["ai_analysis"] = future_output()
        self.assertEqual(fuse(data, ai_model_metadata=metadata)["ai_numeric_contribution"], 0)
        approval = AIWeightAuthorization(
            model_version=metadata["model_version"], model_metadata_sha256=metadata_fingerprint(metadata),
            weight=0.10, approval_reference="fixture-approval", evaluation_reference="fixture-evaluation",
            fusion_policy_version=CURRENT_FUSION_POLICY,
        )
        result = fuse(data, ai_model_metadata=metadata, ai_authorization=approval)
        self.assertEqual(result["ai_numeric_contribution"], 9)
        self.assertEqual(nodes(result, "ML_PHISHING_SIGNAL")[0]["evidence_role"], "CONTRIBUTING")
        self.assertEqual(result["evidence_confidence"]["level"], "LOW")
        invalid_metadata = {**metadata, "validated": False}
        self.assertEqual(fuse(data, ai_model_metadata=invalid_metadata, ai_authorization=approval)["ai_numeric_contribution"], 0)


if __name__ == "__main__":
    unittest.main()
