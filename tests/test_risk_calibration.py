"""Offline validation of the fusion calibration corpus and frozen analysis."""
import copy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from backend.analyze import analyze_email

from backend.analyzers.campaign_correlator import correlate_emails
from backend.analyzers.fusion_engine import calculate_final_risk
from backend.case_store import CaseStore
from backend.fusion_policy import (
    CURRENT_FUSION_POLICY, LEGACY_FUSION_V1, VERDICT_THRESHOLDS,
)
from backend.risk_calibration import (
    DEFAULT_CORPUS, build_report, evaluate_scenario, load_corpus, outcome_class,
    scenario_arguments,
)
from ml.model_policy import legacy_output_metadata
from test_campaign_correlation import analysis, record
from frontend.ai_ui import score_breakdown_rows


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "data/calibration/fusion_v2_results.json"


class CalibrationCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = load_corpus()
        cls.report = build_report(cls.corpus)

    def test_corpus_is_safe_reproducible_and_covers_required_categories(self):
        self.assertEqual(self.corpus["scenario_count"], 33)
        categories = {item["category"] for item in self.corpus["scenarios"]}
        required = {
            "clearly_legitimate_business", "legitimate_newsletter_service",
            "legitimate_third_party_infrastructure", "sender_reply_to_mismatch",
            "spf_failure", "dkim_failure", "dmarc_failure",
            "authentication_missing_inconclusive", "suspicious_url_domain",
            "malicious_reputation_evidence", "suspicious_attachment_hash",
            "relay_chain_mismatch", "bec_style_valid_authentication",
            "obvious_spoofing", "multiple_weak_indicators", "one_strong_indicator",
        }
        self.assertTrue(required.issubset(categories))
        self.assertEqual(
            {item["source"] for item in self.corpus["scenarios"]},
            {"repository_safe_sample", "synthetic_controlled_fixture"},
        )
        self.assertIn("not ground-truth", self.corpus["limitations"])
        self.assertNotIn("body", json.dumps(self.corpus).lower())

    def test_corpus_validation_rejects_duplicates_unknown_sources_and_bad_scores(self):
        for mutate in (
            lambda data: data["scenarios"][1].update(id=data["scenarios"][0]["id"]),
            lambda data: data["scenarios"][0].update(source="private_email"),
            lambda data: data["scenarios"][0]["inputs"].update(sender_score=101),
            lambda data: data.update(scenario_count=999),
        ):
            with self.subTest(mutate=mutate):
                data = copy.deepcopy(self.corpus)
                mutate(data)
                with TemporaryDirectory() as directory:
                    path = Path(directory) / "bad.json"
                    path.write_text(json.dumps(data), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        load_corpus(path)

    def test_frozen_results_are_exactly_reproducible(self):
        frozen = json.loads(RESULTS.read_text(encoding="utf-8"))
        self.assertEqual(self.report, frozen)
        self.assertEqual(build_report(load_corpus(DEFAULT_CORPUS)), frozen)

    def test_repository_demo_aggregate_fixture_matches_offline_analyzers(self):
        item = next(x for x in self.corpus["scenarios"]
                    if x["source"] == "repository_safe_sample")
        with patch("backend.analyzers.reputation_analyzer.VT_API_KEY", None), \
             patch("urllib.request.urlopen", side_effect=OSError("offline")):
            actual = analyze_email(ROOT / item["source_path"])
        inputs = item["inputs"]
        self.assertEqual(inputs["sender_score"], actual["sender_identity"]["risk_score"])
        self.assertEqual(inputs["authentication_score"], actual["authentication"]["risk_score"])
        self.assertEqual(inputs["authentication_results"], {
            key: actual["authentication"][key] for key in ("spf", "dkim", "dmarc")
        })
        self.assertEqual(inputs["authentication_evidence_source"],
                         actual["authentication"]["evidence_confidence"]["source"])
        self.assertEqual(inputs["authentication_evidence_state"],
                         actual["authentication"]["evidence_state"])
        self.assertEqual(inputs["ai_score"], actual["ai_analysis"]["phishing_probability"])
        self.assertEqual(evaluate_scenario(item)["score"], actual["final_assessment"]["risk_score"])

    def test_distribution_and_miss_inventory_are_explicit(self):
        self.assertEqual(self.report["score_distribution"], {
            "0-19": 16, "20-39": 6, "40-59": 4, "60-79": 3, "80-100": 4,
        })
        self.assertEqual(self.report["classification_distribution"], {
            "false_high": 1, "false_low": 10, "match": 22,
        })
        self.assertEqual(self.report["false_high"], ["legit-third-party-mailer"])
        self.assertIn("spf-failure", self.report["false_low"])
        self.assertIn("suspicious-url-no-reputation", self.report["false_low"])
        self.assertEqual(self.report["decision"]["weights"], "KEEP")
        self.assertEqual(self.report["decision"]["bonuses"], "KEEP")
        self.assertEqual(self.report["decision"]["thresholds"], "KEEP")


class CalibrationBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = load_corpus()
        cls.by_id = {item["id"]: item for item in cls.corpus["scenarios"]}
        cls.report = build_report(cls.corpus)

    def test_all_scenarios_are_deterministic_bounded_and_use_v2(self):
        for item in self.corpus["scenarios"]:
            with self.subTest(item=item["id"]):
                first = evaluate_scenario(item)
                second = evaluate_scenario(item)
                self.assertEqual(first, second)
                self.assertGreaterEqual(first["score"], 0)
                self.assertLessEqual(first["score"], 100)
                self.assertEqual(first["fusion_policy_version"], CURRENT_FUSION_POLICY)
                self.assertEqual(first["ai_numeric_contribution"], 0)

    def test_explanation_contributions_reconcile_every_final_score(self):
        for item in self.corpus["scenarios"]:
            with self.subTest(item=item["id"]):
                result = calculate_final_risk(**scenario_arguments(item))
                contributions = result["contributions"]
                pieces = sum(contributions[key] for key in (
                    "sender_identity", "authentication", "reputation",
                    "attachment", "relay", "ai",
                ))
                self.assertAlmostEqual(pieces, contributions["total_before_rounding_and_cap"])
                self.assertAlmostEqual(
                    pieces + contributions["rounding_and_cap_adjustment"],
                    result["risk_score"],
                )
                self.assertEqual(contributions["total"], result["risk_score"])
                self.assertEqual(result["verdict_thresholds"], dict(VERDICT_THRESHOLDS))
                self.assertTrue(result["score_explanation"])
                self.assertTrue(result["reasons"] or result["risk_score"] == 0)

    def test_displayed_breakdown_reconciles_and_old_snapshots_remain_unchanged(self):
        result = calculate_final_risk(
            **scenario_arguments(self.by_id["all-bonuses-cap"])
        )
        rows = score_breakdown_rows(result)
        self.assertEqual(rows[-1]["Evidence"], "Final forensic risk score")
        self.assertAlmostEqual(
            sum(row["Contribution"] for row in rows[:-1]),
            rows[-1]["Contribution"], places=4,
        )
        self.assertEqual(
            next(row["Contribution"] for row in rows if row["Evidence"] == "AI model signal"),
            0,
        )
        for item in self.corpus["scenarios"]:
            assessment = calculate_final_risk(**scenario_arguments(item))
            displayed = score_breakdown_rows(assessment)
            self.assertAlmostEqual(
                sum(row["Contribution"] for row in displayed[:-1]),
                assessment["risk_score"], places=4,
            )
        malformed = copy.deepcopy(result)
        malformed["contributions"]["total"] = 45
        self.assertEqual(score_breakdown_rows(malformed), [])
        malformed["contributions"]["total"] = float("nan")
        self.assertEqual(score_breakdown_rows(malformed), [])
        legacy = {"risk_score": 69, "verdict": "HIGH RISK"}
        before = copy.deepcopy(legacy)
        self.assertEqual(score_breakdown_rows(legacy), [])
        self.assertEqual(legacy, before)

    def test_aligned_legitimate_messages_stay_low(self):
        for identity in ("legit-business", "legit-newsletter"):
            outcome = evaluate_scenario(self.by_id[identity])
            self.assertEqual(outcome["actual_class"], "LOW")
            self.assertEqual(outcome["score"], 0)

    def test_strong_combined_failures_raise_high_or_critical(self):
        self.assertEqual(
            evaluate_scenario(self.by_id["obvious-spoof"])["actual_class"], "CRITICAL"
        )
        self.assertEqual(
            evaluate_scenario(self.by_id["strong-evidence-stack"])["actual_class"],
            "CRITICAL",
        )
        self.assertEqual(
            evaluate_scenario(self.by_id["mixed-high-evidence"])["actual_class"], "HIGH"
        )

    def test_authenticated_bec_language_remains_qualitative_review_evidence(self):
        result = calculate_final_risk(
            **scenario_arguments(self.by_id["authenticated-bec-language"])
        )
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["verdict"], "REVIEW REQUIRED")
        self.assertEqual(result["ai_numeric_contribution"], 0)
        self.assertIn("ai_phishing_language",
                      result["authentication_context"]["behavioral_signals"])

    def test_duplicate_bonus_evidence_does_not_stack(self):
        checks = self.report["duplicate_bonus_checks"]
        self.assertEqual(checks["reputation_single"], checks["reputation_repeated"])
        self.assertEqual(checks["attachment_single"], checks["attachment_repeated"])
        self.assertEqual(checks["relay_single"], checks["relay_repeated"])
        self.assertEqual(checks, {
            "reputation_single": 20, "reputation_repeated": 20,
            "attachment_single": 20, "attachment_repeated": 20,
            "relay_single": 10, "relay_repeated": 10,
        })

    def test_bonus_stacking_caps_and_reconciles(self):
        result = calculate_final_risk(
            **scenario_arguments(self.by_id["all-bonuses-cap"])
        )
        self.assertEqual(result["risk_score"], 100)
        self.assertTrue(result["contributions"]["cap_applied"])
        self.assertLess(result["contributions"]["rounding_and_cap_adjustment"], 0)
        pieces = sum(result["contributions"][key] for key in (
            "sender_identity", "authentication", "reputation",
            "attachment", "relay", "ai",
        ))
        self.assertAlmostEqual(
            pieces + result["contributions"]["rounding_and_cap_adjustment"], 100
        )

    def test_one_factor_sensitivity_is_monotonic_and_documents_dominance(self):
        for name in ("sender_identity", "authentication"):
            scores = [row["score"] for row in self.report["sensitivity"][name]]
            self.assertEqual(scores, sorted(scores))
        self.assertEqual(self.report["sensitivity"]["sender_identity"][-1]["score"], 46)
        self.assertEqual(self.report["sensitivity"]["authentication"][-1]["score"], 54)
        self.assertEqual(
            [row["bonus"] for row in self.report["sensitivity"]["reputation"]],
            [0, 5, 10, 15, 20, 20],
        )
        self.assertEqual(
            [row["bonus"] for row in self.report["sensitivity"]["attachment"]],
            [0, 5, 10, 15, 20, 20],
        )
        self.assertEqual(
            [row["bonus"] for row in self.report["sensitivity"]["relay"]],
            [0, 10, 10, 10],
        )
        self.assertEqual(
            sum(self.report["dominant_evidence"].values()),
            self.report["scenario_count"],
        )

    def test_numeric_threshold_boundaries_remain_20_40_60_80(self):
        def result_for(sender, authentication):
            return calculate_final_risk(
                {"risk_score": sender},
                {"risk_score": authentication, "findings": []},
                {"hops": []},
                {"phishing_probability": 100, **legacy_output_metadata()},
            )
        cases = (
            (20, 20 * 13 / 6, 0, "LOW RISK"),
            (40, 40 * 13 / 6, 0, "SUSPICIOUS"),
            (60, 100, (60 * 13 - 600) / 7, "HIGH RISK"),
            (80, 100, (80 * 13 - 600) / 7, "CRITICAL"),
        )
        for expected, sender, authentication, verdict in cases:
            with self.subTest(expected=expected):
                result = result_for(sender, authentication)
                self.assertEqual(result["risk_score"], expected)
                self.assertEqual(result["verdict"], verdict)

    def test_historical_v1_and_saved_case_compatibility_remain(self):
        item = self.by_id["obvious-spoof"]
        args = scenario_arguments(item)
        historical = calculate_final_risk(**args, policy_version=LEGACY_FUSION_V1)
        self.assertEqual(historical["fusion_policy_version"], LEGACY_FUSION_V1)
        snapshot = analysis()
        snapshot["final_assessment"] = historical
        before = copy.deepcopy(snapshot)
        with TemporaryDirectory() as directory:
            store = CaseStore(Path(directory) / "case.sqlite3")
            case_id = store.create_case("Historical")
            self.assertTrue(store.add_analysis(case_id, "old.eml", snapshot))
            loaded = store.list_analyses(case_id)[0]["analysis"]
        self.assertEqual(loaded, before)
        self.assertEqual(snapshot, before)

    def test_campaign_correlation_is_independent_of_calibration_metadata(self):
        left = analysis(sender="a@one.test", urls=["https://shared.test/a"])
        right = analysis(sender="b@two.test", urls=["https://shared.test/a"])
        calibrated = evaluate_scenario(self.by_id["multiple-weak-indicators"])
        left["final_assessment"].update(calibration=calibrated)
        right["final_assessment"].update(calibration=calibrated)
        records = [record("one", left), record("two", right)]
        before = copy.deepcopy(records)
        result = correlate_emails(records)
        self.assertEqual(len(result["campaigns"]), 1)
        self.assertEqual(records, before)


if __name__ == "__main__":
    unittest.main()
