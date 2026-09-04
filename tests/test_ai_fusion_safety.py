"""Offline regressions for versioned fusion and zero-weight unvalidated AI."""
import copy
import json
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from backend.analyze import analyze_email
from backend.analyzers.fusion_engine import calculate_final_risk
from backend.case_store import CaseStore
from backend.analyzers.campaign_correlator import correlate_emails
from backend.fusion_policy import (
    AIWeightAuthorization,
    AUTHENTICATION_SHARE,
    CURRENT_FUSION_POLICY,
    LEGACY_FUSION_V1,
    SENDER_SHARE,
    ai_numeric_policy,
    metadata_fingerprint,
    snapshot_policy_version,
)
from frontend.ai_ui import ai_evidence_label, fusion_disclosure, score_label
from ml.model_policy import legacy_output_metadata
from test_campaign_correlation import analysis, record


ROOT = Path(__file__).resolve().parents[1]


def auth(score=0):
    return {
        "risk_score": score, "spf": "none", "dkim": "none", "dmarc": "none",
        "findings": [], "evidence_confidence": {},
    }


def passing_bundle():
    return {
        "passed_all": True, "failed": [],
        "gates": {
            "representative_holdout": {
                "actual": True, "limit": True, "operator": "is", "passed": True,
            },
            "recall": {
                "actual": 0.94, "limit": 0.90, "operator": ">=", "passed": True,
            },
        },
    }


def future_metadata():
    return {
        "model_version": "reviewed_future_fixture",
        "validation_status": "VALIDATED",
        "validated": True,
        "activation_eligible": True,
        "blockers": [],
        "development_gates": passing_bundle(),
        "final_confirmation_gates": passing_bundle(),
    }


def future_output(probability=90):
    return {
        "phishing_probability": probability,
        "verdict": "HIGH PHISHING LIKELIHOOD",
        "model_version": "reviewed_future_fixture",
        "model_status": "VALIDATED",
        "validation_status": "VALIDATED",
        "evidence_role": "supporting_evidence_only",
    }


def authorized(metadata, weight=0.10):
    return AIWeightAuthorization(
        model_version=metadata["model_version"],
        model_metadata_sha256=metadata_fingerprint(metadata),
        weight=weight,
        approval_reference="fixture-review-001",
        evaluation_reference="fixture-evaluation-001",
    )


class FusionV2Tests(unittest.TestCase):
    def score(self, sender=0, authentication=0, ai=0, **kwargs):
        return calculate_final_risk(
            {"risk_score": sender}, auth(authentication), {"hops": []},
            {"phishing_probability": ai, **legacy_output_metadata()}, **kwargs,
        )

    def test_v2_non_ai_weights_sum_to_one_and_preserve_relative_ratio(self):
        result = self.score(sender=70, authentication=40, ai=58.05)
        weights = result["base_weights"]
        self.assertAlmostEqual(sum(weights.values()), 1)
        self.assertAlmostEqual(weights["sender_identity"], SENDER_SHARE)
        self.assertAlmostEqual(weights["authentication"], AUTHENTICATION_SHARE)
        self.assertEqual(weights["ai_phishing"], 0)
        self.assertAlmostEqual(
            weights["authentication"] / weights["sender_identity"], 7 / 6
        )
        self.assertEqual(result["risk_score"], 54)

    def test_unvalidated_ai_contributes_exactly_zero(self):
        result = self.score(sender=60, authentication=50, ai=100)
        self.assertEqual(result["fusion_policy_version"], CURRENT_FUSION_POLICY)
        self.assertEqual(result["ai_numeric_contribution"], 0)
        self.assertEqual(result["ai_weight_applied"], 0)
        self.assertFalse(result["ai_included_in_numeric_score"])
        self.assertEqual(result["ai_validation_status"], "NOT VALIDATED")
        self.assertEqual(result["evidence_scores"]["ai_phishing"], 100)
        self.assertIn("excluded from numeric score", " ".join(result["reasons"]))

    def test_changing_unvalidated_ai_signal_does_not_change_v2_numeric_score(self):
        scores = {
            self.score(sender=60, authentication=50, ai=value)["risk_score"]
            for value in (0, 1, 49.99, 50, 58.05, 100)
        }
        self.assertEqual(scores, {55})

    def test_validated_and_eligible_without_explicit_weight_still_contributes_zero(self):
        metadata = future_metadata()
        result = calculate_final_risk(
            {"risk_score": 60}, auth(50), {"hops": []}, future_output(),
            ai_model_metadata=metadata,
        )
        self.assertTrue(result["ai_model_eligible"])
        self.assertEqual(result["ai_weight_applied"], 0)
        self.assertEqual(result["ai_numeric_contribution"], 0)
        self.assertFalse(result["ai_included_in_numeric_score"])
        self.assertIsNone(result["ai_scoring_authorization"])

    def test_explicit_future_weight_is_model_bound_and_auditable(self):
        metadata = future_metadata()
        approval = authorized(metadata)
        result = calculate_final_risk(
            {"risk_score": 70}, auth(40), {"hops": []}, future_output(),
            ai_model_metadata=metadata, ai_authorization=approval,
        )
        self.assertTrue(result["ai_model_eligible"])
        self.assertTrue(result["ai_included_in_numeric_score"])
        self.assertEqual(result["ai_weight_applied"], 0.10)
        self.assertEqual(result["ai_numeric_contribution"], 9)
        self.assertEqual(result["ai_scoring_authorization"]["approval_reference"],
                         "fixture-review-001")
        self.assertAlmostEqual(sum(result["base_weights"].values()), 1)
        self.assertEqual(result["risk_score"], 57)

    def test_mismatched_or_unvalidated_future_policy_fails_to_zero(self):
        metadata = future_metadata()
        wrong = copy.deepcopy(metadata)
        wrong["model_version"] = "different"
        cases = (
            (wrong, authorized(metadata)),
            ({**metadata, "validated": False}, authorized(metadata)),
            (metadata, None),
        )
        for candidate, approval in cases:
            with self.subTest(candidate=candidate["model_version"], approval=bool(approval)):
                decision = ai_numeric_policy(
                    future_output(), model_metadata=candidate, authorization=approval
                )
                self.assertEqual(decision["weight"], 0)
                self.assertFalse(decision["included"])

    def test_authorization_requires_a_bounded_explicit_weight_and_audit_references(self):
        metadata = future_metadata()
        base = dict(
            model_version=metadata["model_version"],
            model_metadata_sha256=metadata_fingerprint(metadata),
            approval_reference="approval", evaluation_reference="evaluation",
        )
        for weight in (0, -0.01, 0.40, 1, True, float("nan")):
            with self.subTest(weight=weight):
                with self.assertRaises(ValueError):
                    AIWeightAuthorization(weight=weight, **base)
        with self.assertRaises(ValueError):
            AIWeightAuthorization(weight=0.10, **{**base, "approval_reference": ""})

    def test_reputation_attachment_and_relay_bonuses_are_compatible(self):
        result = calculate_final_risk(
            {"risk_score": 0}, auth(), {"hops": [{"chain_status": "MISMATCH"}]},
            {"phishing_probability": 100, **legacy_output_metadata()},
            {"domains": [{"status": "success", "analysis_stats": {"malicious": 1}}]},
            [{"status": "success", "analysis_stats": {"suspicious": 1}}],
        )
        self.assertEqual(result["base_score_before_bonuses"], 0)
        self.assertEqual(result["reputation_bonus"], 10)
        self.assertEqual(result["attachment_bonus"], 5)
        self.assertEqual(result["relay_bonus"], 10)
        self.assertEqual(result["risk_score"], 25)

    def test_v2_scoring_is_deterministic_and_bounded(self):
        kwargs = dict(
            sender_identity={"risk_score": 999},
            authentication=auth(999),
            relay_trace={"hops": [{"chain_status": "MISMATCH"}]},
            ai_analysis={"phishing_probability": 100, **legacy_output_metadata()},
            reputation={"ips": [{"status": "success", "analysis_stats": {"malicious": 9}}]},
            attachment_reputation=[{"status": "success", "analysis_stats": {"malicious": 9}}],
        )
        first = calculate_final_risk(**kwargs)
        second = calculate_final_risk(**kwargs)
        self.assertEqual(first, second)
        self.assertEqual(first["risk_score"], 100)
        self.assertGreaterEqual(first["risk_score"], 0)

    def test_unknown_policy_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unknown fusion policy"):
            self.score(policy_version="invented_policy")


class LegacyCompatibilityTests(unittest.TestCase):
    def test_legacy_v1_formula_and_demo_inputs_remain_exact(self):
        result = calculate_final_risk(
            {"risk_score": 70}, auth(80), {"hops": []},
            {"phishing_probability": 58.05, **legacy_output_metadata()},
            policy_version=LEGACY_FUSION_V1,
        )
        self.assertEqual(result["risk_score"], 69)
        self.assertEqual(result["fusion_policy_version"], LEGACY_FUSION_V1)
        self.assertAlmostEqual(result["base_score_before_bonuses"], 69.3175)
        self.assertAlmostEqual(result["ai_numeric_contribution"], 20.3175)
        self.assertTrue(result["ai_included_in_numeric_score"])

    def test_legacy_v1_retains_existing_bonus_behavior(self):
        result = calculate_final_risk(
            {"risk_score": 70}, auth(80), {"hops": [{"chain_status": "MISMATCH"}]},
            {"phishing_probability": 58.05, **legacy_output_metadata()},
            {"domains": [{"status": "success", "analysis_stats": {"malicious": 1}}]},
            [{"status": "success", "analysis_stats": {"suspicious": 1}}],
            policy_version=LEGACY_FUSION_V1,
        )
        self.assertEqual(result["reputation_bonus"], 10)
        self.assertEqual(result["attachment_bonus"], 5)
        self.assertEqual(result["relay_bonus"], 10)
        self.assertEqual(result["risk_score"], 94)

    def test_snapshot_policy_identification_never_recalculates(self):
        self.assertEqual(snapshot_policy_version({}), "LEGACY SNAPSHOT")
        self.assertEqual(snapshot_policy_version(
            {"ai_context": {"calculation_version": LEGACY_FUSION_V1}}
        ), LEGACY_FUSION_V1)
        self.assertEqual(snapshot_policy_version(
            {"fusion_policy_version": CURRENT_FUSION_POLICY, "risk_score": 75}
        ), CURRENT_FUSION_POLICY)
        self.assertEqual(snapshot_policy_version(
            {"fusion_policy_version": "other", "risk_score": 12}
        ), "UNKNOWN SNAPSHOT")

    def test_reanalysis_uses_v2_and_does_not_rewrite_legacy_snapshot(self):
        with patch("backend.analyzers.reputation_analyzer.VT_API_KEY", None), \
             patch("urllib.request.urlopen", side_effect=AssertionError("offline")):
            fresh = analyze_email(ROOT / "data" / "samples" / "test.eml")
        old = copy.deepcopy(fresh)
        old["final_assessment"] = calculate_final_risk(
            old["sender_identity"], old["authentication"], old["relay_trace"],
            old["ai_analysis"], old["reputation"], old["attachment_reputation"],
            policy_version=LEGACY_FUSION_V1,
        )
        for key in (
            "fusion_policy_version", "ai_numeric_contribution", "ai_weight_applied",
            "ai_validation_status", "ai_included_in_numeric_score", "ai_model_eligible",
            "ai_scoring_reason", "ai_scoring_authorization", "score_explanation",
            "base_weights", "base_contributions", "base_score_before_bonuses",
            "ai_context",
        ):
            old["final_assessment"].pop(key, None)
        with TemporaryDirectory() as directory:
            store = CaseStore(Path(directory) / "case.sqlite3")
            case_id = store.create_case("Historical")
            self.assertTrue(store.add_analysis(case_id, "demo.eml", old))
            with sqlite3.connect(store.path) as connection:
                before = connection.execute(
                    "SELECT analysis_json FROM case_emails"
                ).fetchone()[0]
            self.assertFalse(store.add_analysis(case_id, "demo.eml", fresh))
            with sqlite3.connect(store.path) as connection:
                after = connection.execute(
                    "SELECT analysis_json FROM case_emails"
                ).fetchone()[0]
        self.assertEqual(before, after)
        self.assertEqual(json.loads(after), old)
        self.assertEqual(fresh["final_assessment"]["fusion_policy_version"],
                         CURRENT_FUSION_POLICY)
        self.assertEqual(fresh["final_assessment"]["risk_score"], 75)

    def test_campaign_correlation_ignores_mixed_fusion_versions(self):
        left = analysis(sender="one@alpha.test", urls=["https://shared.test/x"])
        right = analysis(sender="two@beta.test", urls=["https://shared.test/x"])
        left["final_assessment"]["fusion_policy_version"] = LEGACY_FUSION_V1
        right["final_assessment"]["fusion_policy_version"] = CURRENT_FUSION_POLICY
        records = [record("left", left), record("right", right)]
        before = copy.deepcopy(records)
        result = correlate_emails(records)
        self.assertEqual(len(result["campaigns"]), 1)
        self.assertEqual(records, before)


class FusionUITests(unittest.TestCase):
    def test_current_ui_disclosure_is_concise_and_non_probabilistic(self):
        result = calculate_final_risk(
            {"risk_score": 70}, auth(80), {"hops": []},
            {"phishing_probability": 58.05, **legacy_output_metadata()},
        )
        disclosure = fusion_disclosure(result)
        self.assertEqual(disclosure["policy"], "Validated Evidence v2")
        self.assertIn("AI numeric contribution: 0 points", disclosure["line"])
        self.assertIn("AI signal: Supporting evidence only", disclosure["line"])
        self.assertIn("not a statistically calibrated probability", disclosure["note"])
        self.assertEqual(ai_evidence_label(result), "AI model signal (0 numeric points)")

    def test_historical_ui_disclosure_does_not_change_stored_score(self):
        assessment = {"risk_score": 69}
        before = copy.deepcopy(assessment)
        disclosure = fusion_disclosure(assessment)
        self.assertEqual(disclosure["policy"], "LEGACY SNAPSHOT")
        self.assertIn("may include experimental AI weighting", disclosure["note"])
        self.assertEqual(assessment, before)

    def test_real_numpy_scalar_ai_score_is_visible(self):
        with patch("backend.analyzers.reputation_analyzer.VT_API_KEY", None), \
             patch("urllib.request.urlopen", side_effect=AssertionError("offline")):
            result = analyze_email(ROOT / "data" / "samples" / "test.eml")
        self.assertEqual(score_label(result["ai_analysis"]), "58.05%")

    def test_active_ui_uses_forensic_risk_language(self):
        sources = "\n".join(
            (ROOT / path).read_text(encoding="utf-8")
            for path in ("frontend/app.py", "frontend/ai_ui.py", "frontend/case_ui.py")
        )
        self.assertIn("Forensic Risk Score", sources)
        self.assertNotIn('"Threat Score"', sources)
        self.assertNotIn("scientifically calibrated", sources)
        self.assertIn("not a statistically calibrated probability", sources)


if __name__ == "__main__":
    unittest.main()
