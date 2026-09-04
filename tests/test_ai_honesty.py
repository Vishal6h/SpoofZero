"""Offline regressions for honest AI labels and fail-closed activation eligibility."""
import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from backend.analyzers.email_parser import parse_email
from backend.analyzers.fusion_engine import calculate_final_risk
from backend.fusion_policy import LEGACY_FUSION_V1
from backend.analyzers.nlp_detector import analyze_text
from backend.case_store import CaseStore
from frontend.ai_ui import ai_card_html, score_label
from ml.model_policy import (
    FUSION_NOTE,
    LEGACY_HASHES,
    LEGACY_NOTE,
    LEGACY_VERSION,
    ROLE,
    activation_eligibility,
    describe_ai_output,
    legacy_output_metadata,
    load_legacy_compatibility_model,
    require_activation_eligible,
)
from test_campaign_correlation import analysis


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "frontend" / "app.py"
ADDITIVE_FIELDS = {
    "model_version",
    "model_status",
    "validation_status",
    "evidence_role",
    "validation_note",
}


def passing_bundle():
    return {
        "passed_all": True,
        "failed": [],
        "gates": {
            "representative_holdout": {
                "actual": True,
                "limit": True,
                "operator": "is",
                "passed": True,
            },
            "recall": {
                "actual": 0.94,
                "limit": 0.90,
                "operator": ">=",
                "passed": True,
            },
            "false_positive_rate": {
                "actual": 0.03,
                "limit": 0.05,
                "operator": "<=",
                "passed": True,
            },
        },
    }


def eligible_metadata():
    return {
        "model_version": "reviewed_future_fixture",
        "validation_status": "VALIDATED",
        "validated": True,
        "activation_eligible": True,
        "blockers": [],
        "development_gates": passing_bundle(),
        "final_confirmation_gates": passing_bundle(),
    }


class NLPHonestyTests(unittest.TestCase):
    def test_legacy_output_is_explicitly_experimental_and_unvalidated(self):
        metadata = legacy_output_metadata()
        self.assertEqual(metadata, {
            "model_version": "legacy_demo_16",
            "model_status": "EXPERIMENTAL",
            "validation_status": "NOT VALIDATED",
            "evidence_role": "supporting_evidence_only",
            "validation_note": LEGACY_NOTE,
        })
        self.assertIn("model signal", metadata["validation_note"].lower())
        self.assertNotIn("accurate", metadata["validation_note"].lower())

    def test_original_output_contract_and_demo_result_are_preserved_additively(self):
        result = analyze_text(parse_email(ROOT / "data" / "samples" / "test.eml"))
        self.assertEqual(
            {key: result[key] for key in ("phishing_probability", "verdict")},
            {"phishing_probability": 58.05, "verdict": "SUSPICIOUS"},
        )
        self.assertTrue(ADDITIVE_FIELDS.issubset(result))
        self.assertEqual(result["model_version"], LEGACY_VERSION)
        self.assertEqual(result["model_status"], "EXPERIMENTAL")
        self.assertEqual(result["validation_status"], "NOT VALIDATED")
        self.assertEqual(result["evidence_role"], ROLE)

    def test_probability_remains_bounded_and_inference_deterministic(self):
        values = [
            {},
            {"subject": "", "body": ""},
            {"subject": "会議", "body": "予定を確認してください"},
            {"body": object()},
        ]
        for value in values:
            with self.subTest(value=value):
                first = analyze_text(value)
                second = analyze_text(value)
                self.assertEqual(first, second)
                self.assertGreaterEqual(first["phishing_probability"], 0)
                self.assertLessEqual(first["phishing_probability"], 100)

    def test_active_legacy_artifacts_match_protected_byte_pins(self):
        for name, expected in LEGACY_HASHES.items():
            actual = sha256((ROOT / "ml" / name).read_bytes()).hexdigest()
            self.assertEqual(actual, expected)

    def test_modified_legacy_artifact_is_rejected_before_deserialization(self):
        with TemporaryDirectory() as directory:
            shadow = Path(directory)
            for name in LEGACY_HASHES:
                (shadow / name).write_bytes((ROOT / "ml" / name).read_bytes())
            (shadow / "phishing_model.joblib").write_bytes(b"changed")
            with patch("ml.model_policy.MODEL_ROOT", shadow), \
                 patch("ml.model_policy.joblib.load") as unsafe_load:
                with self.assertRaisesRegex(ValueError, "Protected legacy artifact changed"):
                    load_legacy_compatibility_model()
                unsafe_load.assert_not_called()


class ActivationPolicyTests(unittest.TestCase):
    def test_validated_metadata_can_be_eligible_but_never_activates_automatically(self):
        result = activation_eligibility(eligible_metadata())
        self.assertTrue(result["eligible"])
        self.assertFalse(result["automatic_activation"])
        self.assertEqual(result["reasons"], [])
        self.assertEqual(require_activation_eligible(eligible_metadata()), result)

    def test_unvalidated_states_and_truthy_flags_fail_closed(self):
        for change in (
            {"validation_status": "UNVALIDATED"},
            {"validation_status": "RESEARCH"},
            {"validation_status": "EXPERIMENTAL"},
            {"validation_status": "validated"},
            {"validated": "true"},
            {"validated": 1},
            {"activation_eligible": "true"},
            {"blockers": ["unresolved"]},
        ):
            with self.subTest(change=change):
                metadata = eligible_metadata()
                metadata.update(change)
                self.assertFalse(activation_eligibility(metadata)["eligible"])
                with self.assertRaises(ValueError):
                    require_activation_eligible(metadata)

    def test_legacy_model_cannot_be_promoted_by_claimed_validated_flags(self):
        metadata = eligible_metadata()
        metadata["model_version"] = LEGACY_VERSION
        metadata["model_status"] = "VALIDATED"
        self.assertFalse(activation_eligibility(metadata)["eligible"])

    def test_missing_partial_or_conflicting_gate_schemas_fail_closed(self):
        variants = []
        no_gates = eligible_metadata()
        no_gates.pop("development_gates")
        no_gates.pop("final_confirmation_gates")
        variants.append(no_gates)
        partial = eligible_metadata()
        partial.pop("final_confirmation_gates")
        variants.append(partial)
        conflicting = eligible_metadata()
        conflicting["inherited_gates"] = passing_bundle()
        conflicting["additional_gates"] = passing_bundle()
        conflicting["additional_gates"]["passed_all"] = False
        variants.append(conflicting)
        for metadata in variants:
            with self.subTest(keys=sorted(metadata)):
                self.assertFalse(activation_eligibility(metadata)["eligible"])

    def test_reported_gate_pass_must_match_typed_evidence(self):
        for index, (actual, limit, operator) in enumerate((
            (0.80, 0.90, ">="),
            (0.20, 0.05, "<="),
            ("0.95", 0.90, ">="),
            (True, 1, ">="),
            (float("nan"), 0.90, ">="),
            (10 ** 10000, 1, ">="),
            (True, "true", "is"),
            (True, True, "=="),
        )):
            with self.subTest(case=index, operator=operator):
                metadata = eligible_metadata()
                metadata["development_gates"]["gates"]["recall"] = {
                    "actual": actual,
                    "limit": limit,
                    "operator": operator,
                    "passed": True,
                }
                self.assertFalse(activation_eligibility(metadata)["eligible"])

    def test_every_checked_in_research_candidate_remains_ineligible(self):
        candidates = []
        for path in (ROOT / "ml" / "models").rglob("metadata.json"):
            metadata = json.loads(path.read_text(encoding="utf-8"))
            if metadata.get("model_version") != LEGACY_VERSION:
                candidates.append(path)
                self.assertFalse(
                    activation_eligibility(metadata)["eligible"],
                    f"{path} unexpectedly became activation eligible",
                )
        self.assertGreaterEqual(len(candidates), 9)

    def test_v1_loader_rejects_forged_truthy_validation_before_loading_pickle(self):
        source = json.loads(
            (ROOT / "ml" / "models" / "candidate_v1" / "metadata.json").read_text()
        )
        source["validated"] = "yes"
        with TemporaryDirectory() as directory:
            folder = Path(directory) / "candidate_v1"
            folder.mkdir()
            (folder / "metadata.json").write_text(json.dumps(source), encoding="utf-8")
            with patch("ml.inference.MODEL_ROOT", Path(directory)), \
                 patch("ml.inference.joblib.load") as unsafe_load:
                from ml.inference import load_candidate
                with self.assertRaisesRegex(ValueError, "not eligible"):
                    load_candidate()
                unsafe_load.assert_not_called()


class UIHonestyTests(unittest.TestCase):
    def test_current_card_uses_controlled_nonmisleading_labels(self):
        output = analyze_text({"subject": "hello", "body": "meeting agenda"})
        rendered = ai_card_html(output)
        self.assertIn("AI phishing score", rendered)
        self.assertIn(score_label(output), rendered)
        self.assertNotEqual(score_label(output), "Unavailable")
        self.assertIn(f"Signal band: {output['verdict']}", rendered)
        self.assertIn("Model status: EXPERIMENTAL", rendered)
        self.assertIn("Validation: NOT VALIDATED", rendered)
        self.assertIn("Role: Supporting evidence only", rendered)
        self.assertNotIn("AI Probability", rendered)
        self.assertNotIn("AI confirmed phishing", rendered)

    def test_old_output_uses_unknown_legacy_snapshot_defaults(self):
        old = {"phishing_probability": 58.05, "verdict": "SUSPICIOUS"}
        labels = describe_ai_output(old)
        self.assertEqual(labels["model_status"], "UNKNOWN")
        self.assertEqual(labels["validation_status"], "UNKNOWN / LEGACY SNAPSHOT")
        self.assertEqual(labels["evidence_role"], ROLE)
        self.assertIn("not recorded", labels["validation_note"])
        self.assertIn("UNKNOWN / LEGACY SNAPSHOT", ai_card_html(old))

    def test_malformed_score_is_not_presented_as_zero_or_a_probability(self):
        for value in (None, {}, [], {"phishing_probability": float("nan")},
                      {"phishing_probability": 101}, {"phishing_probability": "98"},
                      {"phishing_probability": 10 ** 10000}):
            with self.subTest(value_type=type(value).__name__):
                self.assertEqual(score_label(value), "Unavailable")

    def test_snapshot_cannot_inject_html_or_claim_legacy_validation(self):
        malicious = {
            "phishing_probability": 12,
            "verdict": "<script>alert(1)</script>",
            "model_version": LEGACY_VERSION,
            "model_status": "<b>VALIDATED</b>",
            "validation_status": "VALIDATED",
            "evidence_role": "<img src=x>",
            "validation_note": "<script>unsafe()</script>",
        }
        rendered = ai_card_html(malicious)
        self.assertIn("Model status: EXPERIMENTAL", rendered)
        self.assertIn("Validation: NOT VALIDATED", rendered)
        for untrusted in ("script", "img src", "<b>VALIDATED"):
            self.assertNotIn(untrusted, rendered)

    def test_frontend_source_avoids_prohibited_claims(self):
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "frontend").rglob("*.py")
        ).lower()
        for phrase in (
            "ai probability",
            "ai confirmed phishing",
            "chance this email is phishing",
            "99% accurate",
        ):
            self.assertNotIn(phrase, source)

    def test_old_saved_case_opens_without_rewrite_and_shows_safe_defaults(self):
        with TemporaryDirectory() as directory, patch.dict(
            os.environ, {"SPOOFZERO_CASE_DB": str(Path(directory) / "cases.sqlite3")}
        ):
            store = CaseStore()
            case_id = store.create_case("Legacy snapshot")
            old = analysis()
            old["ai_analysis"] = {
                "phishing_probability": 58.05,
                "verdict": "SUSPICIOUS",
            }
            self.assertTrue(store.add_analysis(case_id, "old.eml", old))
            with sqlite3.connect(store.path) as connection:
                before = connection.execute(
                    "SELECT analysis_json FROM case_emails WHERE case_id = ?", (case_id,)
                ).fetchone()[0]

            app = AppTest.from_file(str(APP)).run()
            app.button(key="sz_open_email").click().run()
            self.assertEqual(
                len(app.exception), 0, [item.message for item in app.exception]
            )
            self.assertEqual(app.session_state["spoofzero_result"], old)
            visible = "\n".join(
                item.value for item in list(app.markdown) + list(app.caption)
            )
            self.assertIn("UNKNOWN / LEGACY SNAPSHOT", visible)
            self.assertIn("stored score has not been recalculated", visible)

            with sqlite3.connect(store.path) as connection:
                after = connection.execute(
                    "SELECT analysis_json FROM case_emails WHERE case_id = ?", (case_id,)
                ).fetchone()[0]
            self.assertEqual(after, before)
            self.assertEqual(json.loads(after), old)


class FusionTransparencyTests(unittest.TestCase):
    def test_fusion_numbers_and_weights_remain_legacy_compatible(self):
        bare_ai = {"phishing_probability": 58.05, "verdict": "SUSPICIOUS"}
        labeled_ai = dict(bare_ai, **legacy_output_metadata())
        inputs = {
            "sender_identity": {"risk_score": 70},
            "authentication": {
                "risk_score": 40,
                "evidence_state": "conclusive",
                "evidence_confidence": {},
                "findings": [],
            },
            "relay_trace": {"hops": []},
        }
        bare = calculate_final_risk(
            ai_analysis=bare_ai, policy_version=LEGACY_FUSION_V1, **inputs
        )
        labeled = calculate_final_risk(
            ai_analysis=labeled_ai, policy_version=LEGACY_FUSION_V1, **inputs
        )
        for key in (
            "risk_score",
            "verdict",
            "evidence_scores",
            "reputation_bonus",
            "attachment_bonus",
            "relay_bonus",
            "authentication_context",
        ):
            self.assertEqual(bare[key], labeled[key])
        self.assertEqual(labeled["risk_score"], 55)
        self.assertEqual(labeled["verdict"], "SUSPICIOUS")
        self.assertEqual(labeled["ai_context"]["base_weight"], 0.35)
        self.assertAlmostEqual(
            labeled["ai_context"]["weighted_points_before_rounding"], 20.3175
        )
        self.assertEqual(labeled["ai_context"]["validation_status"], "NOT VALIDATED")
        self.assertEqual(labeled["ai_context"]["limitation"], FUSION_NOTE)

    def test_ai_signal_alone_still_has_original_maximum_contribution(self):
        assessment = calculate_final_risk(
            {"risk_score": 0},
            {"risk_score": 0, "findings": []},
            {"hops": []},
            {"phishing_probability": 100, **legacy_output_metadata()},
            policy_version=LEGACY_FUSION_V1,
        )
        self.assertEqual(assessment["risk_score"], 35)
        self.assertEqual(assessment["verdict"], "LOW RISK")
        self.assertEqual(assessment["ai_context"]["maximum_base_points"], 35)
        self.assertIn("model signal", assessment["reasons"][0].lower())


if __name__ == "__main__":
    unittest.main()
