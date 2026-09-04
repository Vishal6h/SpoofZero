"""Offline synthetic regressions: no public corpora or network required."""
from collections import Counter
from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile

import joblib
import numpy as np
import sklearn

from backend.analyzers.nlp_detector import analyze_text
from ml.data_pipeline import ROOT, digest, write_json
from ml.experiment import CANDIDATES, model_factory
from ml.generalization import data, evaluate, fetch, inference
from ml.generalization.text import feature_text, VERSION

PROJECT = ROOT.parent


def word(index):
    return "item" + chr(97 + index // 26 % 26) + chr(97 + index % 26)


def row(index, label=0, source="source_a", **extra):
    text = "team meeting schedule report colleague" if not label else "urgent password account verify suspended"
    return data.normalize_example(dict(subject=word(index), body=text + " " + word(index),
        label=label, source=source, source_id=str(index), **extra))


def rows(count=80, source="source_a", offset=0):
    return [row(i + offset, i % 2, source) for i in range(count)]


def dedup_fixture():
    records = rows(60) + rows(60, "source_b", 100) + rows(60, "source_c", 200)
    return data.deduplicate(records)[0]


def perfect_bundle():
    records = rows(200)
    probabilities = [.01 if r["label"] == 0 else .99 for r in records]
    evaluation = evaluate.evaluate_records(records, probabilities, .5)
    source_tests = {"summary": evaluation["source_summary"], "all_folds_evaluated": True,
        "paired_source_transfer": [{"status": "EVALUATED", "evaluation": evaluation}]}
    thresholds = {"suspicious": .5, "high": .7, "review_target_met": True, "high_target_met": True}
    evidence = {"independent_real_both_class_sources": 2, "representative_external_holdout": True}
    return evaluation, source_tests, thresholds, 1., evidence


class SourceTextTests(unittest.TestCase):
    def test_metadata_fields_never_change_features(self):
        plain = {"subject": "Review", "body": "Please check the report"}
        self.assertEqual(feature_text(plain), feature_text(dict(plain, source="evil", source_id="p",
            filename="ham.csv", label=1, phishing_type="credential_harvesting", confidence=.999, severity="high")))

    def test_embedded_metadata_lines_removed(self):
        text = feature_text({"body": "Dataset: collection\nsource_id: 400\nLabel=1\n"
            "phishing_type: scam\nCreated by: LLM\nseverity: high\nconfidence: 1\nPlease review report"})
        self.assertEqual(text, "please review report")

    def test_filenames_and_collection_markers_removed(self):
        self.assertEqual(feature_text({"body": "TREC-06.csv /folder/messages.eml synthetic_emails "
                                              "kuladeep19 yoadjei Please review"}), "please review")

    def test_html_unicode_and_malformed_input_are_safe(self):
        self.assertEqual(feature_text({"body": "<p>Ｃafé report</p><script>bad()</script>"}), "café report")
        for value in (None, [], {}, {"body": []}, {"subject": None}):
            self.assertEqual(feature_text(value), "")

    def test_train_only_boilerplate_audit_is_hashed(self):
        records = [row(i) for i in range(25)]
        for r in records:
            r["body"] = "This repeated notice belongs to our demonstration mailing list"
        result = data.artifact_audit(records)
        self.assertEqual(result["partition"], "train_only")
        self.assertEqual(result["repeated_line_groups"], 1)
        self.assertNotIn("demonstration mailing", json.dumps(result))


class GeneralizationDataTests(unittest.TestCase):
    def test_exact_duplicate_across_sources_retains_provenance(self):
        a = row(0)
        b = data.normalize_example(dict(a, source="other", source_id="new"))
        kept, stats, _ = data.deduplicate([a, b])
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["sources"], ["other", "source_a"])
        self.assertEqual(stats["duplicates_removed"], 1)

    def test_body_template_duplicate_with_different_subjects(self):
        body = "please review this invoice and confirm the banking details before the next meeting"
        a = data.normalize_example({"body": body, "subject": "First", "source": "a", "label": 1})
        b = data.normalize_example({"body": body, "subject": "Second", "source": "b", "label": 1})
        self.assertEqual(len(data.deduplicate([a, b])[0]), 1)

    def test_conflict_quarantine_never_guesses(self):
        a, b = row(0), row(0, source="other")
        b["label"] = 1
        kept, stats, quarantine = data.deduplicate([a, b])
        self.assertEqual(kept, [])
        self.assertEqual(stats["conflicting_rows_quarantined"], 2)
        self.assertEqual(quarantine[0]["reason"], "conflicting_labels")

    def test_conflicting_component_cannot_resurrect_through_near_variant(self):
        body = " ".join(word(i) for i in range(100))
        a = data.normalize_example({"source": "a", "label": 0, "body": body})
        b = data.normalize_example({"source": "b", "label": 1, "body": body})
        c = data.normalize_example({"source": "c", "label": 1, "body": body.replace(word(50), "changedword")})
        kept, stats, _ = data.deduplicate([a, b, c])
        self.assertEqual(kept, [])
        self.assertEqual(stats["conflicting_rows_quarantined"], 3)

    def test_v1_protected_family_excluded_across_sources(self):
        a = row(0, source="ling", protected=True)
        b = data.normalize_example(dict(a, source="new_source", source_id="b", protected=False))
        kept, stats, _ = data.deduplicate([a, b])
        self.assertEqual(kept, [])
        self.assertEqual(stats["exposed_v1_rows_quarantined"], 2)

    def test_old_source_duplicate_remains_development_only(self):
        a = row(0, source="ling")
        b = data.normalize_example(dict(a, source="new_source", source_id="b"))
        record = data.deduplicate([a, b])[0][0]
        self.assertTrue(record["previously_seen"])

    def test_source_split_reproducible_under_reordering(self):
        records = dedup_fixture()
        first, _ = data.split_records(records)
        self.assertEqual(first, data.split_records(list(reversed(records)))[0])
        self.assertNotEqual(first, data.split_records(records, seed=12)[0])

    def test_source_and_class_strata_preserved(self):
        splits, _ = data.split_records(dedup_fixture())
        for split in splits.values():
            for source in {"source_a", "source_b", "source_c"}:
                self.assertEqual({r["label"] for r in split if r["source"] == source}, {0, 1})

    def test_old_sources_never_enter_fresh_test(self):
        records = data.deduplicate(rows(80, "ling") + rows(80, "fresh", 100))[0]
        splits, _ = data.split_records(records)
        self.assertTrue(splits["test"])
        self.assertEqual({r["source"] for r in splits["test"]}, {"fresh"})

    def test_tiny_source_training_only_and_reported(self):
        splits, small = data.split_records(data.deduplicate(rows(4))[0])
        self.assertEqual(len(splits["train"]), 4)
        self.assertFalse(splits["validation"] or splits["test"])
        self.assertEqual(sum(s["count"] for s in small), 4)

    def test_no_duplicate_leakage_across_partitions(self):
        splits, _ = data.split_records(dedup_fixture())
        data.assert_disjoint(splits)
        splits["test"].append(splits["train"][0])
        with self.assertRaises(ValueError):
            data.assert_disjoint(splits)

    def test_source_cap_reproducible_and_training_only(self):
        records = dedup_fixture()
        chosen = data.balance_training(records, cap=5)
        self.assertEqual(chosen, data.balance_training(list(reversed(records)), cap=5))
        self.assertEqual(len(chosen), 30)
        self.assertTrue(all(v == 5 for v in Counter((r["source"], r["label"]) for r in chosen).values()))
        with self.assertRaises(ValueError):
            data.balance_training(records, cap=0)

    def test_csv_adapters_strict_labels_and_metadata_projection(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.csv"
            path.write_text("text,label,severity\nhello review,0,high\nurgent verify,1,low\nbad,,high\n", encoding="utf-8")
            source = {"name": "fixture", "file": path.name, "sha256": digest(path.read_bytes()),
                      "label_map": {"0": 0, "1": 1}, "subject_field": None, "body_field": "text"}
            records, summary = data.read_source(source, directory, set())
            self.assertEqual(len(records), 2)
            self.assertEqual(summary["counts"]["invalid_label_excluded"], 1)
            self.assertNotIn("high", records[0]["text"])
            path.write_text("tampered", encoding="utf-8")
            with self.assertRaises(ValueError):
                data.read_source(source, directory, set())

    def test_source_partition_purges_mixed_provenance(self):
        records = dedup_fixture()
        mixed = copy.deepcopy(records[0])
        mixed["sources"] = ["source_a", "source_b"]
        others = [r for r in records if r["id"] != mixed["id"]] + [mixed]
        fit, check, purged = evaluate.source_partition(others, {"source_b"})
        self.assertEqual(purged, 1)
        self.assertTrue(all("source_b" not in r["sources"] for r in fit))
        self.assertTrue(all(set(r["sources"]) <= {"source_b"} for r in check))


class SourceMetricTests(unittest.TestCase):
    def test_per_source_false_positive_negative_and_calibration(self):
        records = [row(0, 0, "a"), row(1, 1, "a"), row(2, 0, "b"), row(3, 1, "b")]
        result = evaluate.evaluate_records(records, [.9, .8, .1, .2], .5)
        self.assertEqual(result["pooled"]["confusion_matrix"], [[1, 1], [1, 1]])
        self.assertEqual(result["per_source"]["a"]["false_positive_rate"], 1)
        self.assertEqual(result["per_source"]["b"]["false_negative_rate"], 1)
        self.assertIn("calibration_bins", result["per_source"]["a"])

    def test_unsupported_single_class_rates_are_null(self):
        ham = evaluate.metric_set([0, 0], [.1, .8])
        phish = evaluate.metric_set([1, 1], [.1, .8])
        self.assertIsNone(ham["recall"])
        self.assertIsNone(ham["precision"])
        self.assertIsNone(ham["f1"])
        self.assertIsNone(phish["false_positive_rate"])
        self.assertEqual(phish["false_negative_rate"], .5)
        self.assertIsNone(ham["roc_auc"])

    def test_macro_gives_small_source_equal_weight(self):
        records = [row(i, 0, "large") for i in range(100)] + [row(200, 0, "small")]
        result = evaluate.evaluate_records(records, [.1] * 100 + [.9], .5)
        self.assertAlmostEqual(result["source_summary"]["macro"]["false_positive_rate"]["value"], .5)
        self.assertAlmostEqual(result["pooled"]["false_positive_rate"], 1 / 101)
        self.assertEqual(result["source_summary"]["worst_source_error"], 1)

    def test_invalid_labels_thresholds_probabilities_rejected(self):
        for y, p, t in (([0, 2], [.1, .9], .5), ([0, 1], [.1, float("nan")], .5),
                        ([0, 1], [.1, .9], 2)):
            with self.assertRaises(ValueError):
                evaluate.metric_set(y, p, t)

    def test_loso_model_and_threshold_exclude_held_out_source(self):
        records = dedup_fixture()
        eligible, _, _ = evaluate.source_partition(records, {"source_b"})
        _, expected_val = evaluate.internal_validation(eligible)
        from ml.experiment import select_thresholds
        with patch("ml.generalization.evaluate.select_thresholds", wraps=select_thresholds) as choose:
            fold = evaluate.source_fold("logistic", records, {"source_b"})
        self.assertEqual(fold["status"], "EVALUATED")
        self.assertEqual(choose.call_args.args[0], [r["label"] for r in expected_val])
        self.assertNotIn("source_b", fold["fitting"]["source_counts"])
        self.assertNotIn("source_b", fold["internal_validation"]["source_counts"])
        self.assertEqual(set(fold["evaluation"]["per_source"]), {"source_b"})

    def test_all_loso_sources_covered_and_transfer_recorded(self):
        with redirect_stdout(io.StringIO()):
            result = evaluate.source_evaluation("logistic", dedup_fixture(), [["source_b", "source_c"]])
        self.assertEqual(len(result["leave_one_source_out"]), 3)
        self.assertEqual(len(result["paired_source_transfer"]), 1)
        self.assertTrue(result["all_folds_evaluated"])

    def test_insufficient_source_fold_is_explicit(self):
        records = data.deduplicate(rows(20))[0]
        fold = evaluate.source_fold("logistic", records, {"source_a"})
        self.assertEqual(fold["status"], "INSUFFICIENT_SUPPORT")


class DeploymentGateTests(unittest.TestCase):
    def test_all_valid_evidence_passes(self):
        self.assertTrue(evaluate.gate_results(*perfect_bundle())["passed_all"])

    def test_each_numeric_gate_fails_when_required_evidence_is_missing(self):
        for position in (0, 1, 3, 4):
            values = list(copy.deepcopy(perfect_bundle()))
            if position == 0:
                values[0]["pooled"]["recall"] = None
            elif position == 1:
                values[1]["summary"]["worst_source_error"] = None
            elif position == 3:
                values[3] = float("nan")
            else:
                values[4]["independent_real_both_class_sources"] = 0
            with self.subTest(position=position):
                self.assertFalse(evaluate.gate_results(*values)["passed_all"])

    def test_mixed_accuracy_cannot_override_bad_source(self):
        values = list(copy.deepcopy(perfect_bundle()))
        values[1]["summary"]["worst_source_error"] = .4
        result = evaluate.gate_results(*values)
        self.assertIn("loso_worst_source_error", result["failed"])

    def test_bad_transfer_fpr_blocks_deployment(self):
        values = list(copy.deepcopy(perfect_bundle()))
        values[1]["paired_source_transfer"][0]["evaluation"]["pooled"]["false_positive_rate"] = .2
        self.assertIn("transfer_max_fpr", evaluate.gate_results(*values)["failed"])

    def test_synthetic_evidence_cannot_satisfy_real_source_requirement(self):
        values = list(copy.deepcopy(perfect_bundle()))
        values[4] = {"independent_real_both_class_sources": 0, "representative_external_holdout": False}
        failed = evaluate.gate_results(*values)["failed"]
        self.assertIn("representative_external_holdout", failed)
        self.assertIn("independent_real_both_class_sources", failed)

    def test_infeasible_bands_block_deployment(self):
        values = list(copy.deepcopy(perfect_bundle()))
        values[2]["high_target_met"] = False
        self.assertIn("validation_band_targets", evaluate.gate_results(*values)["failed"])

    def test_missing_or_small_source_blocks_deployment(self):
        values = list(copy.deepcopy(perfect_bundle()))
        values[1]["summary"]["minimum_support"] = 20
        values[1]["all_folds_evaluated"] = False
        failed = evaluate.gate_results(*values)["failed"]
        self.assertIn("source_sample_support", failed)
        self.assertIn("all_source_folds_evaluated", failed)

    def test_conservative_gate_boundaries_are_inclusive(self):
        values = list(copy.deepcopy(perfect_bundle()))
        values[0]["pooled"]["recall"] = .95
        values[0]["pooled"]["false_positive_rate"] = .05
        values[1]["summary"]["worst_source_error"] = .10
        values[3] = 25
        self.assertTrue(evaluate.gate_results(*values)["passed_all"])


class V2ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(redirect_stdout(io.StringIO()))

    def prepared(self, directory, broken_test=False):
        dataset = Path(directory) / "data"
        dataset.mkdir()
        splits, _ = data.split_records(data.deduplicate(rows(300) + rows(300, "source_b", 400))[0])
        manifest = {"dataset_id": "offline_fixture", "splits": {},
                    "training_after_cap": data.summaries(splits["train"]),
                    "recipe": {"transfer_pairs": [["source_a"]],
                               "evidence": {"independent_real_both_class_sources": 0, "representative_external_holdout": False}}}
        for name, records in splits.items():
            path = dataset / (name + ".jsonl")
            path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
            if broken_test and name == "test":
                path.write_text("DO NOT OPEN DURING SELECTION")
            manifest["splits"][name] = {"count": len(records), "sha256": digest(path.read_bytes())}
        write_json(dataset / "manifest.json", manifest)
        return dataset, Path(directory) / "run", Path(directory) / "lock.json"

    def select(self, args):
        source_tests = perfect_bundle()[1]
        with patch("ml.generalization.evaluate.source_evaluation", return_value=source_tests):
            return evaluate.select(*args)

    def test_selection_never_reads_final_test(self):
        with TemporaryDirectory() as d:
            args = self.prepared(d, True)
            result = self.select(args)
            self.assertFalse(result["test_opened"])
            self.assertEqual(result["active_model"], "legacy_demo_16")
            self.assertEqual(set(result["candidates"]), set(CANDIDATES))
            for c in result["candidates"].values():
                self.assertIn("validation_tradeoff_grid", c["thresholds"])
            with self.assertRaises(FileExistsError):
                self.select(args)

    def test_finalization_preserves_choice_bands_and_all_failed_inactive(self):
        with TemporaryDirectory() as d:
            args = self.prepared(d)
            lock = self.select(args)
            out, report = Path(d) / "models", Path(d) / "final.json"
            result = evaluate.finalize(*args, out, report)
            self.assertEqual(result["selected_model"], lock["selected_model"])
            self.assertFalse(result["any_candidate_eligible"])
            self.assertFalse(result["activated"])
            for name in CANDIDATES:
                meta = json.loads((out / name / "metadata.json").read_text())
                self.assertEqual(meta["validation_status"], "UNVALIDATED")
                self.assertFalse(meta["validated"])
                self.assertFalse(meta["active"])
                self.assertEqual(meta["thresholds"]["suspicious"], lock["candidates"][name]["thresholds"]["suspicious"])
            with self.assertRaises(FileExistsError):
                evaluate.finalize(*args, Path(d) / "other", Path(d) / "other.json")

    def test_lock_tampering_rejected_before_test_open(self):
        with TemporaryDirectory() as d:
            args = self.prepared(d)
            self.select(args)
            args[2].write_text(args[2].read_text() + "\n")
            with self.assertRaises(ValueError):
                evaluate.finalize(*args, Path(d) / "models", Path(d) / "report.json")
            self.assertFalse(Path(str(args[2]) + ".test-opened").exists())

    def test_model_tampering_rejected_before_test_open(self):
        with TemporaryDirectory() as d:
            args = self.prepared(d)
            self.select(args)
            (args[1] / "logistic.joblib").write_bytes(b"bad")
            with self.assertRaises(ValueError):
                evaluate.finalize(*args, Path(d) / "models", Path(d) / "report.json")
            self.assertFalse(Path(str(args[2]) + ".test-opened").exists())


class V2InferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = model_factory("logistic")
        records = rows(80)
        cls.model.fit([r["text"] for r in records], [r["label"] for r in records])

    def metadata(self, artifact):
        return {"model_version": "candidate_v2/logistic", "validation_status": "UNVALIDATED",
                "validated": False, "activation_eligible": False, "normalization_version": VERSION,
                "versions": {"scikit_learn": sklearn.__version__}, "code_sha256": evaluate.code_hashes(),
                "artifact_sha256": digest(artifact.read_bytes()), "thresholds": {"suspicious": .5, "high": .7}}

    def test_loading_requires_explicit_research_and_checks_bytes(self):
        with TemporaryDirectory() as d:
            directory = Path(d) / "logistic"
            directory.mkdir()
            artifact = directory / "model.joblib"
            joblib.dump(self.model, artifact)
            write_json(directory / "metadata.json", self.metadata(artifact))
            with patch.object(inference, "MODEL_ROOT", Path(d)):
                with self.assertRaises(ValueError):
                    inference.load_candidate("logistic")
                loaded, _ = inference.load_candidate("logistic", research=True)
                self.assertEqual(loaded.predict_proba(["hi"]).tolist(), self.model.predict_proba(["hi"]).tolist())
                artifact.write_bytes(b"tampered")
                with patch.object(inference.joblib, "load") as load:
                    with self.assertRaises(ValueError):
                        inference.load_candidate("logistic", research=True)
                    load.assert_not_called()

    def test_claimed_validated_flag_cannot_override_missing_gates(self):
        with TemporaryDirectory() as d:
            directory = Path(d) / "logistic"
            directory.mkdir()
            artifact = directory / "model.joblib"
            joblib.dump(self.model, artifact)
            metadata = dict(self.metadata(artifact), validation_status="VALIDATED", validated=True, activation_eligible=True)
            write_json(directory / "metadata.json", metadata)
            with patch.object(inference, "MODEL_ROOT", Path(d)), self.assertRaises(ValueError):
                inference.load_candidate("logistic")

    def test_output_compatibility_boundaries_and_determinism(self):
        metadata = {"model_version": "fixture", "validation_status": "RESEARCH",
                    "thresholds": {"suspicious": .5, "high": .7}}
        for value in (None, {}, {"body": "Hi"}, {"body": "你好 café"}, {"body": "<p>Review report</p>"}, {"body": []}):
            result = inference.analyze_candidate(value, self.model, metadata)
            self.assertEqual(result, inference.analyze_candidate(value, self.model, metadata))
            self.assertTrue(0 <= result["phishing_probability"] <= 100)
            self.assertIsInstance(result["verdict"], str)
        with patch.object(self.model, "predict_proba", return_value=np.array([[.3, .7]])):
            self.assertEqual(inference.analyze_candidate({}, self.model, metadata)["confidence_band"], "high")

    def test_loading_from_different_working_directory(self):
        with TemporaryDirectory() as d, TemporaryDirectory() as unrelated:
            directory = Path(d) / "logistic"
            directory.mkdir()
            artifact = directory / "model.joblib"
            joblib.dump(self.model, artifact)
            write_json(directory / "metadata.json", self.metadata(artifact))
            code = "import sys; from pathlib import Path; from ml.generalization import inference as i; i.MODEL_ROOT=Path(sys.argv[1]); m,d=i.load_candidate('logistic',research=True); assert 0<=i.analyze_candidate({'body':'hello'},m,d)['phishing_probability']<=100"
            result = subprocess.run([sys.executable, "-c", code, d], cwd=unrelated,
                env=dict(os.environ, PYTHONPATH=str(PROJECT)), capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_legacy_bytes_and_active_paths_preserved(self):
        metadata = json.loads((ROOT / "models/legacy_demo/metadata.json").read_text())
        for name, sha in metadata["artifacts"].items():
            self.assertEqual(digest((PROJECT / name).read_bytes()), sha)
        import backend.analyzers.nlp_detector as active
        self.assertEqual(active.MODEL_PATH, ROOT / "phishing_model.joblib")
        self.assertEqual(active.VECTOR_PATH, ROOT / "vectorizer.joblib")
        output = analyze_text({"body": "hello"})
        self.assertTrue({"phishing_probability", "verdict"}.issubset(output))
        self.assertEqual(output["model_version"], "legacy_demo_16")

    def test_v1_remains_unvalidated(self):
        self.assertFalse(json.loads((ROOT / "models/candidate_v1/metadata.json").read_text())["validated"])


class V2DownloadTests(unittest.TestCase):
    def test_unreviewed_asset_url_license_checksum_rejected(self):
        with TemporaryDirectory() as d, patch("urllib.request.urlopen") as urlopen:
            for source in ({"file": "../bad.csv"}, {"file": "evil.py"},
                           {"file": "TREC-06.csv", "url": "https://evil.test", "license": "CC-BY-4.0", "sha256": "bad"}):
                with self.assertRaises(ValueError):
                    fetch.fetch_source(source, d)
            urlopen.assert_not_called()

    def test_single_csv_archive_only_and_size_bound(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as z:
            z.writestr("safe.csv", "body,label\nhello,0\n")
        self.assertEqual(fetch.csv_bytes(buffer.getvalue(), "safe.csv", 1000), b"body,label\nhello,0\n")
        with self.assertRaises(ValueError):
            fetch.csv_bytes(buffer.getvalue(), "different.csv", 1000)
        with self.assertRaises(ValueError):
            fetch.csv_bytes(b"too large", "safe.csv", 2)

    def test_archive_with_script_and_binary_csv_rejected(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as z:
            z.writestr("safe.csv", "body,label")
            z.writestr("run.py", "print('do not run')")
        with self.assertRaises(ValueError):
            fetch.csv_bytes(buffer.getvalue(), "safe.csv", 1000)
        with self.assertRaises(ValueError):
            fetch.csv_bytes(b"\0binary", "safe.csv", 1000)


if __name__ == "__main__":
    unittest.main()
