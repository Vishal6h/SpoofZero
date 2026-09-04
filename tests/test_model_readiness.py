from collections import Counter
from contextlib import redirect_stdout
import io
import copy
import csv
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import joblib
import numpy as np
import sklearn

from backend.analyzers.email_parser import parse_email
from backend.analyzers.nlp_detector import analyze_text
from ml.data_pipeline import (deduplicate, digest, load_sources, near_pairs,
    normalize_example, read_rows, split_records, write_json)
from ml.experiment import (CANDIDATES, FEATURES, calibration_bins, checked_rows,
    finalize, metrics, model_factory, select, select_thresholds)
from ml.inference import analyze_candidate, load_candidate
from ml.fetch_data import fetch_source
from ml.text import VERSION, feature_text, message_parts, verdict_for_probability

ROOT = Path(__file__).resolve().parents[1]


def marker(index):
    return "word" + chr(97 + index // 26 % 26) + chr(97 + index % 26)


def example(index, label=0, source="synthetic"):
    text = ("team meeting project schedule report colleague" if label == 0 else
            "urgent password verify account click suspended")
    return normalize_example({"subject": marker(index), "body": text,
        "label": label, "source": source, "source_id": str(index)})


def toy_records(count=40):
    return [example(i, i % 2) for i in range(count)]


class TextReadinessTests(unittest.TestCase):
    def test_subject_and_body_are_used(self):
        text = feature_text({"subject": "Account Review", "body": "Please confirm"})
        self.assertEqual(text, "account review please confirm")

    def test_html_produces_readable_text_without_network(self):
        with patch("urllib.request.urlopen", side_effect=AssertionError("Offline")):
            text = feature_text({"body": "<p>Please <b>review</b> the report.</p><script>evil()</script>"})
        self.assertEqual(text, "please review the report")

    def test_parser_derived_html_matches_plain_candidate_input(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.eml"
            path.write_bytes(b"Subject: Notice\nContent-Type: text/html\n\n<p>Please review the report.</p>")
            parsed = parse_email(path)
        self.assertEqual(feature_text(parsed), feature_text({"subject": "Notice", "body": "Please review the report."}))

    def test_missing_and_malformed_fields_are_safe(self):
        for value in (None, [], "bad", 5, {}, {"subject": None, "body": []}, {"body": {"secret": "not text"}}):
            with self.subTest(value=value):
                self.assertEqual(feature_text(value), "")

    def test_unicode_normalization_and_invisible_characters(self):
        self.assertEqual(feature_text({"body": "Ｃafé\u200b BÜCHER"}), "café bücher")

    def test_bytes_decode_without_crashing(self):
        self.assertIn("hello", feature_text({"body": b"Hello \xff"}))

    def test_metadata_and_filter_artifacts_are_not_features(self):
        text = feature_text({"subject": "[SPAM] Subject: notice", "body": "X-Spam-Status: Yes\nReceived: collector\nFrom: sender@example.com\nNormal readable content\n> quoted text"})
        self.assertEqual(text, "notice normal readable content")

    def test_source_ids_urls_addresses_and_numbers_are_masked(self):
        text = feature_text({"body": "Nazario SpamAssassin https://bad.test/a user@example.com 203.0.113.1 1234"})
        self.assertEqual(text, "urltoken emailtoken iptoken numtoken")

    def test_label_and_source_metadata_are_never_features(self):
        base = {"body": "Read this notice"}
        self.assertEqual(feature_text(base), feature_text(dict(base, label=1, source="phishing", source_id="secret-source")))

    def test_empty_subject_and_empty_body_are_independent(self):
        self.assertEqual(feature_text({"subject": "Notice"}), "notice")
        self.assertEqual(feature_text({"body": "Notice"}), "notice")


class DataLeakageTests(unittest.TestCase):
    def test_exact_duplicate_removed_across_sources(self):
        a = example(0)
        b = normalize_example(dict(a, source="another", source_id="2"))
        kept, counts = deduplicate([a, b])
        self.assertEqual(len(kept), 1)
        self.assertEqual(counts["exact_duplicates_removed"], 1)
        self.assertEqual(kept[0]["sources"], ["another", "synthetic"])

    def test_unicode_whitespace_duplicate_removed(self):
        a = normalize_example({"subject": "HELLO", "body": "Some café text", "label": 0, "source": "a"})
        b = normalize_example({"subject": "hello", "body": "Some cafe\u0301   text", "label": 0, "source": "b"})
        self.assertEqual(len(deduplicate([a, b])[0]), 1)

    def test_template_variants_are_removed_before_split(self):
        records = [normalize_example({"body": f"Please review invoice {number} at https://example.test/{number}", "label": 1, "source": "a", "source_id": str(number)}) for number in (123, 456)]
        kept, counts = deduplicate(records)
        self.assertEqual(len(kept), 1)
        self.assertEqual(counts["template_duplicates_removed"], 1)

    def test_near_duplicate_word_edit_is_detected(self):
        words = [marker(i) for i in range(100)]
        a = normalize_example({"body": " ".join(words), "label": 1, "source": "a"})
        words[50] = "changedtoken"
        b = normalize_example({"body": " ".join(words), "label": 1, "source": "b"})
        self.assertEqual(list(near_pairs([a, b])), [(0, 1)])
        kept, counts = deduplicate([a, b])
        self.assertEqual(len(kept), 1)
        self.assertEqual(counts["near_duplicates_removed"], 1)

    def test_conflicting_labels_are_quarantined_not_majority_voted(self):
        a = example(0)
        b = dict(a, label=1, id="other")
        kept, counts = deduplicate([a, b])
        self.assertEqual(kept, [])
        self.assertEqual(counts["exact_conflicting_rows_excluded"], 2)

    def test_no_guessing_invalid_labels_or_sources(self):
        for label in (-1, 2, None, "1", True):
            with self.subTest(label=label), self.assertRaises(ValueError):
                normalize_example({"body": "text", "label": label, "source": "a"})
        with self.assertRaises(ValueError):
            normalize_example({"body": "text", "label": 0})

    def test_empty_training_example_is_excluded(self):
        self.assertIsNone(normalize_example({"label": 0, "source": "a"}))

    def test_split_reproducibility_and_input_order_independence(self):
        records, _ = deduplicate(toy_records(100))
        first = split_records(records)
        second = split_records(list(reversed(records)))
        self.assertEqual(first, second)
        self.assertNotEqual(first, split_records(records, seed=12))

    def test_no_cross_split_content_template_or_group_leakage(self):
        records = toy_records(100)
        records += [copy.deepcopy(records[0]), copy.deepcopy(records[1])]
        kept, _ = deduplicate(records)
        splits = split_records(kept)
        for field in ("id", "group_id", "exact_hash", "template_hash"):
            sets = [set(r[field] for r in split) for split in splits.values()]
            self.assertFalse(sets[0] & sets[1] or sets[0] & sets[2] or sets[1] & sets[2])
        self.assertEqual(sum(len(s) for s in splits.values()), 100)
        self.assertEqual(len(splits["train"]), 70)

    def test_stratification_preserves_both_classes(self):
        records, _ = deduplicate(toy_records(100))
        for split in split_records(records).values():
            counts = Counter(r["label"] for r in split)
            self.assertLessEqual(abs(counts[0] - counts[1]), 1)

    def test_csv_adapter_excludes_generic_spam_and_checks_integrity(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "safe.csv"
            path.write_text('subject,body,label\nNotice,Normal report,0\nOffer,Generic spam,1\n,,0\n', encoding="utf-8")
            source = {"file": path.name, "name": "ham", "checksum": "sha256:" + digest(path.read_bytes()), "retain_original_label": 0, "label": 0}
            records, summaries = load_sources({"sources": [source]}, directory)
            self.assertEqual(len(records), 1)
            self.assertEqual(summaries[0]["counts"]["excluded_other_labels"], 1)
            self.assertEqual(summaries[0]["counts"]["empty_excluded"], 1)
            path.write_text("modified", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_sources({"sources": [source]}, directory)


class EvaluationTests(unittest.TestCase):
    def test_metrics_confusion_counts_and_probability_quality(self):
        result = metrics([0, 0, 1, 1], [.1, .8, .2, .9])
        self.assertEqual(result["confusion_matrix"], [[1, 1], [1, 1]])
        self.assertEqual(result["false_positives"], 1)
        self.assertEqual(result["false_negatives"], 1)
        self.assertEqual(result["precision"], .5)
        self.assertIsNotNone(result["roc_auc"])
        self.assertIsNotNone(result["pr_auc_average_precision"])
        self.assertAlmostEqual(result["brier_score"], .325)
        self.assertEqual(sum(b["count"] for b in result["calibration_bins"]), 4)

    def test_invalid_probabilities_are_rejected(self):
        for probabilities in ([1.1, .5], [float("nan"), .5], [-.1, .5]):
            with self.assertRaises(ValueError):
                metrics([0, 1], probabilities)

    def test_single_class_source_metrics_do_not_invent_auc(self):
        result = metrics([0, 0], [.1, .7])
        self.assertIsNone(result["roc_auc"])
        self.assertIsNone(result["pr_auc_average_precision"])

    def test_threshold_targets_and_boundary_behavior(self):
        labels = [0] * 30 + [1] * 30
        probabilities = [.1] * 30 + [.9] * 30
        selected = select_thresholds(labels, probabilities)
        self.assertTrue(selected["review_target_met"])
        self.assertTrue(selected["high_target_met"])
        self.assertLessEqual(selected["suspicious"], selected["high"])
        for p, expected in ((0, "LOW PHISHING LIKELIHOOD"), (.499, "LOW PHISHING LIKELIHOOD"), (.5, "SUSPICIOUS"), (.699, "SUSPICIOUS"), (.7, "HIGH PHISHING LIKELIHOOD"), (1, "HIGH PHISHING LIKELIHOOD")):
            self.assertEqual(verdict_for_probability(p, {"suspicious": .5, "high": .7}), expected)

    def test_unattainable_threshold_targets_are_explicit(self):
        selected = select_thresholds([0] * 30 + [1] * 30, [.5] * 60)
        self.assertFalse(selected["review_target_met"])
        self.assertFalse(selected["high_target_met"])

    def test_invalid_thresholds_are_rejected(self):
        for thresholds in ({"suspicious": .8, "high": .4}, {"suspicious": -.1, "high": .8}):
            with self.assertRaises(ValueError):
                verdict_for_probability(.5, thresholds)

    def test_all_candidates_fit_without_using_validation_vocabulary(self):
        records = toy_records(40)
        for name in CANDIDATES:
            with self.subTest(name=name):
                model = model_factory(name)
                model.fit([r["text"] for r in records], [r["label"] for r in records])
                p = model.predict_proba(["validationonlytoken"])[0][1]
                self.assertTrue(0 <= p <= 1)
                pipeline = model.calibrated_classifiers_[0].estimator if hasattr(model, "calibrated_classifiers_") else model
                self.assertNotIn("validationonlytoken", pipeline.named_steps["tfidf"].vocabulary_)


class CandidateInferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        records = toy_records(60)
        cls.model = model_factory("logistic")
        cls.model.fit([r["text"] for r in records], [r["label"] for r in records])
        cls.metadata = {"model_version": "test_candidate", "thresholds": {"suspicious": .5, "high": .7}, "status": "research_candidate"}

    def test_legitimate_versus_obvious_phishing_language(self):
        legitimate = analyze_candidate({"body": "Team meeting project schedule report colleague"}, self.model, self.metadata)
        phishing = analyze_candidate({"body": "Urgent password verify account click suspended"}, self.model, self.metadata)
        self.assertLess(legitimate["phishing_probability"], phishing["phishing_probability"])
        self.assertEqual(legitimate["confidence_band"], "low")
        self.assertEqual(phishing["confidence_band"], "high")

    def test_edge_inputs_are_compatible_bounded_and_deterministic(self):
        for data in ({}, None, {"body": ""}, {"subject": ""}, {"body": "Hi"},
                     {"body": "你好 café résumé"}, {"body": []}, {"body": "<p>Review report</p>"}):
            with self.subTest(data=data):
                first = analyze_candidate(data, self.model, self.metadata)
                self.assertEqual(first, analyze_candidate(data, self.model, self.metadata))
                self.assertTrue(0 <= first["phishing_probability"] <= 100)
                self.assertIsInstance(first["verdict"], str)
                self.assertEqual(json.loads(json.dumps(first)), first)

    def test_empty_input_quality_is_explicit(self):
        self.assertEqual(analyze_candidate({}, self.model, self.metadata)["input_quality"], "no_readable_text")

    def test_runtime_fallback_retains_original_score_and_schema(self):
        result = analyze_text(parse_email(ROOT / "data/samples/test.eml"))
        self.assertEqual(
            {key: result[key] for key in ("phishing_probability", "verdict")},
            {"phishing_probability": 58.05, "verdict": "SUSPICIOUS"},
        )
        self.assertEqual(result["model_status"], "EXPERIMENTAL")
        self.assertEqual(result["validation_status"], "NOT VALIDATED")

    def test_runtime_fallback_handles_malformed_inputs_without_switching_models(self):
        for data in (None, [], "bad", {"body": {}}, {"subject": 10}, {"body": b"hello \xff"}):
            with self.subTest(data=data):
                result = analyze_text(data)
                self.assertTrue(0 <= result["phishing_probability"] <= 100)
                self.assertTrue({"phishing_probability", "verdict"}.issubset(result))
                self.assertEqual(result["evidence_role"], "supporting_evidence_only")

    def test_candidate_loading_is_gated_and_checks_bytes(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory) / "fixture"
            folder.mkdir()
            artifact = folder / "model.joblib"
            joblib.dump(self.model, artifact)
            metadata = dict(self.metadata, validated=False, normalization_version=VERSION,
                            versions={"scikit_learn": sklearn.__version__}, code_sha256={"text.py": digest((ROOT / "ml/text.py").read_bytes())}, artifact_sha256=digest(artifact.read_bytes()))
            write_json(folder / "metadata.json", metadata)
            with patch("ml.inference.MODEL_ROOT", Path(directory)):
                with self.assertRaises(ValueError):
                    load_candidate("fixture")
                model, _ = load_candidate("fixture", research=True)
                self.assertEqual(model.predict_proba(["hi"]).tolist(), self.model.predict_proba(["hi"]).tolist())
                artifact.write_bytes(b"not a model")
                with patch("ml.inference.joblib.load") as load:
                    with self.assertRaises(ValueError):
                        load_candidate("fixture", research=True)
                    load.assert_not_called()

    def test_candidate_loading_from_another_working_directory(self):
        with TemporaryDirectory() as directory, TemporaryDirectory() as unrelated:
            folder = Path(directory) / "fixture"
            folder.mkdir()
            artifact = folder / "model.joblib"
            joblib.dump(self.model, artifact)
            write_json(folder / "metadata.json", dict(self.metadata, validated=False, normalization_version=VERSION,
                versions={"scikit_learn": sklearn.__version__}, code_sha256={"text.py": digest((ROOT / "ml/text.py").read_bytes())}, artifact_sha256=digest(artifact.read_bytes())))
            code = "import sys; from pathlib import Path; import ml.inference as i; i.MODEL_ROOT=Path(sys.argv[1]); m,d=i.load_candidate('fixture',research=True); assert 0 <= i.analyze_candidate({'body':'hello'},m,d)['phishing_probability'] <= 100"
            process = subprocess.run([sys.executable, "-c", code, directory], cwd=unrelated,
                env=dict(os.environ, PYTHONPATH=str(ROOT)), capture_output=True, text=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)

    def test_training_import_cannot_overwrite_legacy(self):
        files = [ROOT / "ml/vectorizer.joblib", ROOT / "ml/phishing_model.joblib"]
        before = [digest(p.read_bytes()) for p in files]
        module = importlib.import_module("ml.train_model")
        importlib.reload(module)
        with self.assertRaises(ValueError):
            module.train_legacy_demo(ROOT / "ml")
        self.assertEqual(before, [digest(p.read_bytes()) for p in files])


class EvaluationProtocolTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(redirect_stdout(io.StringIO()))

    def prepare(self, directory, broken_test=False):
        directory = Path(directory)
        dataset = directory / "data"
        dataset.mkdir()
        splits = {"train": toy_records(80), "validation": [example(i, i % 2) for i in range(100, 140)],
                  "test": [example(i, i % 2) for i in range(200, 240)]}
        manifest = {"dataset_id": "synthetic-fixture-only", "splits": {},
                    "recipe": {"promotion_limitations": ["Synthetic unit-test fixture; never deploy"]}}
        for name, records in splits.items():
            path = dataset / (name + ".jsonl")
            path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
            if name == "test" and broken_test:
                path.write_text("TEST MUST NOT BE OPENED IN SELECTION", encoding="utf-8")
            manifest["splits"][name] = {"count": len(records), "sha256": digest(path.read_bytes())}
        write_json(dataset / "manifest.json", manifest)
        holdout = [{"metrics": metrics([0, 1], [.1, .9])}]
        return dataset, directory / "run", directory / "selection.json", holdout

    def test_selection_never_reads_final_test_and_lock_is_immutable(self):
        with TemporaryDirectory() as directory:
            dataset, run, lock, holdout = self.prepare(directory, broken_test=True)
            with patch("ml.experiment.source_holdout", return_value=holdout):
                result = select(dataset, run, lock)
            self.assertFalse(result["test_opened"])
            self.assertIn(result["selected_model"], CANDIDATES)
            self.assertTrue(lock.exists())
            with self.assertRaises(FileExistsError):
                select(dataset, run, lock)

    def test_final_evaluation_requires_lock_and_is_single_use(self):
        with TemporaryDirectory() as directory:
            dataset, run, lock, holdout = self.prepare(directory)
            destination, report = Path(directory) / "model", Path(directory) / "final.json"
            with self.assertRaises(FileNotFoundError):
                finalize(dataset, run, lock, destination, report)
            with patch("ml.experiment.source_holdout", return_value=holdout):
                chosen = select(dataset, run, lock)
            result = finalize(dataset, run, lock, destination, report)
            self.assertEqual(result["selected_model"], chosen["selected_model"])
            self.assertEqual(set(result["candidates_test_at_0_5"]), set(CANDIDATES))
            self.assertEqual(result["active_model"], "legacy_demo_16")
            self.assertFalse(json.loads((destination / "metadata.json").read_text())["validated"])
            with self.assertRaises(FileExistsError):
                finalize(dataset, run, lock, Path(directory) / "different", Path(directory) / "different.json")

    def test_changed_model_or_dataset_cannot_be_evaluated_under_old_lock(self):
        with TemporaryDirectory() as directory:
            dataset, run, lock, holdout = self.prepare(directory)
            with patch("ml.experiment.source_holdout", return_value=holdout):
                result = select(dataset, run, lock)
            (run / (result["selected_model"] + ".joblib")).write_bytes(b"changed")
            with self.assertRaises(ValueError):
                finalize(dataset, run, lock, Path(directory) / "model", Path(directory) / "final.json")
            self.assertFalse(Path(str(lock) + ".test-opened").exists())

    def test_partition_tampering_is_detected(self):
        with TemporaryDirectory() as directory:
            dataset, _, _, _ = self.prepare(directory)
            manifest = json.loads((dataset / "manifest.json").read_text())
            (dataset / "train.jsonl").write_text("changed")
            with self.assertRaises(ValueError):
                checked_rows(dataset, "train", manifest)



class DownloadBoundaryTests(unittest.TestCase):
    def source(self):
        return {"file": "fixture.csv", "license": "CC-BY-4.0",
                "url": "https://zenodo.org/api/records/8339691/files/fixture.csv/content",
                "checksum": "sha256:" + digest(b"subject,body,label\n")}

    def test_only_reviewed_csv_urls_can_be_downloaded(self):
        for changes in ({"url": "https://unreviewed.test/payload"}, {"file": "../escape.csv"},
                        {"file": "payload.exe"}, {"license": "unknown"}):
            with self.subTest(changes=changes), TemporaryDirectory() as directory:
                with patch("urllib.request.urlopen") as fetch:
                    with self.assertRaises(ValueError):
                        fetch_source(dict(self.source(), **changes), directory)
                    fetch.assert_not_called()

    def test_checksum_mismatch_is_rejected_without_reading_data(self):
        with TemporaryDirectory() as directory:
            Path(directory, "fixture.csv").write_bytes(b"corrupted cache")
            with patch("urllib.request.urlopen") as fetch:
                with self.assertRaises(ValueError):
                    fetch_source(self.source(), directory)
                fetch.assert_not_called()

    def test_verified_download_cache_needs_no_network(self):
        with TemporaryDirectory() as directory:
            Path(directory, "fixture.csv").write_bytes(b"subject,body,label\n")
            with patch("urllib.request.urlopen") as fetch:
                self.assertEqual(fetch_source(self.source(), directory), "fixture.csv")
                fetch.assert_not_called()

    def test_ml_alone_cannot_create_a_malicious_fusion_verdict(self):
        from backend.analyzers.fusion_engine import calculate_final_risk
        result = calculate_final_risk({"risk_score": 0}, {"risk_score": 0}, {"hops": []}, {"phishing_probability": 100})
        self.assertEqual(result["risk_score"], 0)
        self.assertNotIn(result["verdict"], ("SUSPICIOUS", "HIGH RISK", "CRITICAL"))

if __name__ == "__main__":
    unittest.main()
