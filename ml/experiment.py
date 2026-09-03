"""Small fixed model comparison: select on validation, lock, then unseal test."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import time

import joblib
import numpy as np
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, brier_score_loss,
    confusion_matrix, f1_score, fbeta_score, log_loss, precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import StratifiedKFold
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC
from threadpoolctl import threadpool_limits

from .data_pipeline import ROOT, SEED, digest, read_rows, write_json
from .text import VERSION

CANDIDATES = ("logistic", "logistic_sigmoid", "linear_svm_sigmoid", "multinomial_nb")
FEATURES = {"ngram_range": (1, 2), "min_df": 2, "max_df": .98, "max_features": 50000,
            "sublinear_tf": True, "strip_accents": "unicode"}
POLICY = {
    "review_recall_target": .95, "review_max_fpr": .05,
    "high_precision_target": .98, "high_max_fpr": .01,
    "high_minimum_predictions": 20,
    "promotion_min_precision": .90, "promotion_min_recall": .95,
    "promotion_max_fpr": .05, "promotion_max_brier": .10,
    "promotion_max_source_error": .20, "promotion_max_single_inference_ms": 25,
    "selection": "0.35*F1 + 0.35*recall + 0.15*specificity + 0.15*(1-Brier) - 0.20*worst source-holdout error; ties prefer simpler/faster model. Test results never enter selection.",
    "threshold_search": "Fixed grid 0.05..0.95 step 0.01, plus 0.975, 0.99, 0.995. Review: largest feasible threshold <=0.70; otherwise maximum F2 within that range. High: lowest feasible threshold >=max(0.70, review+0.10) with >=20 positive predictions; otherwise 0.995 and target marked unmet.",
    "required_external_evidence": "Modern independently labeled source-balanced data; source/label confounding blocks default activation regardless of benchmark accuracy.",
}


def model_factory(name, seed=SEED):
    if name not in CANDIDATES:
        raise ValueError("Unknown model candidate")
    if name == "multinomial_nb":
        classifier = MultinomialNB(alpha=1.0)
    elif name == "linear_svm_sigmoid":
        classifier = LinearSVC(C=1.0, class_weight="balanced", max_iter=5000, random_state=seed)
    else:
        classifier = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=seed)
    pipeline = Pipeline([("tfidf", TfidfVectorizer(**FEATURES)), ("classifier", classifier)])
    if name.endswith("sigmoid"):
        # TF-IDF is inside each fold: calibration never sees in-sample predictions
        # or a vocabulary fitted on its calibration fold. Only training data used.
        return CalibratedClassifierCV(pipeline, method="sigmoid", ensemble=False,
            cv=StratifiedKFold(3, shuffle=True, random_state=seed), n_jobs=1)
    return pipeline


def calibration_bins(labels, probabilities):
    bins = []
    for index in range(10):
        mask = (probabilities >= index / 10) & ((probabilities < (index + 1) / 10) if index < 9 else (probabilities <= 1))
        if mask.any():
            bins.append({"lower": index / 10, "upper": (index + 1) / 10,
                         "count": int(mask.sum()), "mean_probability": float(probabilities[mask].mean()),
                         "observed_phishing_rate": float(labels[mask].mean())})
    return bins


def metrics(labels, probabilities, threshold=.5):
    labels, probabilities = np.asarray(labels, dtype=int), np.asarray(probabilities, dtype=float)
    if len(labels) != len(probabilities) or not len(labels) or not np.isfinite(probabilities).all() or np.any((probabilities < 0) | (probabilities > 1)):
        raise ValueError("Invalid probability evaluation input")
    predictions = probabilities >= threshold
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    bins = calibration_bins(labels, probabilities)
    return {"threshold": float(threshold), "count": len(labels),
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "f2": float(fbeta_score(labels, predictions, beta=2, zero_division=0)),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "false_positives": int(fp), "false_negatives": int(fn),
        "false_positive_rate": float(fp / (tn + fp)) if tn + fp else None,
        "roc_auc": float(roc_auc_score(labels, probabilities)) if len(set(labels)) == 2 else None,
        "pr_auc_average_precision": float(average_precision_score(labels, probabilities)) if len(set(labels)) == 2 else None,
        "brier_score": float(brier_score_loss(labels, probabilities)),
        "log_loss": float(log_loss(labels, probabilities, labels=[0, 1])),
        "ece_10_equal_width": sum(b["count"] * abs(b["mean_probability"] - b["observed_phishing_rate"]) for b in bins) / len(labels),
        "calibration_bins": bins}


def select_thresholds(labels, probabilities):
    grid = sorted({round(i / 100, 2) for i in range(5, 96)} | {.975, .99, .995})
    evaluated = [metrics(labels, probabilities, threshold) for threshold in grid]
    review_grid = [m for m in evaluated if m["threshold"] <= .70]
    review_options = [m for m in review_grid if m["recall"] >= POLICY["review_recall_target"]
                      and m["false_positive_rate"] <= POLICY["review_max_fpr"]]
    review = max(review_options, key=lambda m: m["threshold"]) if review_options else max(
        review_grid, key=lambda m: (m["f2"], m["recall"], -m["false_positive_rate"], m["threshold"]))
    high_options = [m for m in evaluated if m["threshold"] >= max(.70, round(review["threshold"] + .10, 2))
                    and m["precision"] >= POLICY["high_precision_target"]
                    and m["false_positive_rate"] <= POLICY["high_max_fpr"]
                    and sum(row[1] for row in m["confusion_matrix"]) >= POLICY["high_minimum_predictions"]]
    high = min(high_options, key=lambda m: m["threshold"]) if high_options else evaluated[-1]
    return {"suspicious": review["threshold"], "high": high["threshold"],
            "review_target_met": bool(review_options), "high_target_met": bool(high_options),
            "validation_review_metrics": review, "validation_high_metrics": high,
            "validation_tradeoff_grid": [{key: m[key] for key in ("threshold", "precision", "recall", "f1", "false_positives", "false_negatives", "false_positive_rate")} for m in evaluated]}


def source_holdout(name, train):
    result = []
    for held_out in ({"ling", "nazario"}, {"spamassassin", "nigerian_fraud"}):
        fitting = [r for r in train if not (set(r["sources"]) & held_out)]
        checking = [r for r in train if set(r["sources"]) <= held_out]
        if len({r["label"] for r in fitting}) != 2 or len({r["label"] for r in checking}) != 2:
            raise ValueError("Source holdout requires both classes and independent sources")
        model = model_factory(name)
        model.fit([r["text"] for r in fitting], [r["label"] for r in fitting])
        probabilities = model.predict_proba([r["text"] for r in checking])[:, 1]
        result.append({"held_out_sources": sorted(held_out), "train_count": len(fitting),
                       "metrics": metrics([r["label"] for r in checking], probabilities)})
    return result


def legacy_probabilities(records):
    vectorizer = joblib.load(ROOT / "vectorizer.joblib")
    model = joblib.load(ROOT / "phishing_model.joblib")
    return model.predict_proba(vectorizer.transform([r["subject"] + "\n" + r["body"] for r in records]))[:, 1]


def checked_rows(dataset, partition, manifest):
    path = Path(dataset) / (partition + ".jsonl")
    if digest(path.read_bytes()) != manifest["splits"][partition]["sha256"]:
        raise ValueError("Dataset partition differs from the sealed manifest")
    return read_rows(path)


def code_hashes():
    return {name: digest((ROOT / name).read_bytes()) for name in ("text.py", "data_pipeline.py", "experiment.py")}


def select(dataset, run, lock_path):
    dataset, run, lock_path = Path(dataset), Path(run), Path(lock_path)
    if run.exists() or lock_path.exists():
        raise FileExistsError("Selection is immutable; use a new run/version")
    manifest = json.loads((dataset / "manifest.json").read_text())
    train = checked_rows(dataset, "train", manifest)
    validation = checked_rows(dataset, "validation", manifest)
    # This function deliberately never reads test.jsonl.
    train_text, train_y = [r["text"] for r in train], [r["label"] for r in train]
    val_text, val_y = [r["text"] for r in validation], [r["label"] for r in validation]
    run.mkdir(parents=True)
    candidates, validation_predictions = {}, {}
    with threadpool_limits(limits=1):
        for name in CANDIDATES:
            print("Fitting training-only candidate:", name, flush=True)
            start = time.perf_counter()
            model = model_factory(name)
            model.fit(train_text, train_y)
            seconds = time.perf_counter() - start
            probabilities = model.predict_proba(val_text)[:, 1]
            validation_predictions[name] = probabilities
            value = metrics(val_y, probabilities)
            holdouts = source_holdout(name, train)
            worst_error = max(max(1 - h["metrics"]["recall"], h["metrics"]["false_positive_rate"]) for h in holdouts)
            timings = []
            for text in val_text[:100]:
                start = time.perf_counter()
                model.predict_proba([text])
                timings.append((time.perf_counter() - start) * 1000)
            path = run / (name + ".joblib")
            joblib.dump(model, path, compress=3)
            score = .35 * value["f1"] + .35 * value["recall"] + .15 * (1 - value["false_positive_rate"]) + .15 * (1 - value["brier_score"]) - .20 * worst_error
            candidates[name] = {"validation": value, "training_source_holdouts": holdouts,
                "worst_source_error": worst_error, "selection_score": score,
                "fit_seconds": seconds, "single_inference_ms_median": float(np.median(timings)),
                "single_inference_ms_p95": float(np.percentile(timings, 95)),
                "artifact_bytes": path.stat().st_size, "artifact_sha256": digest(path.read_bytes())}
            print(name, "validation F1=", round(value["f1"], 4), "source error=", round(worst_error, 4), flush=True)
    simplicity = {"multinomial_nb": 0, "logistic": 1, "logistic_sigmoid": 2, "linear_svm_sigmoid": 2}
    selected = max(CANDIDATES, key=lambda name: (candidates[name]["selection_score"], -simplicity[name], -candidates[name]["single_inference_ms_median"]))
    thresholds = select_thresholds(val_y, validation_predictions[selected])
    lock = {"model_version": "candidate_v1", "selected_model": selected,
        "selection_locked_at": datetime.now(timezone.utc).isoformat(), "test_opened": False,
        "seed": SEED, "normalization_version": VERSION, "feature_settings": FEATURES,
        "versions": {"python": platform.python_version(), "scikit_learn": sklearn.__version__, "numpy": np.__version__, "joblib": joblib.__version__},
        "code_sha256": code_hashes(), "dataset_manifest_sha256": digest((dataset / "manifest.json").read_bytes()),
        "dataset_id": manifest["dataset_id"], "policy": POLICY, "candidates": candidates,
        "thresholds": thresholds, "legacy_validation": metrics(val_y, legacy_probabilities(validation)),
        "selection_reason": "Highest predeclared validation/transfer/calibration composite among four fixed lightweight candidates. No test data used. Candidate selection does not authorize activation.",
        "promotion_limitations": manifest["recipe"]["promotion_limitations"]}
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(lock_path, lock)
    print("Locked candidate:", selected, "thresholds:", thresholds["suspicious"], thresholds["high"], flush=True)
    return lock


def finalize(dataset, run, lock_path, destination, report_path):
    dataset, run, destination, report_path = map(Path, (dataset, run, destination, report_path))
    lock_path = Path(lock_path)
    if destination.exists() or report_path.exists():
        raise FileExistsError("Final test is already evaluated for this output; do not tune or overwrite")
    lock = json.loads(lock_path.read_text())
    if lock["test_opened"] or lock["code_sha256"] != code_hashes():
        raise ValueError("Selection lock/code mismatch")
    if digest((dataset / "manifest.json").read_bytes()) != lock["dataset_manifest_sha256"]:
        raise ValueError("Dataset manifest changed after model selection")
    for name in CANDIDATES:
        if digest((run / (name + ".joblib")).read_bytes()) != lock["candidates"][name]["artifact_sha256"]:
            raise ValueError("A frozen candidate changed after selection")
    # Consume the lock before opening test, even if evaluation is interrupted.
    # A fresh output directory cannot be used to repeatedly unseal the same run.
    marker = Path(str(lock_path) + ".test-opened")
    with marker.open("x", encoding="utf-8") as handle:
        handle.write(datetime.now(timezone.utc).isoformat())
    manifest = json.loads((dataset / "manifest.json").read_text())
    test = checked_rows(dataset, "test", manifest)
    texts, labels = [r["text"] for r in test], [r["label"] for r in test]
    results, selected_probabilities = {}, None
    with threadpool_limits(limits=1):
        for name in CANDIDATES:
            model = joblib.load(run / (name + ".joblib"))
            probabilities = model.predict_proba(texts)[:, 1]
            results[name] = metrics(labels, probabilities)
            if name == lock["selected_model"]:
                selected_probabilities = probabilities
    review = metrics(labels, selected_probabilities, lock["thresholds"]["suspicious"])
    high = metrics(labels, selected_probabilities, lock["thresholds"]["high"])
    legacy = metrics(labels, legacy_probabilities(test))
    failures = list(lock["promotion_limitations"])
    checks = {"precision": review["precision"] >= POLICY["promotion_min_precision"],
              "recall": review["recall"] >= POLICY["promotion_min_recall"],
              "false_positive_rate": review["false_positive_rate"] <= POLICY["promotion_max_fpr"],
              "brier": review["brier_score"] <= POLICY["promotion_max_brier"],
              "source_generalization": lock["candidates"][lock["selected_model"]]["worst_source_error"] <= POLICY["promotion_max_source_error"],
              "inference_speed": lock["candidates"][lock["selected_model"]]["single_inference_ms_p95"] <= POLICY["promotion_max_single_inference_ms"],
              "better_than_legacy_f1": review["f1"] > legacy["f1"],
              "threshold_targets": lock["thresholds"]["review_target_met"] and lock["thresholds"]["high_target_met"]}
    failures += ["Evaluation gate failed: " + key for key, passed in checks.items() if not passed]
    by_source = {}
    for source in sorted({r["source"] for r in test}):
        indices = [i for i, r in enumerate(test) if r["source"] == source]
        by_source[source] = metrics(np.asarray(labels)[indices], selected_probabilities[indices], lock["thresholds"]["suspicious"])
    report = {"selected_model": lock["selected_model"], "selection_lock_sha256": digest(lock_path.read_bytes()),
        "test_evaluated_at": datetime.now(timezone.utc).isoformat(), "dataset_id": manifest["dataset_id"],
        "split_counts": manifest["splits"], "candidates_test_at_0_5": results,
        "selected_locked_review_threshold": review, "selected_locked_high_threshold": high,
        "selected_test_by_source": by_source, "legacy_test_at_0_5": legacy,
        "selected_error_ids": {"false_positive": [r["id"] for r, p in zip(test, selected_probabilities) if r["label"] == 0 and p >= lock["thresholds"]["suspicious"]],
                               "false_negative": [r["id"] for r, p in zip(test, selected_probabilities) if r["label"] == 1 and p < lock["thresholds"]["suspicious"]]},
        "promotion_checks": checks, "promotion_blockers": failures,
        "active_model": "legacy_demo_16" if failures else "candidate_v1",
        "test_methodology": "Single post-lock evaluation; all candidate test metrics reported for transparency, never used to switch candidates or retune thresholds. Confusion matrices are [[TN,FP],[FN,TP]]. PR-AUC is average precision. Brier combines calibration and discrimination; reliability bins are provided."}
    destination.mkdir(parents=True)
    artifact = destination / "model.joblib"
    artifact.write_bytes((run / (lock["selected_model"] + ".joblib")).read_bytes())
    metadata = {"model_version": "candidate_v1", "model_type": lock["selected_model"],
        "status": "research_candidate" if failures else "validated_candidate", "validated": not failures,
        "trained_at": lock["selection_locked_at"], "random_seed": SEED,
        "normalization_version": VERSION, "feature_settings": FEATURES, "versions": lock["versions"],
        "dataset_id": manifest["dataset_id"], "dataset_manifest_sha256": lock["dataset_manifest_sha256"],
        "thresholds": {k: lock["thresholds"][k] for k in ("suspicious", "high")},
        "artifact_sha256": digest(artifact.read_bytes()), "code_sha256": lock["code_sha256"],
        "test_metrics": review, "validation_metrics": lock["candidates"][lock["selected_model"]]["validation"],
        "promotion_blockers": failures, "legacy_artifacts_overwritten": False}
    write_json(destination / "metadata.json", metadata)
    write_json(report_path, report)
    print(json.dumps({"selected": lock["selected_model"], "test_at_locked_threshold": review,
                      "promotion_checks": checks, "active_model": report["active_model"]}, indent=2), flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("select", "finalize"))
    parser.add_argument("--dataset", type=Path, default=ROOT / "data/processed/public_email_v1")
    parser.add_argument("--run", type=Path, default=ROOT / "runs/candidate_v1")
    parser.add_argument("--lock", type=Path, default=ROOT / "reports/candidate_v1_selection.json")
    parser.add_argument("--destination", type=Path, default=ROOT / "models/candidate_v1")
    parser.add_argument("--report", type=Path, default=ROOT / "reports/candidate_v1_final.json")
    args = parser.parse_args()
    if args.phase == "select":
        select(args.dataset, args.run, args.lock)
    else:
        finalize(args.dataset, args.run, args.lock, args.destination, args.report)


if __name__ == "__main__":
    main()
