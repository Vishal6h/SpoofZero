"""Locked v2 evaluation: source generalization is required, never optional."""
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
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, balanced_accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from threadpoolctl import threadpool_limits

from ml.data_pipeline import ROOT, SEED, digest, write_json
from ml.experiment import (CANDIDATES, FEATURES, checked_rows, metrics as base_metrics,
                           model_factory, select_thresholds)
from .data import assert_disjoint, balance_training, summaries
from .text import VERSION

POLICY = {
    "validation_min_precision": .90, "validation_min_recall": .95,
    "validation_max_fpr": .05, "validation_min_f1": .90,
    "validation_max_brier": .10, "validation_max_ece": .05,
    "validation_max_source_error": .10,
    "loso_max_source_error": .10, "loso_min_macro_recall": .90,
    "loso_max_macro_fpr": .05, "loso_max_macro_brier": .10,
    "loso_max_worst_brier": .15, "loso_max_macro_ece": .10,
    "transfer_min_recall": .90, "transfer_max_fpr": .05, "transfer_min_f1": .90,
    "minimum_held_out_source_support": 100,
    "minimum_independent_real_both_class_sources": 2,
    "max_p95_inference_ms": 25,
    "training_cap_per_source_class": 1500,
    "rationale": {
        "recall": "At most 5% missed phishing on mixed validation, 10% on any held-out phishing source; mixed results cannot excuse source failures.",
        "false_positives": "At most 5% legitimate FPR on mixed validation and each paired transfer; 10% worst-source error is a research ceiling, not an acceptable operational inbox guarantee.",
        "f1": "At least 0.90 balances precision/recall; accuracy alone is not a selection criterion.",
        "calibration": "Brier<=0.10 and ECE<=0.05 on validation; source-macro Brier<=0.10/ECE<=0.10 and no source Brier>0.15 prevent large sources masking overconfidence.",
        "support": "At least 100 independent representatives in each held-out source; small folds are insufficient evidence, not automatic passes.",
        "provenance": "At least two independently collected modern real-email sources with both classes plus a representative fresh external holdout; synthetic generation and a new release date do not establish this.",
        "latency": "p95 <=25 ms per normalized text on this CPU, matching the prior lightweight research budget.",
        "bands": "Both inherited review and high-band validation targets must be feasible; failed targets are explicit.",
    },
    "selection": "Prefer development-gate passes, then 0.50*(1-worst source error)+0.25*LOSO macro recall+0.15*validation F1+0.10*(1-LOSO macro Brier); ties prefer simpler/faster. Final test never selects or tunes.",
}
SIMPLICITY = {"multinomial_nb": 0, "logistic": 1, "logistic_sigmoid": 2, "linear_svm_sigmoid": 2}


def metric_set(labels, probabilities, threshold=.5):
    labels = np.asarray(labels)
    if labels.ndim != 1 or not len(labels) or not set(labels.tolist()) <= {0, 1}:
        raise ValueError("Evaluation labels must be binary and nonempty")
    if not 0 <= threshold <= 1:
        raise ValueError("Threshold must be in [0,1]")
    result = base_metrics(labels, probabilities, threshold)
    positives, negatives = int((labels == 1).sum()), int((labels == 0).sum())
    result["class_counts"] = {"0": negatives, "1": positives}
    result["false_negative_rate"] = result["false_negatives"] / positives if positives else None
    if not positives:
        result["recall"] = None
    if not positives or not negatives:
        # Positive-class precision/F1 without both classes is misleading source evidence.
        result["precision"] = result["f1"] = result["f2"] = None
    rates = [result[k] for k in ("false_positive_rate", "false_negative_rate") if result[k] is not None]
    result["worst_class_error"] = max(rates)
    return result


def source_summary(per_source):
    if not per_source:
        return {"source_count": 0, "macro": {}, "worst_source_error": None,
                "worst_source_brier": None, "minimum_support": 0}
    keys = ("precision", "recall", "f1", "false_positive_rate", "false_negative_rate",
            "brier_score", "log_loss", "ece_10_equal_width")
    macro = {}
    for key in keys:
        values = [m[key] for m in per_source.values() if m[key] is not None]
        macro[key] = {"value": float(np.mean(values)) if values else None,
                      "sources_with_support": len(values)}
    return {"source_count": len(per_source), "macro": macro,
            "worst_source_error": max(m["worst_class_error"] for m in per_source.values()),
            "worst_source_brier": max(m["brier_score"] for m in per_source.values()),
            "minimum_support": min(m["count"] for m in per_source.values())}


def evaluate_records(records, probabilities, threshold):
    probabilities = np.asarray(probabilities)
    if len(records) != len(probabilities):
        raise ValueError("Prediction/record length mismatch")
    by_source = {}
    # Representative source is used for macro statistics; merged provenance
    # remains available and is purged at source-holdout boundaries.
    for source in sorted({r["source"] for r in records}):
        ix = [i for i, r in enumerate(records) if r["source"] == source]
        by_source[source] = metric_set([records[i]["label"] for i in ix], probabilities[ix], threshold)
    return {"pooled": metric_set([r["label"] for r in records], probabilities, threshold),
            "per_source": by_source, "source_summary": source_summary(by_source)}


def source_partition(records, held_out):
    held_out = set(held_out)
    fit = [r for r in records if not set(r["sources"]) & held_out]
    check = [r for r in records if set(r["sources"]) <= held_out]
    purged = len(records) - len(fit) - len(check)
    assert_disjoint({"fit": fit, "check": check})
    return fit, check, purged


def internal_validation(records, seed=SEED):
    fit, validation = [], []
    strata = {}
    for r in sorted(records, key=lambda r: r["id"]):
        strata.setdefault((tuple(r["sources"]), r["label"]), []).append(r)
    for _, rows in sorted(strata.items()):
        if len(rows) < 8:
            fit.extend(rows)
            continue
        train, val = train_test_split(rows, test_size=.20, random_state=seed)
        fit.extend(train)
        validation.extend(val)
    return sorted(fit, key=lambda r: r["id"]), sorted(validation, key=lambda r: r["id"])


def source_fold(name, train, held_out, seed=SEED):
    eligible, checking, purged = source_partition(train, held_out)
    fit, validation = internal_validation(eligible, seed)
    fit = balance_training(fit, POLICY["training_cap_per_source_class"], seed)
    description = {"held_out_sources": sorted(held_out), "purged_cross_boundary": purged,
                   "fitting": summaries(fit), "internal_validation": summaries(validation),
                   "checking": summaries(checking)}
    if not checking or any(len({r["label"] for r in rows}) != 2 for rows in (fit, validation)):
        return dict(description, status="INSUFFICIENT_SUPPORT",
                    reason="Fitting and its internal validation need both classes; held-out sources need observations.")
    model = model_factory(name, seed)
    model.fit([r["text"] for r in fit], [r["label"] for r in fit])
    val_p = model.predict_proba([r["text"] for r in validation])[:, 1]
    bands = select_thresholds([r["label"] for r in validation], val_p)
    check_p = model.predict_proba([r["text"] for r in checking])[:, 1]
    return dict(description, status="EVALUATED",
                threshold_origin="internal validation from fitting sources only",
                thresholds={k: bands[k] for k in ("suspicious", "high", "review_target_met", "high_target_met")},
                evaluation=evaluate_records(checking, check_p, bands["suspicious"]),
                fixed_0_5=evaluate_records(checking, check_p, .5))


def source_evaluation(name, train, pairs, seed=SEED):
    sources = sorted({s for r in train for s in r["sources"]})
    loso = []
    for source in sources:
        print("  LOSO:", source, flush=True)
        loso.append(source_fold(name, train, {source}, seed))
    transfer = []
    for pair in pairs:
        if set(pair) <= set(sources):
            print("  transfer holdout:", ",".join(pair), flush=True)
            transfer.append(source_fold(name, train, set(pair), seed))
    # Exactly one non-overlapping checking subset per LOSO source.
    per_source = {}
    for fold in loso:
        if fold["status"] == "EVALUATED":
            per_source.update(fold["evaluation"]["per_source"])
    return {"leave_one_source_out": loso, "paired_source_transfer": transfer,
            "summary": source_summary(per_source),
            "all_folds_evaluated": bool(loso) and len(transfer) == len(pairs) and
                all(f["status"] == "EVALUATED" for f in loso + transfer),
            "expected_sources": sources}


def gate_results(validation, source_tests, thresholds, latency, evidence):
    """Fail closed for missing source, probability or provenance evidence."""
    gates = {}
    def check(name, actual, operator, limit):
        finite = isinstance(actual, (float, int)) and np.isfinite(actual)
        passed = bool(finite and (actual >= limit if operator == ">=" else actual <= limit))
        gates[name] = {"passed": passed, "actual": actual, "operator": operator, "limit": limit}
    mixed, sm = validation["pooled"], validation["source_summary"]
    for name, key, operator, setting in (
        ("validation_precision", "precision", ">=", "validation_min_precision"),
        ("validation_recall", "recall", ">=", "validation_min_recall"),
        ("validation_fpr", "false_positive_rate", "<=", "validation_max_fpr"),
        ("validation_f1", "f1", ">=", "validation_min_f1"),
        ("validation_brier", "brier_score", "<=", "validation_max_brier"),
        ("validation_ece", "ece_10_equal_width", "<=", "validation_max_ece")):
        check(name, mixed[key], operator, POLICY[setting])
    check("validation_worst_source", sm["worst_source_error"], "<=", POLICY["validation_max_source_error"])
    summary = source_tests["summary"]
    check("loso_worst_source_error", summary["worst_source_error"], "<=", POLICY["loso_max_source_error"])
    for key, operator, setting in (
        ("recall", ">=", "loso_min_macro_recall"),
        ("false_positive_rate", "<=", "loso_max_macro_fpr"),
        ("brier_score", "<=", "loso_max_macro_brier"),
        ("ece_10_equal_width", "<=", "loso_max_macro_ece")):
        check("loso_macro_" + key, summary["macro"].get(key, {}).get("value"), operator, POLICY[setting])
    check("loso_worst_brier", summary["worst_source_brier"], "<=", POLICY["loso_max_worst_brier"])
    check("source_sample_support", summary["minimum_support"], ">=", POLICY["minimum_held_out_source_support"])
    paired = [f["evaluation"]["pooled"] for f in source_tests["paired_source_transfer"]
              if f["status"] == "EVALUATED"]
    def extremum(key, function):
        values = [m[key] for m in paired]
        return function(values) if values and all(v is not None for v in values) else None
    check("transfer_min_recall", extremum("recall", min), ">=", POLICY["transfer_min_recall"])
    check("transfer_max_fpr", extremum("false_positive_rate", max), "<=", POLICY["transfer_max_fpr"])
    check("transfer_min_f1", extremum("f1", min), ">=", POLICY["transfer_min_f1"])
    check("inference_p95_ms", latency, "<=", POLICY["max_p95_inference_ms"])
    check("independent_real_both_class_sources", evidence.get("independent_real_both_class_sources"), ">=",
          POLICY["minimum_independent_real_both_class_sources"])
    for name, passed in (
        ("all_source_folds_evaluated", source_tests["all_folds_evaluated"]),
        ("validation_band_targets", thresholds["review_target_met"] and thresholds["high_target_met"]),
        ("representative_external_holdout", evidence.get("representative_external_holdout") is True)):
        gates[name] = {"passed": bool(passed), "actual": bool(passed), "operator": "is", "limit": True}
    return {"gates": gates, "passed_all": all(g["passed"] for g in gates.values()),
            "failed": [name for name, gate in gates.items() if not gate["passed"]]}


def code_hashes():
    names = ("text.py", "data_pipeline.py", "experiment.py", "generalization/text.py",
             "generalization/data.py", "generalization/evaluate.py", "generalization/fetch.py",
             "generalization/inference.py")
    return {name: digest((ROOT / name).read_bytes()) for name in names}


def source_predictability(train, validation):
    """Diagnostic only: can text identify its corpus? Not a phishing model."""
    model = Pipeline([("tfidf", TfidfVectorizer(**FEATURES)),
                      ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=SEED))])
    model.fit([r["text"] for r in train], [r["source"] for r in train])
    predicted = model.predict([r["text"] for r in validation])
    y = [r["source"] for r in validation]
    counts = Counter(y)
    return {"validation_accuracy": float(accuracy_score(y, predicted)),
            "validation_balanced_accuracy": float(balanced_accuracy_score(y, predicted)),
            "majority_source_baseline": max(counts.values()) / len(y),
            "scope": "Training fitted text-to-source diagnostic; source/labels are never phishing-model features. High source predictability indicates residual collection/topic distinctions, not necessarily intentional leakage."}


def select(dataset, run, lock_path):
    dataset, run, lock_path = map(Path, (dataset, run, lock_path))
    if run.exists() or lock_path.exists():
        raise FileExistsError("Selection and run are immutable; use a new research version")
    manifest = json.loads((dataset / "manifest.json").read_text())
    train_all = checked_rows(dataset, "train", manifest)
    validation = checked_rows(dataset, "validation", manifest)
    assert_disjoint({"train": train_all, "validation": validation})
    train = balance_training(train_all, POLICY["training_cap_per_source_class"], SEED)
    run.mkdir(parents=True)
    candidates = {}
    with threadpool_limits(limits=1):
        for name in CANDIDATES:
            print("Fitting v2 candidate:", name, flush=True)
            start = time.perf_counter()
            model = model_factory(name)
            model.fit([r["text"] for r in train], [r["label"] for r in train])
            fit_seconds = time.perf_counter() - start
            val_p = model.predict_proba([r["text"] for r in validation])[:, 1]
            thresholds = select_thresholds([r["label"] for r in validation], val_p)
            evaluation = evaluate_records(validation, val_p, thresholds["suspicious"])
            source_tests = source_evaluation(name, train_all, manifest["recipe"]["transfer_pairs"])
            timings = []
            for record in validation[:100]:
                start = time.perf_counter()
                model.predict_proba([record["text"]])
                timings.append((time.perf_counter() - start) * 1000)
            latency = float(np.percentile(timings, 95))
            gates = gate_results(evaluation, source_tests, thresholds, latency, manifest["recipe"]["evidence"])
            sm = source_tests["summary"]
            worst = sm["worst_source_error"] if sm["worst_source_error"] is not None else 1.
            recall = sm["macro"].get("recall", {}).get("value") or 0.
            brier = sm["macro"].get("brier_score", {}).get("value")
            score = .50 * (1 - worst) + .25 * recall + .15 * evaluation["pooled"]["f1"] + .10 * (1 - (brier if brier is not None else 1))
            artifact = run / (name + ".joblib")
            joblib.dump(model, artifact, compress=3)
            candidates[name] = {"validation": evaluation, "validation_fixed_0_5": evaluate_records(validation, val_p, .5),
                "thresholds": thresholds, "source_evaluation": source_tests, "development_gates": gates,
                "fit_seconds": fit_seconds, "inference_ms_median": float(np.median(timings)), "inference_ms_p95": latency,
                "selection_score": score, "artifact_sha256": digest(artifact.read_bytes()),
                "artifact_bytes": artifact.stat().st_size, "validation_status": "RESEARCH"}
            print(name, "validation F1", round(evaluation["pooled"]["f1"], 4),
                  "worst source error", round(worst, 4), "failed gates:", len(gates["failed"]), flush=True)
        diagnostic = source_predictability(train, validation)
    selected = max(CANDIDATES, key=lambda n: (candidates[n]["development_gates"]["passed_all"],
        candidates[n]["selection_score"], -SIMPLICITY[n], -candidates[n]["inference_ms_median"]))
    lock = {"model_version": "candidate_v2", "selected_model": selected, "test_opened": False,
            "selection_locked_at": datetime.now(timezone.utc).isoformat(), "seed": SEED,
            "normalization_version": VERSION, "feature_settings": FEATURES, "policy": POLICY,
            "versions": {"python": platform.python_version(), "scikit_learn": sklearn.__version__,
                         "numpy": np.__version__, "joblib": joblib.__version__},
            "code_sha256": code_hashes(), "dataset_manifest_sha256": digest((dataset / "manifest.json").read_bytes()),
            "dataset_id": manifest["dataset_id"], "training_after_cap": summaries(train),
            "candidates": candidates, "source_predictability": diagnostic,
            "evidence": manifest["recipe"]["evidence"], "active_model": "legacy_demo_16",
            "final_test_scope": "Only fresh new-source representatives, with exposed v1 evaluation families excluded. Synthetic support does not establish real deployment readiness."}
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(lock_path, lock)
    # Digest beside ignored fitted artifacts binds the actual lock, not just code.
    (run / "selection.sha256").write_text(digest(lock_path.read_bytes()), encoding="ascii")
    print("Locked v2 research choice:", selected, flush=True)
    return lock


def finalize(dataset, run, lock_path, destination, report_path):
    dataset, run, lock_path, destination, report_path = map(Path, (dataset, run, lock_path, destination, report_path))
    if destination.exists() or report_path.exists():
        raise FileExistsError("Final results/model metadata cannot be overwritten")
    if digest(lock_path.read_bytes()) != (run / "selection.sha256").read_text():
        raise ValueError("Selection lock was changed")
    lock = json.loads(lock_path.read_text())
    if lock["test_opened"] or lock["code_sha256"] != code_hashes() or lock["policy"] != POLICY:
        raise ValueError("Frozen code/policy no longer matches the locked experiment")
    if digest((dataset / "manifest.json").read_bytes()) != lock["dataset_manifest_sha256"]:
        raise ValueError("Dataset manifest changed after selection")
    for name in CANDIDATES:
        if digest((run / (name + ".joblib")).read_bytes()) != lock["candidates"][name]["artifact_sha256"]:
            raise ValueError("Frozen candidate artifact changed")
    marker = Path(str(lock_path) + ".test-opened")
    with marker.open("x", encoding="utf-8") as handle:
        handle.write(datetime.now(timezone.utc).isoformat())
    manifest = json.loads((dataset / "manifest.json").read_text())
    # Check integrity of all partitions and family separation before inference.
    splits = {p: checked_rows(dataset, p, manifest) for p in ("train", "validation", "test")}
    assert_disjoint(splits)
    test = splits["test"]
    if any(r["previously_seen"] or r["protected"] for r in test):
        raise ValueError("Exposed corpus records cannot be final v2 test evidence")
    result = {"model_version": "candidate_v2", "selected_model": lock["selected_model"],
              "selection_lock_sha256": digest(lock_path.read_bytes()), "dataset_id": lock["dataset_id"],
              "test_evaluated_at": datetime.now(timezone.utc).isoformat(), "split_counts": manifest["splits"],
              "active_model": "legacy_demo_16", "candidates": {}, "activated": False}
    destination.mkdir(parents=True)
    with threadpool_limits(limits=1):
        for name in CANDIDATES:
            chosen = lock["candidates"][name]
            model = joblib.load(run / (name + ".joblib"))
            probabilities = model.predict_proba([r["text"] for r in test])[:, 1]
            bands = {k: chosen["thresholds"][k] for k in ("suspicious", "high")}
            evaluation = evaluate_records(test, probabilities, bands["suspicious"])
            test_gates = gate_results(evaluation, chosen["source_evaluation"], chosen["thresholds"],
                                      chosen["inference_ms_p95"], lock["evidence"])
            # No candidate switching using test results, and no activation side effect.
            validated = name == lock["selected_model"] and chosen["development_gates"]["passed_all"] and test_gates["passed_all"]
            status = "VALIDATED" if validated else "UNVALIDATED"
            blockers = sorted(set(chosen["development_gates"]["failed"] +
                                  ["final_confirmation:" + x for x in test_gates["failed"]]))
            if name != lock["selected_model"]:
                blockers.append("not_selected_before_final_test")
            result["candidates"][name] = {"test": evaluation,
                "test_fixed_0_5": evaluate_records(test, probabilities, .5),
                "test_high_band": evaluate_records(test, probabilities, bands["high"]),
                "development_gates": chosen["development_gates"], "final_confirmation_gates": test_gates,
                "validation_status": status, "activation_eligible": validated, "blockers": blockers}
            directory = destination / name
            directory.mkdir()
            artifact = directory / "model.joblib"
            artifact.write_bytes((run / (name + ".joblib")).read_bytes())
            metadata = {"model_version": "candidate_v2/" + name, "model_type": name,
                "validation_status": status, "status": status, "validated": validated,
                "activation_eligible": validated, "active": False, "normalization_version": VERSION,
                "code_sha256": lock["code_sha256"], "artifact_sha256": digest(artifact.read_bytes()),
                "versions": lock["versions"], "random_seed": lock["seed"], "trained_at": lock["selection_locked_at"],
                "thresholds": bands, "training_sources": sorted(manifest["training_after_cap"]["source_counts"]),
                "dataset_id": lock["dataset_id"], "dataset_manifest_sha256": lock["dataset_manifest_sha256"],
                "feature_settings": lock["feature_settings"], "development_gates": chosen["development_gates"],
                "final_confirmation_gates": test_gates, "blockers": blockers,
                "legacy_artifacts_overwritten": False}
            write_json(directory / "metadata.json", metadata)
            print(name, status, "test F1", round(evaluation["pooled"]["f1"], 4), flush=True)
    result["any_candidate_eligible"] = any(r["activation_eligible"] for r in result["candidates"].values())
    write_json(report_path, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("select", "finalize"))
    parser.add_argument("--dataset", type=Path, default=ROOT / "data/processed/public_email_v2")
    parser.add_argument("--run", type=Path, default=ROOT / "runs/candidate_v2")
    parser.add_argument("--lock", type=Path, default=ROOT / "reports/candidate_v2_selection.json")
    parser.add_argument("--destination", type=Path, default=ROOT / "models/candidate_v2")
    parser.add_argument("--report", type=Path, default=ROOT / "reports/candidate_v2_final.json")
    args = parser.parse_args()
    if args.phase == "select":
        select(args.dataset, args.run, args.lock)
    else:
        finalize(args.dataset, args.run, args.lock, args.destination, args.report)


if __name__ == "__main__":
    main()
