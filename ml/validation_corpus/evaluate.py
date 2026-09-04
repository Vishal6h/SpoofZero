"""Select on development evidence, freeze, then evaluate temporal/external holdouts."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import shutil
import time
import joblib
import numpy as np
import sklearn
from threadpoolctl import threadpool_limits
from ml.data_pipeline import ROOT, SEED, digest, write_json
from ml.experiment import CANDIDATES, FEATURES, checked_rows, model_factory, select_thresholds
from ml.generalization.evaluate import (POLICY as V2_POLICY, SIMPLICITY, metric_set,
    evaluate_records, source_evaluation, source_predictability, gate_results,
    code_hashes as v2_code_hashes)
from ml.generalization.data import assert_disjoint, balance_training
from .data import (DATASET, summary, assert_external_isolation, assert_temporal_integrity)
from .text import VERSION

VERSION_ID = "candidate_real_world_v1"
RUN = ROOT / "runs" / VERSION_ID
LOCK = ROOT / "reports" / (VERSION_ID + "_selection.json")
FINAL = ROOT / "reports" / (VERSION_ID + "_final.json")
DESTINATION = ROOT / "models" / VERSION_ID
EXTRA_POLICY = {
    "minimum_modern_real_email_phishing": 100,
    "modern_date_floor": "2024-01-01",
    "maximum_synthetic_malicious_fraction": .50,
    "maximum_unknown_malicious_fraction": .10,
    "minimum_external_real_email_per_class": 100,
    "minimum_temporal_validation_per_class": 20,
    "external_min_precision": .90, "external_min_recall": .95,
    "external_max_fpr": .05, "external_min_f1": .90,
    "external_max_brier": .10, "external_max_ece": .05,
    "external_max_source_error": .10,
    "temporal_min_precision": .90, "temporal_min_recall": .95,
    "temporal_max_fpr": .05, "temporal_min_f1": .90,
    "temporal_max_brier": .10, "temporal_max_ece": .05,
    "temporal_max_source_error": .10,
    "rationale": "Inherited v2 gates remain mandatory. External and chronological tests must also meet the mixed-validation ceilings. At least 100 modern real phishing email representatives and 100 real emails of each class externally are evidence floors, not statistical proof. Unknown provenance cannot mask synthetic dominance. Even a passing candidate remains inactive.",
}
LEGACY_HASHES = {
    "vectorizer.joblib": "8eb8faebe8fb0a94989a36e37702b3bc88c1d0400860259750e8245a0d6ce30f",
    "phishing_model.joblib": "efc92ce20d0a736847148bdeef16aeee902ef91213e7392b29fffa1a96f9fabf",
}

def verify_legacy():
    if any(digest((ROOT / name).read_bytes()) != expected for name, expected in LEGACY_HASHES.items()):
        raise ValueError("Protected legacy model changed")
    return dict(LEGACY_HASHES)

def code_hashes():
    result = v2_code_hashes()
    for name in ("__init__.py", "text.py", "data.py", "evaluate.py", "fetch.py"):
        result["validation_corpus/" + name] = digest((ROOT / "validation_corpus" / name).read_bytes())
    return result

def cohorts(records, probabilities, threshold):
    probabilities = np.asarray(probabilities)
    if len(records) != len(probabilities):
        raise ValueError("Prediction/record length mismatch")
    if not records:
        return {"overall": None, "by_reality": {}, "by_reality_class": {}, "by_year": {}}
    result = {"overall": evaluate_records(records, probabilities, threshold),
              "by_reality": {}, "by_reality_class": {}, "by_year": {}}
    for tag in ("REAL", "SYNTHETIC", "UNKNOWN"):
        ix = [i for i, r in enumerate(records) if r["reality"] == tag]
        result["by_reality"][tag] = evaluate_records([records[i] for i in ix], probabilities[ix], threshold) if ix else None
        for label in (0, 1):
            selected = [i for i in ix if records[i]["label"] == label]
            result["by_reality_class"][tag + ("_legitimate" if label == 0 else "_malicious")] = (
                metric_set([records[i]["label"] for i in selected], probabilities[selected], threshold) if selected else None)
    years = sorted({r["date_start"][:4] for r in records if r["date_start"] and r["date_start"] == r["date_end"]})
    for year in years:
        ix = [i for i, r in enumerate(records) if r["date_start"] and r["date_start"] == r["date_end"] and r["date_start"].startswith(year)]
        result["by_year"][year] = metric_set([records[i]["label"] for i in ix], probabilities[ix], threshold)
    return result

def evidence_counts(records, external):
    positives = [r for r in records if r["label"] == 1]
    modern = [r for r in positives if r["reality"] == "REAL" and r["channel"] == "email"
              and r["date_quality"] == "DOCUMENTED_MESSAGE_DATE"
              and r["date_start"] and r["date_start"] >= EXTRA_POLICY["modern_date_floor"]]
    return {"malicious_count": len(positives),
        "modern_real_email_phishing": len(modern),
        "synthetic_malicious_fraction": sum(r["reality"] == "SYNTHETIC" for r in positives) / len(positives) if positives else None,
        "unknown_malicious_fraction": sum(r["reality"] == "UNKNOWN" for r in positives) / len(positives) if positives else None,
        "external_real_email_counts": {str(label): sum(r["reality"] == "REAL" and r["channel"] == "email" and r["label"] == label for r in external) for label in (0, 1)}}

def extra_gates(temporal, external, evidence, temporal_validation_counts):
    gates = {}
    def check(name, actual, op, limit):
        passed = isinstance(actual, (float, int)) and np.isfinite(actual) and (actual >= limit if op == ">=" else actual <= limit)
        gates[name] = {"passed": bool(passed), "actual": actual, "operator": op, "limit": limit}
    for phase, evaluation in (("temporal", temporal), ("external", external)):
        for key, suffix, op in (
            ("precision", "min_precision", ">="), ("recall", "min_recall", ">="),
            ("false_positive_rate", "max_fpr", "<="), ("f1", "min_f1", ">="),
            ("brier_score", "max_brier", "<="), ("ece_10_equal_width", "max_ece", "<=")):
            actual = evaluation["pooled"][key] if evaluation else None
            check(phase + "_" + key, actual, op, EXTRA_POLICY[phase + "_" + suffix])
        check(phase + "_worst_source_error", evaluation["source_summary"]["worst_source_error"] if evaluation else None,
              "<=", EXTRA_POLICY[phase + "_max_source_error"])
    check("modern_real_email_support", evidence.get("modern_real_email_phishing"), ">=", EXTRA_POLICY["minimum_modern_real_email_phishing"])
    check("synthetic_dominance", evidence.get("synthetic_malicious_fraction"), "<=", EXTRA_POLICY["maximum_synthetic_malicious_fraction"])
    check("unknown_malicious_provenance", evidence.get("unknown_malicious_fraction"), "<=", EXTRA_POLICY["maximum_unknown_malicious_fraction"])
    for label in ("0", "1"):
        check("external_real_email_support_" + label, evidence.get("external_real_email_counts", {}).get(label), ">=", EXTRA_POLICY["minimum_external_real_email_per_class"])
        check("temporal_validation_support_" + label, temporal_validation_counts.get(label), ">=", EXTRA_POLICY["minimum_temporal_validation_per_class"])
    return {"gates": gates, "passed_all": all(g["passed"] for g in gates.values()),
            "failed": [k for k, g in gates.items() if not g["passed"]]}

def candidate_status(selected, inherited, additional):
    eligible = selected and inherited["passed_all"] and additional["passed_all"]
    return {"status": "VALIDATED" if eligible else "UNVALIDATED",
            "validated": bool(eligible), "active": False,
            "activation_recommended": False,
            "activation_note": "VALIDATED — eligible for activation review" if eligible else "Insufficient deployment evidence; retain legacy fallback."}

def select(dataset=DATASET, run=RUN, lock_path=LOCK):
    dataset, run, lock_path = map(Path, (dataset, run, lock_path))
    if run.exists() or lock_path.exists():
        raise FileExistsError("Selection is immutable; use a new research version")
    legacy = verify_legacy()
    manifest_path = dataset / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    # Deliberately no reads of external, final test, unknown dates or synthetic stress.
    train_all = checked_rows(dataset, "train", manifest)
    temporal_val = checked_rows(dataset, "validation", manifest)
    historical_val = checked_rows(dataset, "validation_historical", manifest)
    mixed_val = temporal_val + historical_val
    assert_disjoint({"train": train_all, "temporal_val": temporal_val, "historical_val": historical_val})
    assert_temporal_integrity(train_all, temporal_val, [])
    assert_external_isolation(train_all, mixed_val, [])
    if any(r["reality"] != "REAL" or r["channel"] != "email" for r in train_all):
        raise ValueError("Only real older email may fit this version")
    if {r["label"] for r in temporal_val} != {0, 1}:
        raise ValueError("Later validation must contain both labels")
    train = balance_training(train_all, V2_POLICY["training_cap_per_source_class"], SEED)
    run.mkdir(parents=True)
    candidates = {}
    with threadpool_limits(limits=1):
        for name in CANDIDATES:
            print("Fitting real-world candidate:", name, flush=True)
            model = model_factory(name, SEED)
            start = time.perf_counter()
            model.fit([r["text"] for r in train], [r["label"] for r in train])
            seconds = time.perf_counter() - start
            temporal_p = model.predict_proba([r["text"] for r in temporal_val])[:, 1]
            bands = select_thresholds([r["label"] for r in temporal_val], temporal_p)
            p = model.predict_proba([r["text"] for r in mixed_val])[:, 1]
            evaluation = evaluate_records(mixed_val, p, bands["suspicious"])
            source_tests = source_evaluation(name, train_all, manifest["recipe"]["transfer_pairs"])
            timings = []
            for row in mixed_val[:100]:
                start = time.perf_counter()
                model.predict_proba([row["text"]])
                timings.append((time.perf_counter() - start) * 1000)
            p95 = float(np.percentile(timings, 95))
            gates = gate_results(evaluation, source_tests, bands, p95, manifest["recipe"]["evidence"])
            sm = source_tests["summary"]
            worst = sm["worst_source_error"] if sm["worst_source_error"] is not None else 1.
            recall = sm["macro"].get("recall", {}).get("value") or 0.
            brier = sm["macro"].get("brier_score", {}).get("value")
            score = .50 * (1 - worst) + .25 * recall + .15 * evaluation["pooled"]["f1"] + .10 * (1 - (brier if brier is not None else 1))
            artifact = run / (name + ".joblib")
            joblib.dump(model, artifact, compress=3)
            candidates[name] = {"thresholds": bands, "threshold_origin": "SpaPhish 2023 only",
                "validation": evaluation, "temporal_validation": cohorts(temporal_val, temporal_p, bands["suspicious"]),
                "source_evaluation": source_tests, "development_gates": gates, "selection_score": score,
                "fit_seconds": seconds, "inference_ms_median": float(np.median(timings)), "inference_ms_p95": p95,
                "artifact_sha256": digest(artifact.read_bytes()), "artifact_bytes": artifact.stat().st_size,
                "status": "RESEARCH", "active": False}
            print(name, "mixed validation F1", round(evaluation["pooled"]["f1"], 4),
                  "worst-source error", round(worst, 4), "threshold", bands["suspicious"], flush=True)
        diagnostic = source_predictability(train, mixed_val)
    selected = max(CANDIDATES, key=lambda n: (candidates[n]["development_gates"]["passed_all"],
        candidates[n]["selection_score"], -SIMPLICITY[n], -candidates[n]["inference_ms_median"]))
    lock = {"model_version": VERSION_ID, "selected_model": selected,
        "selection_locked_at": datetime.now(timezone.utc).isoformat(), "test_opened": False,
        "seed": SEED, "feature_settings": FEATURES, "normalization_version": VERSION,
        "inherited_policy": V2_POLICY, "extra_policy": EXTRA_POLICY,
        "versions": {"python": platform.python_version(), "scikit_learn": sklearn.__version__, "numpy": np.__version__, "joblib": joblib.__version__},
        "code_sha256": code_hashes(), "dataset_manifest_sha256": digest(manifest_path.read_bytes()),
        "training_after_cap": summary(train), "temporal_validation_counts": summary(temporal_val)["class_counts"],
        "candidates": candidates, "source_predictability": diagnostic,
        "legacy_hashes": legacy, "active_model": "legacy_demo_16",
        "evidence": manifest["recipe"]["evidence"],
        "external_scope": "Fresh SmishX SMS, never a source in development; not representative email evidence."}
    write_json(lock_path, lock)
    (run / "selection.sha256").write_text(digest(lock_path.read_bytes()), encoding="ascii")
    print("Selection locked:", selected, flush=True)
    return lock

def verify_lock(dataset, run, lock_path):
    verify_legacy()
    if digest(lock_path.read_bytes()) != (run / "selection.sha256").read_text():
        raise ValueError("Selection lock changed")
    lock = json.loads(lock_path.read_text())
    if lock["test_opened"] or lock["code_sha256"] != code_hashes():
        raise ValueError("Frozen experiment code changed")
    if lock["inherited_policy"] != V2_POLICY or lock["extra_policy"] != EXTRA_POLICY:
        raise ValueError("Deployment policy changed")
    if digest((dataset / "manifest.json").read_bytes()) != lock["dataset_manifest_sha256"]:
        raise ValueError("Dataset manifest changed")
    for name in CANDIDATES:
        if digest((run / (name + ".joblib")).read_bytes()) != lock["candidates"][name]["artifact_sha256"]:
            raise ValueError("Candidate binary changed")
    return lock

def finalize(dataset=DATASET, run=RUN, lock_path=LOCK, destination=DESTINATION, report_path=FINAL):
    dataset, run, lock_path, destination, report_path = map(Path, (dataset, run, lock_path, destination, report_path))
    if destination.exists() or report_path.exists():
        raise FileExistsError("Final evaluation cannot overwrite an experiment")
    lock = verify_lock(dataset, run, lock_path)
    marker = Path(str(lock_path) + ".test-opened")
    # Consume before opening evaluation records: a failed partial reveal is not reset.
    with marker.open("x", encoding="utf-8") as f:
        f.write(datetime.now(timezone.utc).isoformat() + "\n")
    manifest = json.loads((dataset / "manifest.json").read_text())
    partitions = {name: checked_rows(dataset, name, manifest) for name in
        ("train", "validation", "validation_historical", "test", "external", "date_unknown", "synthetic_stress")}
    assert_disjoint(partitions)
    assert_external_isolation(partitions["train"], partitions["validation"] + partitions["validation_historical"], partitions["external"])
    assert_temporal_integrity(partitions["train"], partitions["validation"], partitions["test"])
    evidence = evidence_counts(partitions["test"] + partitions["external"], partitions["external"])
    result = {"model_version": VERSION_ID, "selected_model": lock["selected_model"],
        "selection_sha256": digest(lock_path.read_bytes()), "test_opened_at": marker.read_text().strip(),
        "dataset_manifest_sha256": lock["dataset_manifest_sha256"], "candidates": {},
        "deployment_evidence": evidence, "active_model": "legacy_demo_16", "legacy_hashes": verify_legacy(),
        "external_holdout": summary(partitions["external"]), "temporal_test": summary(partitions["test"]),
        "synthetic_scope": "Previously exposed v2 synthetic representatives; diagnostic only. Never used for model fitting, threshold tuning, candidate ranking or deployment evidence."}
    with threadpool_limits(limits=1):
        for name in CANDIDATES:
            model = joblib.load(run / (name + ".joblib"))
            development = lock["candidates"][name]
            threshold = development["thresholds"]["suspicious"]
            evaluations = {}
            for part in ("test", "external", "date_unknown", "synthetic_stress"):
                rows = partitions[part]
                p = model.predict_proba([r["text"] for r in rows])[:, 1] if rows else []
                evaluations[part] = cohorts(rows, p, threshold)
                if rows:
                    evaluations[part]["fixed_0_5"] = evaluate_records(rows, p, .5)
                    evaluations[part]["high_band"] = evaluate_records(rows, p, development["thresholds"]["high"])
            extra = extra_gates(evaluations["test"]["overall"], evaluations["external"]["overall"],
                                evidence, lock["temporal_validation_counts"])
            status = candidate_status(name == lock["selected_model"], development["development_gates"], extra)
            result["candidates"][name] = dict(evaluations=evaluations, inherited_gates=development["development_gates"],
                additional_gates=extra, thresholds=development["thresholds"], **status)
            folder = destination / name
            folder.mkdir(parents=True)
            shutil.copyfile(run / (name + ".joblib"), folder / "model.joblib")
            metadata = {**status, "model_version": VERSION_ID, "model_type": name, "seed": SEED,
                "training_date": lock["selection_locked_at"], "versions": lock["versions"],
                "normalization_version": VERSION, "feature_settings": FEATURES,
                "thresholds": development["thresholds"], "artifact_sha256": development["artifact_sha256"],
                "manifest_sha256": lock["dataset_manifest_sha256"], "selection_sha256": digest(lock_path.read_bytes()),
                "code_sha256": lock["code_sha256"], "inherited_policy": V2_POLICY, "extra_policy": EXTRA_POLICY,
                "inherited_gates": development["development_gates"], "additional_gates": extra,
                "evaluation_report": "ml/reports/" + report_path.name,
                "validation": development["validation"]["pooled"],
                "temporal_test": evaluations["test"]["overall"]["pooled"] if evaluations["test"]["overall"] else None,
                "external": evaluations["external"]["overall"]["pooled"] if evaluations["external"]["overall"] else None}
            write_json(folder / "metadata.json", metadata)
            print(name, status["status"], "extra gates failed", len(extra["failed"]), flush=True)
    write_json(report_path, result)
    return result

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("phase", choices=("select", "finalize"))
    p.add_argument("--dataset", type=Path, default=DATASET)
    p.add_argument("--run", type=Path, default=RUN)
    p.add_argument("--lock", type=Path, default=LOCK)
    p.add_argument("--destination", type=Path, default=DESTINATION)
    p.add_argument("--report", type=Path, default=FINAL)
    a = p.parse_args()
    if a.phase == "select":
        select(a.dataset, a.run, a.lock)
    else:
        finalize(a.dataset, a.run, a.lock, a.destination, a.report)
