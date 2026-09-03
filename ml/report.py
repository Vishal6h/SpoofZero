"""Render aggregate metrics from the frozen run; never refit or read test text."""
import argparse
import json
from pathlib import Path

from .data_pipeline import ROOT

NAMES = {"logistic": "Logistic Regression", "logistic_sigmoid": "Logistic Regression + sigmoid",
         "linear_svm_sigmoid": "Linear SVM + sigmoid", "multinomial_nb": "Multinomial Naive Bayes"}


def render(test_count):
    manifest = json.loads((ROOT / "data/manifest.json").read_text())
    lock = json.loads((ROOT / "reports/candidate_v1_selection.json").read_text())
    final = json.loads((ROOT / "reports/candidate_v1_final.json").read_text())
    chosen = final["selected_model"]
    lines = ["# AI Model Readiness evaluation", "",
        "**Decision: retain the active 16-example fallback.** The selected research candidate is " + NAMES[chosen] + ". It outperforms the legacy demo on this corpus but fails the source-generalization gate; its artifact is marked `validated: false`.", "",
        "Protected reference: `666c31dc9deedc09a3301daaff0b791f33e1ddcd`. Nothing was committed or pushed by this milestone.", "",
        "## Sources and construction", "",
        "Source: [Phishing Email Curated Datasets, Zenodo 8339691](https://zenodo.org/records/8339691), publisher-declared CC BY 4.0. Full citations, usage notes, download checksums and construction details are in `ml/data/sources.json` and `ml/data/manifest.json`. Only public CSV text was used; raw/processed text and model binaries remain outside Git.", "",
        "| Source | Raw rows | Eligible label | Usable before dedup | Final representatives |",
        "|---|---:|---|---:|---:|"]
    for source in manifest["sources"]:
        counts = source["counts"]
        lines.append(f'| {source["name"]} | {counts["raw"]:,} | {"0 legitimate" if source["label"] == 0 else "1 phishing/fraud"} | {counts["usable_before_deduplication"]:,} | {manifest["usable_by_source"][source["name"]]:,} |')
    d = manifest["deduplication"]
    lines += ["", "Excluded 2,176 generic spam rows rather than labeling them phishing, and one empty row. Removed **1,004 duplicates**: 55 exact, 255 masked-template/body, and 694 near duplicates. Quarantined 12 conflicting-label rows. Retained 10,372 representatives. Counts by source identify the representative; merged provenance is retained locally.", "",
        "| Split | Total | Legitimate (0) | Phishing/fraud (1) |", "|---|---:|---:|---:|"]
    for split in ("train", "validation", "test"):
        values = manifest["splits"][split]
        lines.append(f'| {split} | {values["count"]:,} | {values["class_counts"]["0"]:,} | {values["class_counts"]["1"]:,} |')
    zero = sum(s["class_counts"]["0"] for s in manifest["splits"].values())
    one = sum(s["class_counts"]["1"] for s in manifest["splits"].values())
    lines += ["", f"Overall class balance: {zero:,} legitimate ({zero/(zero+one):.2%}) and {one:,} phishing/fraud ({one/(zero+one):.2%}). Seed: {lock['seed']}. Content/template components were collapsed before source+label stratification. Near matching uses a hashing cosine prefilter and exact trigram Jaccard >=0.85, not a guarantee against paraphrases.", "",
        "## Protocol and model choice", "",
        "Four fixed candidates used 50,000 capped word unigram/bigram TF-IDF features, min_df=2, max_df=0.98 and sublinear TF. Logistic Regression and Linear SVM used C=1 and balanced class weights; NB used alpha=1. Sigmoid calibration used training-only three-fold out-of-fold predictions, with TF-IDF fitted inside every fold. No neural models or GPUs were used.", "",
        "Selection maximized a predeclared validation composite of F1, recall, specificity, Brier and source-transfer error, with simplicity/latency tie-breaks. Thresholds were chosen on validation only. Artifact/configuration/code hashes and thresholds were locked before opening the final test. All four test results below are transparency reporting; they did not change the chosen model or thresholds.", "",
        "| Candidate | Validation precision | Recall | F1 | Brier | Worst source error | Median / p95 inference ms |",
        "|---|---:|---:|---:|---:|---:|---:|"]
    for name, candidate in lock["candidates"].items():
        m = candidate["validation"]
        lines.append(f'| {NAMES[name]} | {m["precision"]:.4f} | {m["recall"]:.4f} | {m["f1"]:.4f} | {m["brier_score"]:.6f} | {candidate["worst_source_error"]:.2%} | {candidate["single_inference_ms_median"]:.3f} / {candidate["single_inference_ms_p95"]:.3f} |')
    lines += ["", "Linear SVM + sigmoid has the strongest predeclared composite and the lowest worst source error among these candidates. It remains fast, small and probability-capable. This selects it for research; it does not prove readiness for inbox deployment.", "",
        "## Final untouched test: all candidates at fixed 0.50", "",
        "These are within-collection, deduplicated holdout metrics on 1,556 emails, not operational accuracy. Positive class is phishing/fraud. Confusion matrices are `[[TN, FP], [FN, TP]]`.", "",
        "| Candidate | Accuracy | Precision | Recall | F1 | FP | FN | Confusion matrix |",
        "|---|---:|---:|---:|---:|---:|---:|---|"]
    for name, m in final["candidates_test_at_0_5"].items():
        lines.append(f'| {NAMES[name]} | {m["accuracy"]:.4f} | {m["precision"]:.4f} | {m["recall"]:.4f} | {m["f1"]:.4f} | {m["false_positives"]} | {m["false_negatives"]} | `{m["confusion_matrix"]}` |')
    lines += ["", "| Candidate | ROC-AUC | PR-AUC (average precision) | Brier | Log loss | ECE (10 bins) |",
              "|---|---:|---:|---:|---:|---:|"]
    for name, m in final["candidates_test_at_0_5"].items():
        lines.append(f'| {NAMES[name]} | {m["roc_auc"]:.6f} | {m["pr_auc_average_precision"]:.6f} | {m["brier_score"]:.6f} | {m["log_loss"]:.6f} | {m["ece_10_equal_width"]:.6f} |')
    legacy = final["legacy_test_at_0_5"]
    lines += ["", f'Legacy demo comparison on the same readable examples at 0.50: accuracy {legacy["accuracy"]:.4f}, precision {legacy["precision"]:.4f}, recall {legacy["recall"]:.4f}, F1 {legacy["f1"]:.4f}, FP {legacy["false_positives"]}, FN {legacy["false_negatives"]}, Brier {legacy["brier_score"]:.6f}. Keeping it active is continuity, not an assertion that it is a validated detector.', "",
        "## Locked bands and final selected-model confusion matrix", "",
        "Candidate bands: **low <70%; suspicious 70% to <80%; high >=80%**. The active fallback retains 50%/70%. Review aimed for >=95% recall and <=5% FPR on validation, with a 0.70 cap. High aimed for >=98% precision and <=1% FPR, at least 20 predictions and at least 0.10 above review. Both targets were met on validation. A zero observed FP count is not a guaranteed zero false-positive rate.", "",
        "| Partition / threshold | Precision | Recall | FP | FN |", "|---|---:|---:|---:|---:|"]
    rows = [("Validation / 0.70", lock["thresholds"]["validation_review_metrics"]),
            ("Validation / 0.80", lock["thresholds"]["validation_high_metrics"]),
            ("Final test / 0.70", final["selected_locked_review_threshold"]),
            ("Final test / 0.80", final["selected_locked_high_threshold"])]
    for name, m in rows:
        lines.append(f'| {name} | {m["precision"]:.4f} | {m["recall"]:.4f} | {m["false_positives"]} | {m["false_negatives"]} |')
    m = final["selected_locked_review_threshold"]
    matrix = m["confusion_matrix"]
    lines += ["", "At the selected 0.70 review threshold:", "", "| Actual / predicted | Legitimate | Phishing |", "|---|---:|---:|",
        f'| Legitimate | {matrix[0][0]} | {matrix[0][1]} |', f'| Phishing/fraud | {matrix[1][0]} | {matrix[1][1]} |', "",
        f'Accuracy {m["accuracy"]:.4f}, precision {m["precision"]:.4f}, recall {m["recall"]:.4f}, F1 {m["f1"]:.4f}; **{m["false_positives"]} FP and {m["false_negatives"]} FN**. Raising to 0.80 removes the one FP but increases FN from four to six. This test observation was not used to retune either threshold.', "",
        "## Calibration evidence", "", "Brier, log loss and ECE are reported for every candidate above; full validation/test reliability bins are in the JSON reports. Selected candidate final-test bins:", "",
        "| Probability bin | Count | Mean predicted probability | Observed phishing fraction |", "|---|---:|---:|---:|"]
    for b in m["calibration_bins"]:
        lines.append(f'| {b["lower"]:.1f}-{b["upper"]:.1f} | {b["count"]} | {b["mean_probability"]:.4f} | {b["observed_phishing_rate"]:.4f} |')
    lines += ["", "Middle bins have very few observations. Brier combines calibration and discrimination; a small Brier score does not establish stable calibration under domain/prevalence shift. The dataset contains about 39% phishing/fraud, unlike many real inboxes.", "",
        "## Why activation is blocked", "",
        "The source-transfer stress test fits on one benign/phishing source pair and checks the other using training-partition data only, then reverses roles. It excludes cross-boundary merged provenance. Both pairs contain both classes; results below use the predeclared 0.50 threshold.", "",
        "| Held-out source pair | Precision | Recall | F1 | FPR | Confusion matrix |", "|---|---:|---:|---:|---:|---|"]
    for fold in lock["candidates"][chosen]["training_source_holdouts"]:
        m = fold["metrics"]
        lines.append(f'| {", ".join(fold["held_out_sources"])} | {m["precision"]:.4f} | {m["recall"]:.4f} | {m["f1"]:.4f} | {m["false_positive_rate"]:.4f} | `{m["confusion_matrix"]}` |')
    lines += ["", "Worst transfer error is 35.32%, above the 20% gate. Recall falls to 64.68%, and the corresponding FPR is 22.39%. These results outweigh the excellent mixed-corpus holdout numbers.", "",
        "Additional limitations: each admitted source supplies one class; collection/topic artifacts may survive masking; historical English-heavy mail is not representative of modern BEC, OAuth lures or multilingual mail; fraud labels are broader than credential phishing; corpus labels were not independently reannotated; near-deduplication does not identify every paraphrase. The absence of subject fields and the 40,000-character cap can lose context. No privacy-sensitive inbox data was collected to fill these gaps.", "",
        "Next evidence needed for promotion: an independently labeled modern dataset with legitimate and phishing examples from comparable collection pipelines, plus a fresh source/time-separated final holdout. Do not optimize against this already revealed test set.", "",
        "## Artifacts and verification", "",
        "- `ml/models/legacy_demo/metadata.json`: protected original hashes; original `ml/*.joblib` remain active and byte-for-byte unchanged.",
        "- `ml/models/candidate_v1/model.joblib`: locally trained research candidate, ignored by Git.",
        "- `ml/models/candidate_v1/metadata.json`: type, date, dependency versions, source/feature hashes, thresholds, evaluation and promotion blockers.",
        "- `ml/reports/candidate_v1_selection.json`: validation metrics for every candidate, source tests, latency and threshold tradeoff grid, locked before test.",
        "- `ml/reports/candidate_v1_final.json`: final candidate metrics, calibration bins, source breakdowns and hashed error IDs.",
        f"- Complete offline test suite: **{test_count} tests passed**. Tests need no downloads or public-corpus files; synthetic fixtures exercise pipeline correctness.",
        "- No UI redesign or changes to fusion weights, authentication, VirusTotal, attachments, geolocation or correlation. The runtime input guard is compatible with existing valid-text scores.", "",
        "See `docs/ai-model-readiness.md` for commands and the full methodology. No candidate is automatically activated.", ""]
    lines += ["## Files changed", "",
        "- `.gitignore`, `requirements.txt`: exclude local datasets/runs/model binaries and pin already-installed NumPy/threadpoolctl as direct dependencies.",
        "- `ml/__init__.py`, `ml/fetch_data.py`, `ml/text.py`, `ml/data_pipeline.py`: public-data acquisition and normalization/deduplication/splitting.",
        "- `ml/train_model.py`, `ml/experiment.py`, `ml/inference.py`, `ml/report.py`: protected legacy training, candidate comparison, gated loading and report rendering.",
        "- `backend/analyzers/nlp_detector.py`: malformed-input guard; the active model and valid-input output remain unchanged.",
        "- `ml/data/sources.json`, `ml/data/manifest.json`: source/license recipe and measured construction/split metadata.",
        "- `ml/models/legacy_demo/metadata.json`, `ml/models/candidate_v1/metadata.json`: versioned provenance, artifact hashes and readiness status.",
        "- `ml/reports/candidate_v1_selection.json`, `ml/reports/candidate_v1_selection.json.test-opened`, `ml/reports/candidate_v1_final.json`, `ml/reports/AI_MODEL_READINESS.md`: frozen selection, final evaluation and this report.",
        "- `tests/test_model_readiness.py`: 44 new offline regressions.",
        "- `README.md`, `docs/architecture.md`, `docs/ai-model-readiness.md`: operating instructions, architecture and interpretation.", ""]
    path = ROOT / "reports/AI_MODEL_READINESS.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    print("Wrote:", path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-count", type=int, required=True)
    render(parser.parse_args().test_count)
