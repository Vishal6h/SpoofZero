# AI Model Readiness evaluation

**Decision: retain the active 16-example fallback.** The selected research candidate is Linear SVM + sigmoid. It outperforms the legacy demo on this corpus but fails the source-generalization gate; its artifact is marked `validated: false`.

Protected reference: `666c31dc9deedc09a3301daaff0b791f33e1ddcd`. Nothing was committed or pushed by this milestone.

## Sources and construction

Source: [Phishing Email Curated Datasets, Zenodo 8339691](https://zenodo.org/records/8339691), publisher-declared CC BY 4.0. Full citations, usage notes, download checksums and construction details are in `ml/data/sources.json` and `ml/data/manifest.json`. Only public CSV text was used; raw/processed text and model binaries remain outside Git.

| Source | Raw rows | Eligible label | Usable before dedup | Final representatives |
|---|---:|---|---:|---:|
| ling | 2,859 | 0 legitimate | 2,401 | 2,312 |
| spamassassin | 5,809 | 0 legitimate | 4,091 | 3,975 |
| nazario | 1,565 | 1 phishing/fraud | 1,565 | 1,403 |
| nigerian_fraud | 3,332 | 1 phishing/fraud | 3,331 | 2,682 |

Excluded 2,176 generic spam rows rather than labeling them phishing, and one empty row. Removed **1,004 duplicates**: 55 exact, 255 masked-template/body, and 694 near duplicates. Quarantined 12 conflicting-label rows. Retained 10,372 representatives. Counts by source identify the representative; merged provenance is retained locally.

| Split | Total | Legitimate (0) | Phishing/fraud (1) |
|---|---:|---:|---:|
| train | 7,260 | 4,401 | 2,859 |
| validation | 1,556 | 943 | 613 |
| test | 1,556 | 943 | 613 |

Overall class balance: 6,287 legitimate (60.62%) and 4,085 phishing/fraud (39.38%). Seed: 20260904. Content/template components were collapsed before source+label stratification. Near matching uses a hashing cosine prefilter and exact trigram Jaccard >=0.85, not a guarantee against paraphrases.

## Protocol and model choice

Four fixed candidates used 50,000 capped word unigram/bigram TF-IDF features, min_df=2, max_df=0.98 and sublinear TF. Logistic Regression and Linear SVM used C=1 and balanced class weights; NB used alpha=1. Sigmoid calibration used training-only three-fold out-of-fold predictions, with TF-IDF fitted inside every fold. No neural models or GPUs were used.

Selection maximized a predeclared validation composite of F1, recall, specificity, Brier and source-transfer error, with simplicity/latency tie-breaks. Thresholds were chosen on validation only. Artifact/configuration/code hashes and thresholds were locked before opening the final test. All four test results below are transparency reporting; they did not change the chosen model or thresholds.

| Candidate | Validation precision | Recall | F1 | Brier | Worst source error | Median / p95 inference ms |
|---|---:|---:|---:|---:|---:|---:|
| Linear SVM + sigmoid | 0.9951 | 0.9902 | 0.9926 | 0.004047 | 35.32% | 1.143 / 2.158 |
| Logistic Regression | 0.9967 | 0.9837 | 0.9901 | 0.012444 | 76.98% | 0.657 / 1.420 |
| Logistic Regression + sigmoid | 0.9951 | 0.9886 | 0.9918 | 0.004981 | 57.91% | 1.460 / 3.342 |
| Multinomial Naive Bayes | 0.9983 | 0.9853 | 0.9918 | 0.006519 | 94.99% | 0.945 / 1.975 |

Linear SVM + sigmoid has the strongest predeclared composite and the lowest worst source error among these candidates. It remains fast, small and probability-capable. This selects it for research; it does not prove readiness for inbox deployment.

## Final untouched test: all candidates at fixed 0.50

These are within-collection, deduplicated holdout metrics on 1,556 emails, not operational accuracy. Positive class is phishing/fraud. Confusion matrices are `[[TN, FP], [FN, TP]]`.

| Candidate | Accuracy | Precision | Recall | F1 | FP | FN | Confusion matrix |
|---|---:|---:|---:|---:|---:|---:|---|
| Linear SVM + sigmoid | 0.9968 | 0.9967 | 0.9951 | 0.9959 | 2 | 3 | `[[941, 2], [3, 610]]` |
| Logistic Regression | 0.9904 | 0.9983 | 0.9772 | 0.9876 | 1 | 14 | `[[942, 1], [14, 599]]` |
| Logistic Regression + sigmoid | 0.9923 | 0.9886 | 0.9918 | 0.9902 | 7 | 5 | `[[936, 7], [5, 608]]` |
| Multinomial Naive Bayes | 0.9910 | 0.9983 | 0.9788 | 0.9885 | 1 | 13 | `[[942, 1], [13, 600]]` |

| Candidate | ROC-AUC | PR-AUC (average precision) | Brier | Log loss | ECE (10 bins) |
|---|---:|---:|---:|---:|---:|
| Linear SVM + sigmoid | 0.999945 | 0.999917 | 0.002425 | 0.009583 | 0.004163 |
| Logistic Regression | 0.999784 | 0.999675 | 0.013697 | 0.088032 | 0.069991 |
| Logistic Regression + sigmoid | 0.999784 | 0.999675 | 0.005489 | 0.018431 | 0.003862 |
| Multinomial Naive Bayes | 0.999701 | 0.999561 | 0.006717 | 0.025982 | 0.010214 |

Legacy demo comparison on the same readable examples at 0.50: accuracy 0.7140, precision 0.7593, recall 0.4013, F1 0.5251, FP 78, FN 367, Brier 0.227628. Keeping it active is continuity, not an assertion that it is a validated detector.

## Locked bands and final selected-model confusion matrix

Candidate bands: **low <70%; suspicious 70% to <80%; high >=80%**. The active fallback retains 50%/70%. Review aimed for >=95% recall and <=5% FPR on validation, with a 0.70 cap. High aimed for >=98% precision and <=1% FPR, at least 20 predictions and at least 0.10 above review. Both targets were met on validation. A zero observed FP count is not a guaranteed zero false-positive rate.

| Partition / threshold | Precision | Recall | FP | FN |
|---|---:|---:|---:|---:|
| Validation / 0.70 | 0.9967 | 0.9902 | 2 | 6 |
| Validation / 0.80 | 1.0000 | 0.9869 | 0 | 8 |
| Final test / 0.70 | 0.9984 | 0.9935 | 1 | 4 |
| Final test / 0.80 | 1.0000 | 0.9902 | 0 | 6 |

At the selected 0.70 review threshold:

| Actual / predicted | Legitimate | Phishing |
|---|---:|---:|
| Legitimate | 942 | 1 |
| Phishing/fraud | 4 | 609 |

Accuracy 0.9968, precision 0.9984, recall 0.9935, F1 0.9959; **1 FP and 4 FN**. Raising to 0.80 removes the one FP but increases FN from four to six. This test observation was not used to retune either threshold.

## Calibration evidence

Brier, log loss and ECE are reported for every candidate above; full validation/test reliability bins are in the JSON reports. Selected candidate final-test bins:

| Probability bin | Count | Mean predicted probability | Observed phishing fraction |
|---|---:|---:|---:|
| 0.0-0.1 | 929 | 0.0024 | 0.0011 |
| 0.1-0.2 | 10 | 0.1466 | 0.0000 |
| 0.2-0.3 | 1 | 0.2807 | 1.0000 |
| 0.3-0.4 | 1 | 0.3308 | 0.0000 |
| 0.4-0.5 | 3 | 0.4555 | 0.3333 |
| 0.5-0.6 | 1 | 0.5634 | 0.0000 |
| 0.6-0.7 | 1 | 0.6401 | 1.0000 |
| 0.7-0.8 | 3 | 0.7281 | 0.6667 |
| 0.8-0.9 | 6 | 0.8464 | 1.0000 |
| 0.9-1.0 | 601 | 0.9994 | 1.0000 |

Middle bins have very few observations. Brier combines calibration and discrimination; a small Brier score does not establish stable calibration under domain/prevalence shift. The dataset contains about 39% phishing/fraud, unlike many real inboxes.

## Why activation is blocked

The source-transfer stress test fits on one benign/phishing source pair and checks the other using training-partition data only, then reverses roles. It excludes cross-boundary merged provenance. Both pairs contain both classes; results below use the predeclared 0.50 threshold.

| Held-out source pair | Precision | Recall | F1 | FPR | Confusion matrix |
|---|---:|---:|---:|---:|---|
| ling, nazario | 0.7415 | 0.8442 | 0.7895 | 0.1786 | `[[1329, 289], [153, 829]]` |
| nigerian_fraud, spamassassin | 0.6609 | 0.6468 | 0.6537 | 0.2239 | `[[2160, 623], [663, 1214]]` |

Worst transfer error is 35.32%, above the 20% gate. Recall falls to 64.68%, and the corresponding FPR is 22.39%. These results outweigh the excellent mixed-corpus holdout numbers.

Additional limitations: each admitted source supplies one class; collection/topic artifacts may survive masking; historical English-heavy mail is not representative of modern BEC, OAuth lures or multilingual mail; fraud labels are broader than credential phishing; corpus labels were not independently reannotated; near-deduplication does not identify every paraphrase. The absence of subject fields and the 40,000-character cap can lose context. No privacy-sensitive inbox data was collected to fill these gaps.

Next evidence needed for promotion: an independently labeled modern dataset with legitimate and phishing examples from comparable collection pipelines, plus a fresh source/time-separated final holdout. Do not optimize against this already revealed test set.

## Artifacts and verification

- `ml/models/legacy_demo/metadata.json`: protected original hashes; original `ml/*.joblib` remain active and byte-for-byte unchanged.
- `ml/models/candidate_v1/model.joblib`: locally trained research candidate, ignored by Git.
- `ml/models/candidate_v1/metadata.json`: type, date, dependency versions, source/feature hashes, thresholds, evaluation and promotion blockers.
- `ml/reports/candidate_v1_selection.json`: validation metrics for every candidate, source tests, latency and threshold tradeoff grid, locked before test.
- `ml/reports/candidate_v1_final.json`: final candidate metrics, calibration bins, source breakdowns and hashed error IDs.
- Complete offline test suite: **170 tests passed**. Tests need no downloads or public-corpus files; synthetic fixtures exercise pipeline correctness.
- No UI redesign or changes to fusion weights, authentication, VirusTotal, attachments, geolocation or correlation. The runtime input guard is compatible with existing valid-text scores.

See `docs/ai-model-readiness.md` for commands and the full methodology. No candidate is automatically activated.

## Files changed

- `.gitignore`, `requirements.txt`: exclude local datasets/runs/model binaries and pin already-installed NumPy/threadpoolctl as direct dependencies.
- `ml/__init__.py`, `ml/fetch_data.py`, `ml/text.py`, `ml/data_pipeline.py`: public-data acquisition and normalization/deduplication/splitting.
- `ml/train_model.py`, `ml/experiment.py`, `ml/inference.py`, `ml/report.py`: protected legacy training, candidate comparison, gated loading and report rendering.
- `backend/analyzers/nlp_detector.py`: malformed-input guard; the active model and valid-input output remain unchanged.
- `ml/data/sources.json`, `ml/data/manifest.json`: source/license recipe and measured construction/split metadata.
- `ml/models/legacy_demo/metadata.json`, `ml/models/candidate_v1/metadata.json`: versioned provenance, artifact hashes and readiness status.
- `ml/reports/candidate_v1_selection.json`, `ml/reports/candidate_v1_selection.json.test-opened`, `ml/reports/candidate_v1_final.json`, `ml/reports/AI_MODEL_READINESS.md`: frozen selection, final evaluation and this report.
- `tests/test_model_readiness.py`: 44 new offline regressions.
- `README.md`, `docs/architecture.md`, `docs/ai-model-readiness.md`: operating instructions, architecture and interpretation.
