# AI Dataset Generalization v2: measured research results

**Active model: unchanged 16-example legacy fallback. No research candidate was activated.**
Preselected research candidate: **Linear SVM + sigmoid**. Any candidate eligible: **False**.
The v1 candidate remains unvalidated and inactive.

Protected checkpoint: a56e87675657cbfbde3f70be7c440db203bed76a. No commit, remote or push is part of this milestone.
Full offline suite: **217 tests passed**. Tests require no public datasets, trained candidate binaries or network.

## Dataset decisions and provenance

Only public CSV text/metadata was used. Raw/derived emails and fitted binaries are ignored. Counts are measured from pinned files, not advertised full-corpus sizes. The original four sources are publisher-declared CC-BY-4.0 under [Zenodo 8339691](https://zenodo.org/records/8339691). New sources have citations, version URLs and usage notes in ml/data/sources_v2.json.

| Admitted corpus | License | Raw | Label eligible | Usable before dedup | Retained | Class |
|---|---|---:|---:|---:|---:|---|
| [ling](https://zenodo.org/records/8339691) | CC-BY-4.0 | 2859 | 2401 | 2401 | 1618 | 0 |
| [spamassassin](https://zenodo.org/records/8339691) | CC-BY-4.0 | 5809 | 4091 | 4091 | 2783 | 0 |
| [nazario](https://zenodo.org/records/8339691) | CC-BY-4.0 | 1565 | 1565 | 1565 | 982 | 1 |
| [nigerian_fraud](https://zenodo.org/records/8339691) | CC-BY-4.0 | 3332 | 3332 | 3331 | 1877 | 1 |
| [trec06_ham](https://figshare.com/articles/dataset/25432108) | CC-BY-4.0 | 16463 | 12411 | 12409 | 12078 | 0 |
| [adjei_bec](https://www.kaggle.com/datasets/yoadjei/adversarial-bec-email-dataset) | CC-BY-SA-4.0 | 4211 | 4181 | 4181 | 4181 | 1 |
| [kuladeep_synthetic](https://www.kaggle.com/datasets/kuladeep19/phishing-and-legitimate-emails-dataset) | CC-BY-SA-4.0 | 10000 | 10000 | 10000 | 7538 | 0, 1 |

Labels: 0 legitimate; 1 phishing/social-engineering fraud. Synthetic samples are stress evidence, not observed inbox phishing. TREC-06 spam is excluded. Adjei advertises 4,211 messages, but only 4,181 rows have admissible labels. Kuladeep's 2026 title refers to a September 2025 release.

| Source / publisher | Period | Usage/provenance notes |
|---|---|---|
| trec06_ham / Arifa Islam Champa and Md Fazle Rabbi; original TREC 2006 spam track | TREC 2006 collection; row Date headers are unverified and not reliable chronology | Retain explicitly labeled ham only; exclude label 1 generic spam and null/invalid labels. New corpus source, not independent evidence for both classes. |
| adjei_bec / Yaw Osei Adjei | Published November 2025; generated examples, no real sent timestamps | Gemini 2.5 Flash synthetic BEC/fraud. Only clean CSV; the paired obfuscated version is excluded to avoid splitting paraphrase families and is not downloaded. Actual filename differs from the card. Blank labels excluded rather than inferred. |
| kuladeep_synthetic / Kuladeep P | Version 1 released September 2025 despite 2026 title; synthetic, no real sent timestamps | Both classes within one collection. Explicit separate prompts make legitimate text deliberately non-suspicious; template/topic bias is expected. Ignore phishing_type, severity and confidence entirely. |

The four original collections are historical (the combined release describes 1995–2022); reliable individual cross-source chronology was not established. A recent dataset release does not make its email recent.

Every additional dataset actively assessed is listed below. Search suggestions without substantive review were not treated as corpus decisions. Unverified counts mean no raw corpus was obtained.

| Dataset considered | Publisher | License / terms | Reported size | Decision and reason |
|---|---|---|---|---|
| [DataPhish / Constructing and Benchmarking (2025)](https://arxiv.org/abs/2511.21448) | Rebeka Toth, Tamas Bisztray, Richard A. Dubniczky | Paper CC-BY-4.0; downloadable corpus license not verified | Paper describes originals and rephrases; no verified accessible raw count | REJECTED_UNAVAILABLE: Published GitHub DataPhish/PhishingSpamDataSet and API returned 404 on 2026-09-04. No data downloaded; paper license does not establish permission for unavailable corpus. |
| [MeAJOR v2](https://zenodo.org/records/18471483) | Cardoso, Vitorino, Mendes, Maia, Praca | CC-BY-4.0 | 108685 | REJECTED: Repackages overlapping corpora; merged positive label includes spam sources. Not new independent phishing ground truth; anonymization also changes text. No raw download. |
| [Phishing-Email-Detection-Dataset (2025)](https://zenodo.org/records/17314806) | Alhuzali, Alloqmani, Aljabri, Alharbi | CC-BY-4.0 | not verified | REJECTED: Merged/downsampled public corpora; no verified new independent collection or spam/phishing separation. No raw download. |
| [Seven Phishing Email Datasets: other files](https://figshare.com/articles/dataset/25432108) | Champa and Rabbi | CC-BY-4.0 | not verified | PARTIAL: TREC-06 ham admitted. Assassin/Ling copies duplicate existing bytes; TREC-05/-07 and CEAS generic spam positives not admitted as phishing; Enron and pre-vectorized files not used. TREC-06 suffices as one extra historical legitimate source in this fixed run. |
| [Human-LLM generated phishing-legitimate emails](https://www.kaggle.com/datasets/francescogreco97/human-llm-generated-phishing-legitimate-emails) | Francesco Greco et al. | CC-BY-NC-SA-4.0 | 4000 | REJECTED: Label column denotes human versus LLM, not phishing; human source description ambiguously attributes legitimate mail to Nazario/Nigerian Fraud. Do not guess a class mapping. No raw download. |
| [PhishNChips v5.2](https://huggingface.co/datasets/AreLit/PhishNChips) | PhishNChips / AreLit | MIT synthetic content plus mixed third-party/academic permissions; not a blanket MIT corpus license | 2000 core synthetic emails plus overlapping Nazario subsets | REJECTED: Additional synthetic source with mixed source-specific permissions, not fresh independent real email ground truth. Core URL-derived labels have source/label confounding. Prefer clearly licensed CSVs for this run. |
| [IWSPA-AP v2](https://www2.cs.uh.edu/~rmverma/book.html) | Rakesh M. Verma / University of Houston | Restricted academic request, institutional identity and NDA | not verified | REJECTED_RESTRICTED: Not openly downloadable under current authorization; no request, NDA, identity transfer or third-party mirror use. |
| [AVN Phishing Email Classification Dataset](https://www.kaggle.com/datasets/avnbluefox/avn-phishing-email-classification-dataset) | AVN BlueFox | CC-BY-4.0 | 60000 Basic rows advertised; clean corpus count not verified | REJECTED: Adds deliberate noise/garbage labels; independent original collection and inherited class provenance not sufficiently documented. No raw download. |
| [Turkish Phishing Email Dataset](https://www.kaggle.com/datasets/osmancancet/turkish-phishing-email-dataset) | Osman Can Cetlenbik | Card text CC-BY-4.0 conflicts with platform CC-BY-NC-SA-4.0 | 7500+ advertised | REJECTED: Conflicting usage declarations and unclear generation/collection provenance; language transfer is outside this fixed English-centric research comparison. No raw download. |
| [Phishing Codebook](https://arxiv.org/abs/2408.08967) | Saka, Jain, Vaniea, Kokciyan | Open paper; separately licensed downloadable email-text corpus not verified | 503 | REJECTED_UNVERIFIED: Useful independent phishing study, but no verified licensed text asset located in this review. No data downloaded. |
| [Impact of email category on phishing detection](https://figshare.com/articles/dataset/28953446) | Arifa Islam Champa | CC-BY-4.0 | 20 | REJECTED: Small user-study package with questionnaire, response spreadsheet and 20 stimuli; insufficient source-generalization support. No participant data downloaded. |
| [Spam E-mail and Phishing Detection](https://data.mendeley.com/datasets/shj94nrczy/1) | Ahmed Sedik and Moustafa M. Nasralla | CC-BY-4.0 | not verified | REJECTED: RAR notebook bundle with unclear phishing/ham text label provenance; no reviewed standalone email CSV. No archive downloaded. |
| [Balanced Dataset for Spam and Smishing Detection](https://data.mendeley.com/datasets/vmg875v4xs/1) | Miriam Munoz and Muhammad Islam | CC-BY-4.0 | 10191 | REJECTED: Synthetic SMS/smishing, not email text; no download. |

## Exclusions, duplicates and balance

Inspected **44,239 raw rows**. Excluded **6,165 generic-spam/other-label rows**, **93 missing/invalid labels**, **3 empty examples**, and **0 malformed CSV rows**.
Of **37,978 usable rows**, removed **3,482 duplicates** from retained consistent families; quarantined **12 conflicting-label rows** and **3,427 rows in 3,112 exposed-v1 evaluation families**. Retained **31,057 representatives**.
The graph made 129 exact and 367 additional template/body component merges and found 5891 near edges. Edges are not additional removed-row counts; conflict/exposure quarantine takes priority.

| Source | Legitimate | Phishing/fraud | Fitted training after cap |
|---|---:|---:|---:|
| adjei_bec | 0 | 4181 | 1500 |
| kuladeep_synthetic | 1538 | 6000 | 2576 |
| ling | 1618 | 0 | 1375 |
| nazario | 0 | 982 | 834 |
| nigerian_fraud | 0 | 1877 | 1500 |
| spamassassin | 2783 | 0 | 1500 |
| trec06_ham | 12078 | 0 | 1500 |

Class balance: **18,017 legitimate**, **13,040 phishing/fraud**. **11,719 records are synthetic**. Only Kuladeep contributes both labels within one collection; its prompts differ by label.

## Partitions and untouched-test methodology

| Partition | Total | Legitimate | Phishing/fraud | Synthetic |
|---|---:|---:|---:|---:|
| train | 22824 | 13270 | 9554 | 8201 |
| validation | 4662 | 2704 | 1958 | 1759 |
| test | 3571 | 2043 | 1528 | 1759 |
| Training actually fitted | 10785 | 5451 | 5334 | 4076 |

Source+class strata are split after global duplicate/conflict quarantine, seed 20260904. New-source strata use 70/15/15. Old-source components are development-only, 85/15/0. Strata under eight rows are training-only and reported.
The final test covers **TREC-06, Adjei BEC and Kuladeep only**, with no old-source representative or detected v1 evaluation family. All its positive examples are synthetic. This is a fresh diagnostic research holdout, **not a representative deployment test**. Old sources receive validation and training-only source evaluation.
TF-IDF and three-fold sigmoid calibration see training only. The cap applies only to training, after splitting. Each source-holdout model tunes thresholds on internal validation from its fitting sources only. All four artifacts and per-candidate mixed-validation bands were locked before final testing.
Final-test results never choose a model or revise thresholds. Model/code/data/lock hashes and a single-use marker guard final evaluation. A better final score from another model cannot switch the preselected candidate.
Temporal evaluation: **unavailable**. No reliable message chronology, so no fabricated temporal split. New synthetic release dates are not sent dates. Source transfer is reported, not called temporal validation.

## Fixed candidates and validation choice

The four v1 model configurations are reused: TF-IDF word unigrams/bigrams, min_df=2, max_df=0.98, 50,000 features, sublinear TF; LR/SVM C=1 and balanced classes, NB alpha=1. Sigmoid calibration uses training-only out-of-fold predictions with TF-IDF inside each fold. No sweep, neural model or GPU dependency was added.
Preselected **Linear SVM + sigmoid** using: Prefer development-gate passes, then 0.50*(1-worst source error)+0.25*LOSO macro recall+0.15*validation F1+0.10*(1-LOSO macro Brier); ties prefer simpler/faster. Final test never selects or tunes.

| Candidate | Review / high | Validation F1 | LOSO worst error | Macro recall | Macro FPR | Macro Brier | p95 ms | Failed gates |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Linear SVM + sigmoid | 0.70 / 0.80 | 0.9941 | 0.6696 | 0.7107 | 0.1157 | 0.1171 | 2.014 | 10 |
| Logistic Regression | 0.70 / 0.80 | 0.9886 | 0.9718 | 0.4011 | 0.0031 | 0.1501 | 1.146 | 10 |
| Logistic Regression + sigmoid | 0.70 / 0.80 | 0.9918 | 0.7931 | 0.6595 | 0.1096 | 0.1453 | 1.925 | 10 |
| Multinomial Naive Bayes | 0.70 / 0.80 | 0.9915 | 0.9605 | 0.5639 | 0.0282 | 0.1749 | 2.003 | 9 |

## Mixed-source validation at validation-selected review thresholds

| Candidate / source | n | Precision | Recall | F1 | FPR | FNR | FP | FN | Brier | ECE |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Linear SVM + sigmoid | 4662 | 0.9929 | 0.9954 | 0.9941 | 0.0052 | 0.0046 | 14 | 9 | 0.0039 | 0.0038 |
| Logistic Regression | 4662 | 0.9995 | 0.9780 | 0.9886 | 0.0004 | 0.0220 | 1 | 43 | 0.0128 | 0.0696 |
| Logistic Regression + sigmoid | 4662 | 0.9913 | 0.9923 | 0.9918 | 0.0063 | 0.0077 | 17 | 15 | 0.0056 | 0.0052 |
| Multinomial Naive Bayes | 4662 | 0.9944 | 0.9888 | 0.9915 | 0.0041 | 0.0112 | 11 | 22 | 0.0057 | 0.0100 |

## Fresh new-source final research test at locked review thresholds

| Candidate / source | n | Precision | Recall | F1 | FPR | FNR | FP | FN | Brier | ECE |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Linear SVM + sigmoid | 3571 | 0.9954 | 1.0000 | 0.9977 | 0.0034 | 0.0000 | 7 | 0 | 0.0027 | 0.0057 |
| Logistic Regression | 3571 | 0.9993 | 0.9836 | 0.9914 | 0.0005 | 0.0164 | 1 | 25 | 0.0117 | 0.0724 |
| Logistic Regression + sigmoid | 3571 | 0.9928 | 0.9993 | 0.9961 | 0.0054 | 0.0007 | 11 | 1 | 0.0039 | 0.0073 |
| Multinomial Naive Bayes | 3571 | 0.9987 | 0.9961 | 0.9974 | 0.0010 | 0.0039 | 2 | 6 | 0.0038 | 0.0130 |

| Candidate | Final accuracy | ROC-AUC | PR-AUC (AP) | Log loss | Confusion [[TN,FP],[FN,TP]] |
|---|---:|---:|---:|---:|---|
| Linear SVM + sigmoid | 0.9980 | 1.0000 | 1.0000 | 0.0102 | [[2036, 7], [0, 1528]] |
| Logistic Regression | 0.9927 | 1.0000 | 1.0000 | 0.0825 | [[2042, 1], [25, 1503]] |
| Logistic Regression + sigmoid | 0.9966 | 1.0000 | 1.0000 | 0.0147 | [[2032, 11], [1, 1527]] |
| Multinomial Naive Bayes | 0.9978 | 1.0000 | 0.9999 | 0.0187 | [[2041, 2], [6, 1522]] |

Selected candidate confusion matrix: **[[2036, 7], [0, 1528]]**; **7 FP**, **0 FN**. These describe the stated diagnostic split, not real-world accuracy.

## Validation per source

| Candidate / source | n | Precision | Recall | F1 | FPR | FNR | FP | FN | Brier | ECE |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Linear SVM + sigmoid / adjei_bec | 628 | n/a | 0.9984 | n/a | n/a | 0.0016 | 0 | 1 | 0.0003 | 0.0015 |
| Linear SVM + sigmoid / kuladeep_synthetic | 1131 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 0 | 0 | 0.0000 | 0.0001 |
| Linear SVM + sigmoid / ling | 243 | n/a | n/a | n/a | 0.0000 | n/a | 0 | 0 | 0.0004 | 0.0024 |
| Linear SVM + sigmoid / nazario | 148 | n/a | 0.9865 | n/a | n/a | 0.0135 | 0 | 2 | 0.0135 | 0.0200 |
| Linear SVM + sigmoid / nigerian_fraud | 282 | n/a | 0.9787 | n/a | n/a | 0.0213 | 0 | 6 | 0.0099 | 0.0152 |
| Linear SVM + sigmoid / spamassassin | 418 | n/a | n/a | n/a | 0.0048 | n/a | 2 | 0 | 0.0030 | 0.0058 |
| Linear SVM + sigmoid / trec06_ham | 1812 | n/a | n/a | n/a | 0.0066 | n/a | 12 | 0 | 0.0066 | 0.0124 |
| Logistic Regression / adjei_bec | 628 | n/a | 0.9729 | n/a | n/a | 0.0271 | 0 | 17 | 0.0165 | 0.1005 |
| Logistic Regression / kuladeep_synthetic | 1131 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 0 | 0 | 0.0006 | 0.0218 |
| Logistic Regression / ling | 243 | n/a | n/a | n/a | 0.0000 | n/a | 0 | 0 | 0.0070 | 0.0604 |
| Logistic Regression / nazario | 148 | n/a | 0.9122 | n/a | n/a | 0.0878 | 0 | 13 | 0.0355 | 0.1224 |
| Logistic Regression / nigerian_fraud | 282 | n/a | 0.9539 | n/a | n/a | 0.0461 | 0 | 13 | 0.0193 | 0.0791 |
| Logistic Regression / spamassassin | 418 | n/a | n/a | n/a | 0.0000 | n/a | 0 | 0 | 0.0100 | 0.0752 |
| Logistic Regression / trec06_ham | 1812 | n/a | n/a | n/a | 0.0006 | n/a | 1 | 0 | 0.0176 | 0.1010 |
| Logistic Regression + sigmoid / adjei_bec | 628 | n/a | 0.9984 | n/a | n/a | 0.0016 | 0 | 1 | 0.0004 | 0.0022 |
| Logistic Regression + sigmoid / kuladeep_synthetic | 1131 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 0 | 0 | 0.0000 | 0.0000 |
| Logistic Regression + sigmoid / ling | 243 | n/a | n/a | n/a | 0.0000 | n/a | 0 | 0 | 0.0017 | 0.0042 |
| Logistic Regression + sigmoid / nazario | 148 | n/a | 0.9527 | n/a | n/a | 0.0473 | 0 | 7 | 0.0208 | 0.0316 |
| Logistic Regression + sigmoid / nigerian_fraud | 282 | n/a | 0.9752 | n/a | n/a | 0.0248 | 0 | 7 | 0.0140 | 0.0195 |
| Logistic Regression + sigmoid / spamassassin | 418 | n/a | n/a | n/a | 0.0024 | n/a | 1 | 0 | 0.0038 | 0.0069 |
| Logistic Regression + sigmoid / trec06_ham | 1812 | n/a | n/a | n/a | 0.0088 | n/a | 16 | 0 | 0.0092 | 0.0162 |
| Multinomial Naive Bayes / adjei_bec | 628 | n/a | 0.9952 | n/a | n/a | 0.0048 | 0 | 3 | 0.0023 | 0.0169 |
| Multinomial Naive Bayes / kuladeep_synthetic | 1131 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 0 | 0 | 0.0000 | 0.0000 |
| Multinomial Naive Bayes / ling | 243 | n/a | n/a | n/a | 0.0000 | n/a | 0 | 0 | 0.0010 | 0.0065 |
| Multinomial Naive Bayes / nazario | 148 | n/a | 0.9324 | n/a | n/a | 0.0676 | 0 | 10 | 0.0342 | 0.0572 |
| Multinomial Naive Bayes / nigerian_fraud | 282 | n/a | 0.9681 | n/a | n/a | 0.0319 | 0 | 9 | 0.0142 | 0.0217 |
| Multinomial Naive Bayes / spamassassin | 418 | n/a | n/a | n/a | 0.0024 | n/a | 1 | 0 | 0.0051 | 0.0224 |
| Multinomial Naive Bayes / trec06_ham | 1812 | n/a | n/a | n/a | 0.0055 | n/a | 10 | 0 | 0.0075 | 0.0253 |

## Final test per new source

| Candidate / source | n | Precision | Recall | F1 | FPR | FNR | FP | FN | Brier | ECE |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Linear SVM + sigmoid / adjei_bec | 628 | n/a | 1.0000 | n/a | n/a | 0.0000 | 0 | 0 | 0.0000 | 0.0011 |
| Linear SVM + sigmoid / kuladeep_synthetic | 1131 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 0 | 0 | 0.0000 | 0.0001 |
| Linear SVM + sigmoid / trec06_ham | 1812 | n/a | n/a | n/a | 0.0039 | n/a | 7 | 0 | 0.0053 | 0.0116 |
| Logistic Regression / adjei_bec | 628 | n/a | 0.9602 | n/a | n/a | 0.0398 | 0 | 25 | 0.0168 | 0.0999 |
| Logistic Regression / kuladeep_synthetic | 1131 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 0 | 0 | 0.0006 | 0.0216 |
| Logistic Regression / trec06_ham | 1812 | n/a | n/a | n/a | 0.0006 | n/a | 1 | 0 | 0.0170 | 0.1000 |
| Logistic Regression + sigmoid / adjei_bec | 628 | n/a | 0.9984 | n/a | n/a | 0.0016 | 0 | 1 | 0.0004 | 0.0025 |
| Logistic Regression + sigmoid / kuladeep_synthetic | 1131 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 0 | 0 | 0.0000 | 0.0000 |
| Logistic Regression + sigmoid / trec06_ham | 1812 | n/a | n/a | n/a | 0.0061 | n/a | 11 | 0 | 0.0076 | 0.0152 |
| Multinomial Naive Bayes / adjei_bec | 628 | n/a | 0.9904 | n/a | n/a | 0.0096 | 0 | 6 | 0.0035 | 0.0181 |
| Multinomial Naive Bayes / kuladeep_synthetic | 1131 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 0 | 0 | 0.0000 | 0.0000 |
| Multinomial Naive Bayes / trec06_ham | 1812 | n/a | n/a | n/a | 0.0011 | n/a | 2 | 0 | 0.0063 | 0.0243 |

Single-class sources have n/a positive-class precision/F1. Unsupported recall/FNR/FPR are n/a, never zero or safe. Macro summaries retain supporting-source denominators; large corpora get no additional weight.

## Leave-one-source-out using fitting-source-only thresholds

| Candidate / source | n | Precision | Recall | F1 | FPR | FNR | FP | FN | Brier | ECE |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Linear SVM + sigmoid / adjei_bec | 2925 | n/a | 0.6995 | n/a | n/a | 0.3005 | 0 | 879 | 0.1472 | 0.2377 |
| Linear SVM + sigmoid / kuladeep_synthetic | 5276 | 0.9044 | 1.0000 | 0.9498 | 0.4126 | 0.0000 | 444 | 0 | 0.0794 | 0.1032 |
| Linear SVM + sigmoid / ling | 1375 | n/a | n/a | n/a | 0.0095 | n/a | 13 | 0 | 0.0095 | 0.0173 |
| Linear SVM + sigmoid / nazario | 834 | n/a | 0.8129 | n/a | n/a | 0.1871 | 0 | 156 | 0.1043 | 0.1571 |
| Linear SVM + sigmoid / nigerian_fraud | 1595 | n/a | 0.3304 | n/a | n/a | 0.6696 | 0 | 1068 | 0.4285 | 0.5482 |
| Linear SVM + sigmoid / spamassassin | 2365 | n/a | n/a | n/a | 0.0135 | n/a | 32 | 0 | 0.0169 | 0.0374 |
| Linear SVM + sigmoid / trec06_ham | 8454 | n/a | n/a | n/a | 0.0272 | n/a | 230 | 0 | 0.0338 | 0.0665 |
| Logistic Regression / adjei_bec | 2925 | n/a | 0.1525 | n/a | n/a | 0.8475 | 0 | 2479 | 0.2921 | 0.5086 |
| Logistic Regression / kuladeep_synthetic | 5276 | 0.9971 | 0.8914 | 0.9413 | 0.0102 | 0.1086 | 11 | 456 | 0.0666 | 0.1515 |
| Logistic Regression / ling | 1375 | n/a | n/a | n/a | 0.0000 | n/a | 0 | 0 | 0.0278 | 0.1406 |
| Logistic Regression / nazario | 834 | n/a | 0.5324 | n/a | n/a | 0.4676 | 0 | 390 | 0.1469 | 0.3253 |
| Logistic Regression / nigerian_fraud | 1595 | n/a | 0.0282 | n/a | n/a | 0.9718 | 0 | 1550 | 0.4229 | 0.6335 |
| Logistic Regression / spamassassin | 2365 | n/a | n/a | n/a | 0.0004 | n/a | 1 | 0 | 0.0386 | 0.1677 |
| Logistic Regression / trec06_ham | 8454 | n/a | n/a | n/a | 0.0017 | n/a | 14 | 0 | 0.0555 | 0.2046 |
| Logistic Regression + sigmoid / adjei_bec | 2925 | n/a | 0.5856 | n/a | n/a | 0.4144 | 0 | 1212 | 0.2198 | 0.3263 |
| Logistic Regression + sigmoid / kuladeep_synthetic | 5276 | 0.9089 | 1.0000 | 0.9523 | 0.3913 | 0.0000 | 421 | 0 | 0.0796 | 0.1051 |
| Logistic Regression + sigmoid / ling | 1375 | n/a | n/a | n/a | 0.0095 | n/a | 13 | 0 | 0.0108 | 0.0218 |
| Logistic Regression + sigmoid / nazario | 834 | n/a | 0.8453 | n/a | n/a | 0.1547 | 0 | 129 | 0.0845 | 0.1262 |
| Logistic Regression + sigmoid / nigerian_fraud | 1595 | n/a | 0.2069 | n/a | n/a | 0.7931 | 0 | 1265 | 0.5733 | 0.6726 |
| Logistic Regression + sigmoid / spamassassin | 2365 | n/a | n/a | n/a | 0.0097 | n/a | 23 | 0 | 0.0141 | 0.0338 |
| Logistic Regression + sigmoid / trec06_ham | 8454 | n/a | n/a | n/a | 0.0280 | n/a | 237 | 0 | 0.0348 | 0.0658 |
| Multinomial Naive Bayes / adjei_bec | 2925 | n/a | 0.5323 | n/a | n/a | 0.4677 | 0 | 1368 | 0.2044 | 0.3464 |
| Multinomial Naive Bayes / kuladeep_synthetic | 5276 | 0.9783 | 0.9643 | 0.9712 | 0.0836 | 0.0357 | 90 | 150 | 0.0481 | 0.0766 |
| Multinomial Naive Bayes / ling | 1375 | n/a | n/a | n/a | 0.0029 | n/a | 4 | 0 | 0.0117 | 0.0455 |
| Multinomial Naive Bayes / nazario | 834 | n/a | 0.7194 | n/a | n/a | 0.2806 | 0 | 234 | 0.1257 | 0.2209 |
| Multinomial Naive Bayes / nigerian_fraud | 1595 | n/a | 0.0395 | n/a | n/a | 0.9605 | 0 | 1532 | 0.7628 | 0.8508 |
| Multinomial Naive Bayes / spamassassin | 2365 | n/a | n/a | n/a | 0.0135 | n/a | 32 | 0 | 0.0375 | 0.1122 |
| Multinomial Naive Bayes / trec06_ham | 8454 | n/a | n/a | n/a | 0.0127 | n/a | 107 | 0 | 0.0343 | 0.1049 |

## Train-on-other-sources / unseen source-pair transfer

| Candidate / source | n | Precision | Recall | F1 | FPR | FNR | FP | FN | Brier | ECE |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Linear SVM + sigmoid / ling, nazario | 2209 | 0.9867 | 0.7986 | 0.8827 | 0.0065 | 0.2014 | 9 | 168 | 0.0447 | 0.0520 |
| Linear SVM + sigmoid / nigerian_fraud, spamassassin | 3960 | 0.9547 | 0.2777 | 0.4303 | 0.0089 | 0.7223 | 21 | 1152 | 0.1841 | 0.2197 |
| Linear SVM + sigmoid / adjei_bec, trec06_ham | 11379 | 0.9411 | 0.7915 | 0.8598 | 0.0172 | 0.2085 | 145 | 610 | 0.0388 | 0.0152 |
| Logistic Regression / ling, nazario | 2209 | 1.0000 | 0.5228 | 0.6866 | 0.0000 | 0.4772 | 0 | 398 | 0.0688 | 0.1669 |
| Logistic Regression / nigerian_fraud, spamassassin | 3960 | 1.0000 | 0.0213 | 0.0417 | 0.0000 | 0.9787 | 0 | 1561 | 0.1819 | 0.2011 |
| Logistic Regression / adjei_bec, trec06_ham | 11379 | 0.9932 | 0.2000 | 0.3330 | 0.0005 | 0.8000 | 4 | 2340 | 0.0826 | 0.1764 |
| Logistic Regression + sigmoid / ling, nazario | 2209 | 0.9873 | 0.8405 | 0.9080 | 0.0065 | 0.1595 | 9 | 133 | 0.0367 | 0.0378 |
| Logistic Regression + sigmoid / nigerian_fraud, spamassassin | 3960 | 0.9357 | 0.1643 | 0.2795 | 0.0076 | 0.8357 | 18 | 1333 | 0.2533 | 0.2758 |
| Logistic Regression + sigmoid / adjei_bec, trec06_ham | 11379 | 0.9419 | 0.7477 | 0.8336 | 0.0160 | 0.2523 | 135 | 738 | 0.0438 | 0.0212 |
| Multinomial Naive Bayes / ling, nazario | 2209 | 0.9968 | 0.7578 | 0.8610 | 0.0015 | 0.2422 | 2 | 202 | 0.0439 | 0.0609 |
| Multinomial Naive Bayes / nigerian_fraud, spamassassin | 3960 | 0.9172 | 0.0903 | 0.1644 | 0.0055 | 0.9097 | 13 | 1451 | 0.2305 | 0.2486 |
| Multinomial Naive Bayes / adjei_bec, trec06_ham | 11379 | 0.9824 | 0.6875 | 0.8089 | 0.0043 | 0.3125 | 36 | 914 | 0.0381 | 0.0547 |

Source experiments use the mixed training partition only. JSON retains internal fit/validation/check counts, source purges, thresholds, fixed-0.50 comparisons, macro summaries and reliability bins.

## Calibration and residual source artifacts

Per-source Brier, log loss, ten-bin reliability and ECE are recorded for all candidates. Brier combines discrimination and calibration; sparse bins and prevalence changes limit inference. Low pooled Brier cannot establish real-inbox probability calibration.
Training-only audit: 52 rows contain embedded metadata and 96 contain filenames before scrubbing; no known marker pattern remained afterward. 138 repeated-line groups occur in at least 20 messages. Only hashes/counts of these lines are exported.
The separate text-to-source classifier achieves validation accuracy **96.87%**, balanced accuracy **97.30%**, versus majority-source baseline **38.87%**. Metadata removal does not eliminate topic and collection fingerprints.

## Deployment gates fixed before fitting

| Development gate | Required | Linear SVM + sigmoid | Logistic Regression | Logistic Regression + sigmoid | Multinomial Naive Bayes |
|---|---|---|---|---|---|
| all_source_folds_evaluated | is True | PASS (True) | PASS (True) | PASS (True) | PASS (True) |
| independent_real_both_class_sources | >= 2 | FAIL (0.0000) | FAIL (0.0000) | FAIL (0.0000) | FAIL (0.0000) |
| inference_p95_ms | <= 25 | PASS (2.0136) | PASS (1.1463) | PASS (1.9254) | PASS (2.0029) |
| loso_macro_brier_score | <= 0.1 | FAIL (0.1171) | FAIL (0.1501) | FAIL (0.1453) | FAIL (0.1749) |
| loso_macro_ece_10_equal_width | <= 0.1 | FAIL (0.1668) | FAIL (0.3046) | FAIL (0.1931) | FAIL (0.2511) |
| loso_macro_false_positive_rate | <= 0.05 | FAIL (0.1157) | PASS (0.0031) | FAIL (0.1096) | PASS (0.0282) |
| loso_macro_recall | >= 0.9 | FAIL (0.7107) | FAIL (0.4011) | FAIL (0.6595) | FAIL (0.5639) |
| loso_worst_brier | <= 0.15 | FAIL (0.4285) | FAIL (0.4229) | FAIL (0.5733) | FAIL (0.7628) |
| loso_worst_source_error | <= 0.1 | FAIL (0.6696) | FAIL (0.9718) | FAIL (0.7931) | FAIL (0.9605) |
| representative_external_holdout | is True | FAIL (False) | FAIL (False) | FAIL (False) | FAIL (False) |
| source_sample_support | >= 100 | PASS (834.0000) | PASS (834.0000) | PASS (834.0000) | PASS (834.0000) |
| transfer_max_fpr | <= 0.05 | PASS (0.0172) | PASS (0.0005) | PASS (0.0160) | PASS (0.0055) |
| transfer_min_f1 | >= 0.9 | FAIL (0.4303) | FAIL (0.0417) | FAIL (0.2795) | FAIL (0.1644) |
| transfer_min_recall | >= 0.9 | FAIL (0.2777) | FAIL (0.0213) | FAIL (0.1643) | FAIL (0.0903) |
| validation_band_targets | is True | PASS (True) | PASS (True) | PASS (True) | PASS (True) |
| validation_brier | <= 0.1 | PASS (0.0039) | PASS (0.0128) | PASS (0.0056) | PASS (0.0057) |
| validation_ece | <= 0.05 | PASS (0.0038) | FAIL (0.0696) | PASS (0.0052) | PASS (0.0100) |
| validation_f1 | >= 0.9 | PASS (0.9941) | PASS (0.9886) | PASS (0.9918) | PASS (0.9915) |
| validation_fpr | <= 0.05 | PASS (0.0052) | PASS (0.0004) | PASS (0.0063) | PASS (0.0041) |
| validation_precision | >= 0.9 | PASS (0.9929) | PASS (0.9995) | PASS (0.9913) | PASS (0.9944) |
| validation_recall | >= 0.95 | PASS (0.9954) | PASS (0.9780) | PASS (0.9923) | PASS (0.9888) |
| validation_worst_source | <= 0.1 | PASS (0.0213) | PASS (0.0878) | PASS (0.0473) | PASS (0.0676) |

**bands:** Both inherited review and high-band validation targets must be feasible; failed targets are explicit.

**calibration:** Brier<=0.10 and ECE<=0.05 on validation; source-macro Brier<=0.10/ECE<=0.10 and no source Brier>0.15 prevent large sources masking overconfidence.

**f1:** At least 0.90 balances precision/recall; accuracy alone is not a selection criterion.

**false_positives:** At most 5% legitimate FPR on mixed validation and each paired transfer; 10% worst-source error is a research ceiling, not an acceptable operational inbox guarantee.

**latency:** p95 <=25 ms per normalized text on this CPU, matching the prior lightweight research budget.

**provenance:** At least two independently collected modern real-email sources with both classes plus a representative fresh external holdout; synthetic generation and a new release date do not establish this.

**recall:** At most 5% missed phishing on mixed validation, 10% on any held-out phishing source; mixed results cannot excuse source failures.

**support:** At least 100 independent representatives in each held-out source; small folds are insufficient evidence, not automatic passes.

Final confirmation repeats numerical checks with locked test predictions and retains development failures. Full confirmation gates are in JSON/metadata; final performance never erases a source-validation failure.

| Candidate | Validation state | Eligible | Failed development gates |
|---|---|---|---|
| Linear SVM + sigmoid | UNVALIDATED | False | loso_worst_source_error, loso_macro_recall, loso_macro_false_positive_rate, loso_macro_brier_score, loso_macro_ece_10_equal_width, loso_worst_brier, transfer_min_recall, transfer_min_f1, independent_real_both_class_sources, representative_external_holdout |
| Logistic Regression | UNVALIDATED | False | validation_ece, loso_worst_source_error, loso_macro_recall, loso_macro_brier_score, loso_macro_ece_10_equal_width, loso_worst_brier, transfer_min_recall, transfer_min_f1, independent_real_both_class_sources, representative_external_holdout |
| Logistic Regression + sigmoid | UNVALIDATED | False | loso_worst_source_error, loso_macro_recall, loso_macro_false_positive_rate, loso_macro_brier_score, loso_macro_ece_10_equal_width, loso_worst_brier, transfer_min_recall, transfer_min_f1, independent_real_both_class_sources, representative_external_holdout |
| Multinomial Naive Bayes | UNVALIDATED | False | loso_worst_source_error, loso_macro_recall, loso_macro_brier_score, loso_macro_ece_10_equal_width, loso_worst_brier, transfer_min_recall, transfer_min_f1, independent_real_both_class_sources, representative_external_holdout |

## Limitations and activation decision

No candidate is safe to activate on available evidence. Historical real corpora mostly supply one class; the only two-class new source uses synthetic class-specific prompts. All final positive examples are synthetic. No verified modern independently labeled real two-class collection or representative deployment holdout was admitted. Release dates cannot substitute for temporal evaluation.
Labels are inherited, not reannotated by experts. Topic, spelling, mailing-list boilerplate and generation templates can remain predictive. Practical near matching cannot prove all paraphrase/campaign separation. Deduplication changes prevalence, especially repetitive synthetic legitimate text. Training caps reduce source-size dominance but do not establish source independence. Calibration reflects a research mixture, not real inbox prevalence. Latency is normalized-text inference on this CPU, not end-to-end forensic processing.
V1 and v2 have different sources, exclusions, balance and gate values, so their metrics are not a controlled generalization-improvement comparison. Future promotion needs modern independently labeled real sources containing both classes, adequate source/time support and a new untouched external holdout.
Legacy artifact bytes, the active loader, UI, forensic modules and fusion weights remain unchanged. Keeping the fallback active preserves compatibility; it is not a claim that the demonstration model is validated.

## Files changed

- ml/generalization/__init__.py, text.py, fetch.py, data.py: isolated normalization, reviewed downloads, quarantine, source splits and training cap.
- ml/generalization/evaluate.py, inference.py, report.py: source evaluation, calibration, gates, locked research inference and aggregate report.
- ml/data/sources_v2.json and manifest_v2.json: source decisions, citations, measured counts and hashes.
- ml/reports/candidate_v2_selection.json, its .test-opened marker, candidate_v2_final.json and this report: frozen validation/source/final evidence.
- Four ml/models/candidate_v2/<candidate>/metadata.json files: validation states, gates and source/artifact/version metadata. Fitted binaries are ignored.
- tests/test_model_generalization.py: offline regressions.
- docs/ai-dataset-generalization-v2.md, README.md and docs/architecture.md: methodology, exact gates, reproducibility and compatibility.

Verification: **217 offline tests passed**, including all original 170. No private email, raw corpus text, API key, database, export or fitted research binary belongs in Git.
