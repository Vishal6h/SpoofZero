# Real-World Validation Corpus: frozen evidence

**Legacy model remains active and byte-for-byte unchanged. No candidate was activated.**

Protected checkpoint: bfa6d958631cdafa3c893d2ca439931f4cc22f71. Research choice: **Linear SVM + sigmoid**. Status: **UNVALIDATED**. Activation recommended: **No**. Full offline suite: **294 tests passed**.

This milestone adds a dated real-email corpus and a fresh external SMS corpus. It does not establish real-inbox accuracy. All four candidates are reported after selection, and their final results cannot change the locked model or thresholds.

## Inspection findings and reuse

V1's source-transfer failure and v2's 66.96% worst-source error outweighed excellent mixed-corpus scores. All v2 final-test positives were synthetic. The existing normalizers, duplicate graph primitives, model factory, calibration, metrics, source-aware evaluation and numerical deployment gates were reused without editing their frozen source. Production inference still uses the original model; its 35% fusion contribution, the forensic pipeline and UI are unchanged.

## Every dataset considered: admitted and reused

Counts below distinguish original raw releases from retained representatives. This run reads 31,057 prior v2 representatives and 2,276 eligible new records; it does not pretend to rediscover the historical raw corpora. Source URLs carry publisher attribution. Original CC-BY/CC-BY-SA usage notes remain in the catalog.

| Source | Publisher | License | Origin | Raw release | Input eligible | Retained | Legit | Malicious | Role |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [ling](https://zenodo.org/records/8339691) | Champa, Rabbi and Zibran (2024), Curated datasets and feature analysis for phishing email detection with machine learning; Why phishing emails escape detection: A closer look at the failure points. DOI:10.5281/zenodo.8339691 | CC-BY-4.0 | REAL | 2859 | 1618 | 1618 | 1618 | 0 | DEVELOPMENT_ONLY |
| [spamassassin](https://zenodo.org/records/8339691) | Champa, Rabbi and Zibran (2024), Curated datasets and feature analysis for phishing email detection with machine learning; Why phishing emails escape detection: A closer look at the failure points. DOI:10.5281/zenodo.8339691 | CC-BY-4.0 | REAL | 5809 | 2783 | 2783 | 2783 | 0 | DEVELOPMENT_ONLY |
| [nazario](https://zenodo.org/records/8339691) | Champa, Rabbi and Zibran (2024), Curated datasets and feature analysis for phishing email detection with machine learning; Why phishing emails escape detection: A closer look at the failure points. DOI:10.5281/zenodo.8339691 | CC-BY-4.0 | REAL | 1565 | 982 | 982 | 0 | 982 | DEVELOPMENT_ONLY |
| [nigerian_fraud](https://zenodo.org/records/8339691) | Champa, Rabbi and Zibran (2024), Curated datasets and feature analysis for phishing email detection with machine learning; Why phishing emails escape detection: A closer look at the failure points. DOI:10.5281/zenodo.8339691 | CC-BY-4.0 | REAL | 3332 | 1877 | 1877 | 0 | 1877 | DEVELOPMENT_ONLY |
| [trec06_ham](https://figshare.com/articles/dataset/25432108) | Arifa Islam Champa and Md Fazle Rabbi; original TREC 2006 spam track | CC-BY-4.0 | REAL | 16463 | 12078 | 10266 | 10266 | 0 | DEVELOPMENT_ONLY |
| [adjei_bec](https://www.kaggle.com/datasets/yoadjei/adversarial-bec-email-dataset) | Yaw Osei Adjei | CC-BY-SA-4.0 | SYNTHETIC | 4211 | 4181 | 4181 | 0 | 4181 | DIAGNOSTIC_ONLY |
| [kuladeep_synthetic](https://www.kaggle.com/datasets/kuladeep19/phishing-and-legitimate-emails-dataset) | Kuladeep P | CC-BY-SA-4.0 | SYNTHETIC | 10000 | 7538 | 7538 | 1538 | 6000 | DIAGNOSTIC_ONLY |
| [spaphish](https://data.mendeley.com/datasets/hz2d6gz7pc/5) | Lazaro Bustio-Martinez et al. | CC-BY-4.0 | REAL | 1395 | 1395 | 1168 | 647 | 521 | ADMITTED_TEMPORAL_EMAIL |
| [smishx](https://github.com/yizhu-joy/SmishX) | Yizhu Wang, Haoyu Zhai, Chenkai Wang, Qingying Hao, Nick A. Cohen, Roopa Foulger, Jonathan A. Handler, Gang Wang | MIT, publisher repository LICENSE | REAL | 1200 | 881 | 786 | 604 | 182 | ADMITTED_EXTERNAL_SMS |

SpaPhish's source release has 1,395 rows (664 legitimate / 731 phishing); SmishX has 1,200 (622 legitimate / 259 smishing / 319 generic spam). Only legitimate and smishing SMS enter the corpus. Only CSV text and JSON schema were downloaded; no raw MIME, attachments, archives, leaked inboxes or scripts.

## Other reviewed datasets and exclusions

| Dataset | Publisher | License/usage | Period | Origin | Classes | Reported raw count | Admitted | Reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [DataPhish / Constructing and Benchmarking (2025)](https://arxiv.org/abs/2511.21448) | Rebeka Toth, Tamas Bisztray, Richard A. Dubniczky | Paper CC-BY-4.0; downloadable corpus license not verified | 2025 publication | UNKNOWN | See publisher; unverified unless specified | Paper describes originals and rephrases; no verified accessible raw count | 0 | Published GitHub DataPhish/PhishingSpamDataSet and API returned 404 on 2026-09-04. No data downloaded; paper license does not establish permission for unavailable corpus. |
| [MeAJOR v2](https://zenodo.org/records/18471483) | Cardoso, Vitorino, Mendes, Maia, Praca | CC-BY-4.0 | Historical TREC 2005-2007, Nazario and Nigerian Fraud; 2026 release | UNKNOWN | See publisher; unverified unless specified | 108685 | 0 | Repackages overlapping corpora; merged positive label includes spam sources. Not new independent phishing ground truth; anonymization also changes text. No raw download. |
| [Phishing-Email-Detection-Dataset (2025)](https://zenodo.org/records/17314806) | Alhuzali, Alloqmani, Aljabri, Alharbi | CC-BY-4.0 | 2025 release, older merged corpora | UNKNOWN | See publisher; unverified unless specified | — | 0 | Merged/downsampled public corpora; no verified new independent collection or spam/phishing separation. No raw download. |
| [Seven Phishing Email Datasets: other files](https://figshare.com/articles/dataset/25432108) | Champa and Rabbi | CC-BY-4.0 | Historical through 2008; released 2024 | UNKNOWN | See publisher; unverified unless specified | — | 0 | TREC-06 ham admitted. Assassin/Ling copies duplicate existing bytes; TREC-05/-07 and CEAS generic spam positives not admitted as phishing; Enron and pre-vectorized files not used. TREC-06 suffices as one extra historical legitimate source in this fixed run. |
| [Human-LLM generated phishing-legitimate emails](https://www.kaggle.com/datasets/francescogreco97/human-llm-generated-phishing-legitimate-emails) | Francesco Greco et al. | CC-BY-NC-SA-4.0 | 2024 release; mixed historical and generated | UNKNOWN | See publisher; unverified unless specified | 4000 | 0 | Label column denotes human versus LLM, not phishing; human source description ambiguously attributes legitimate mail to Nazario/Nigerian Fraud. Do not guess a class mapping. No raw download. |
| [PhishNChips v5.2](https://huggingface.co/datasets/AreLit/PhishNChips) | PhishNChips / AreLit | MIT synthetic content plus mixed third-party/academic permissions; not a blanket MIT corpus license | 2026 synthetic release; historical real phishing | UNKNOWN | See publisher; unverified unless specified | 2000 core synthetic emails plus overlapping Nazario subsets | 0 | Additional synthetic source with mixed source-specific permissions, not fresh independent real email ground truth. Core URL-derived labels have source/label confounding. Prefer clearly licensed CSVs for this run. |
| [IWSPA-AP v2](https://www2.cs.uh.edu/~rmverma/book.html) | Rakesh M. Verma / University of Houston | Restricted academic request, institutional identity and NDA | 2018/2019 | UNKNOWN | See publisher; unverified unless specified | — | 0 | Not openly downloadable under current authorization; no request, NDA, identity transfer or third-party mirror use. |
| [AVN Phishing Email Classification Dataset](https://www.kaggle.com/datasets/avnbluefox/avn-phishing-email-classification-dataset) | AVN BlueFox | CC-BY-4.0 | 2025 release; original message period unknown | UNKNOWN | See publisher; unverified unless specified | 60000 Basic rows advertised; clean corpus count not verified | 0 | Adds deliberate noise/garbage labels; independent original collection and inherited class provenance not sufficiently documented. No raw download. |
| [Turkish Phishing Email Dataset](https://www.kaggle.com/datasets/osmancancet/turkish-phishing-email-dataset) | Osman Can Cetlenbik | Card text CC-BY-4.0 conflicts with platform CC-BY-NC-SA-4.0 | 2025 release; message dates unknown | UNKNOWN | See publisher; unverified unless specified | 7500+ advertised | 0 | Conflicting usage declarations and unclear generation/collection provenance; language transfer is outside this fixed English-centric research comparison. No raw download. |
| [Phishing Codebook](https://arxiv.org/abs/2408.08967) | Saka, Jain, Vaniea, Kokciyan | Open paper; separately licensed downloadable email-text corpus not verified | 2015-2021 emails; 2024 paper | UNKNOWN | See publisher; unverified unless specified | 503 | 0 | The primary paper identifies the annotated corpus as Nazario 2015-2021, not an independent collection. No licensed independent text asset; not downloaded. |
| [Impact of email category on phishing detection](https://figshare.com/articles/dataset/28953446) | Arifa Islam Champa | CC-BY-4.0 | 2025 study | UNKNOWN | See publisher; unverified unless specified | 20 | 0 | Small user-study package with questionnaire, response spreadsheet and 20 stimuli; insufficient source-generalization support. No participant data downloaded. |
| [Spam E-mail and Phishing Detection](https://data.mendeley.com/datasets/shj94nrczy/1) | Ahmed Sedik and Moustafa M. Nasralla | CC-BY-4.0 | 2025 release | UNKNOWN | See publisher; unverified unless specified | — | 0 | RAR notebook bundle with unclear phishing/ham text label provenance; no reviewed standalone email CSV. No archive downloaded. |
| [Balanced Dataset for Spam and Smishing Detection](https://data.mendeley.com/datasets/vmg875v4xs/1) | Miriam Munoz and Muhammad Islam | CC-BY-4.0 | 2025 generated release | UNKNOWN | See publisher; unverified unless specified | 10191 | 0 | Synthetic SMS/smishing, not email text; no download. |
| [Phishing Pot](https://github.com/rf-peixoto/phishing_pot) | rf-peixoto and contributors | CC-BY-NC-4.0 | Modern honeypot collection; public snapshot dates do not establish each message date | REAL | [1] | 10,362 including private samples advertised; public text-only usable count unverified | 0 | Raw MIME collection can contain weaponized attachments. No reviewed attachment-free text release verified. No EML or archive downloaded. |
| [realprogrammersusevim/email-dataset](https://github.com/realprogrammersusevim/email-dataset) | Jonathan Milligan; inherited zrz1996, SpamAssassin contributors, Rachael Tatman | MIT notices plus CC-BY-SA-4.0 Fraudulent E-mail Corpus notice | Historical; exact message range not documented in card | UNKNOWN | ["ham", "spam"] | 19528 | 0 | Not a verified independent modern collection; inherited SpamAssassin/Fraudulent Email content and no per-record original source map. Generic spam is not phishing. No messages downloaded. |
| [Sting9](https://sting9.org/dataset) | Sting9 Research Initiative | Page conflicts: CC0 access description versus ODC-BY-NC footer | 2025 onward advertised; not verified | UNKNOWN | ["phishing", "BEC", "smishing", "scam"] | — | 0 | Conflicting public license statements; no clearly versioned text-only corpus verified. No database dump downloaded. |
| [BanglaPhish-2026](https://github.com/Xrenes/BanglaPhish-2026) | Xrenes | CC-BY-NC-4.0 | 2026 synthetic release | SYNTHETIC | [0, 1] | 6000 | 0 | Explicitly synthetic Bengali benchmark; does not add captured real-email evidence. No download. |

Inherited v2 decisions are explicitly marked in the JSON catalog. Search-engine suggestions without substantive provenance review are not counted as dataset decisions. The Codebook paper explicitly uses Nazario: its annotation release is not a new independent collection. Phishing Pot's raw MIME payload risk prevented admission under this milestone's text-only restriction. Sting9's conflicting license statements were not resolved by assuming the more permissive one.

## Class overlap, dates and corpus quality

| Source | Class overlap quality | Date evidence | Provenance/usage limitations |
| --- | --- | --- | --- |
| ling | SINGLE_CLASS | Publisher compilation spans 1995-2022; conservative 2022 upper bound, not individual timestamps | Reuse local pinned v2 text only. No new raw download. Synthetic rows never fit a model or tune thresholds in this run; previously exposed real test families are quarantined. |
| spamassassin | SINGLE_CLASS | Publisher compilation spans 1995-2022; conservative 2022 upper bound, not individual timestamps | Reuse local pinned v2 text only. No new raw download. Synthetic rows never fit a model or tune thresholds in this run; previously exposed real test families are quarantined. |
| nazario | SINGLE_CLASS | Publisher compilation spans 1995-2022; conservative 2022 upper bound, not individual timestamps | Reuse local pinned v2 text only. No new raw download. Synthetic rows never fit a model or tune thresholds in this run; previously exposed real test families are quarantined. |
| nigerian_fraud | SINGLE_CLASS | Publisher compilation spans 1995-2022; conservative 2022 upper bound, not individual timestamps | Reuse local pinned v2 text only. No new raw download. Synthetic rows never fit a model or tune thresholds in this run; previously exposed real test families are quarantined. |
| trec06_ham | SINGLE_CLASS | TREC 2006 collection; row Date headers are unverified and not reliable chronology | Reuse local pinned v2 text only. No new raw download. Synthetic rows never fit a model or tune thresholds in this run; previously exposed real test families are quarantined. |
| adjei_bec | SINGLE_CLASS | Published November 2025; generated examples, no real sent timestamps | Reuse local pinned v2 text only. No new raw download. Synthetic rows never fit a model or tune thresholds in this run; previously exposed real test families are quarantined. |
| kuladeep_synthetic | BOTH_CLASSES_SYNTHETIC | Version 1 released September 2025 despite 2026 title; synthetic, no real sent timestamps | Reuse local pinned v2 text only. No new raw download. Synthetic rows never fit a model or tune thresholds in this run; previously exposed real test families are quarantined. |
| spaphish | BOTH_CLASSES_REAL | 2014-07 through 2025-10; DD/MM/YYYY per publisher schema, 24 missing dates | Authors voluntarily published manually anonymized personal/institutional messages. Majority expert labels. Plain CSV subject/body only; annotations, attachment metadata, hashes, dates and labels are never model text. One collection, not one independent source per author. |
| smishx | BOTH_CLASSES_REAL_MULTIPLE_ORIGINS | Published SOUPS 2025; reuses older public SMS and 22 author-contributed messages; no row dates | Researcher relabeling of public real SMS. Admit legitimate and smishing, exclude generic spam. Underlying sources vary by class and are not mapped per row; not an independent real-email environment. Never follow URLs or execute companion crawler/LLM code. |

One modern real **email** collection supplies both labels: SpaPhish. Its contributors are not counted as independent environments. SmishX contains both real classes but combines different underlying SMS origins without row-level source mapping. Synthetic same-source class overlap is tracked separately.

## Construction, duplicates and artifacts

Input: **33333** eligible representatives. Removed **274** duplicate rows. Quarantined rows by reason: **{"cross_partition_family": 48, "previously_exposed_test_family": 1812}**. Retained **31199** representatives. Exact component merges: 49; additional template/body/prior-family merges: 96; near edges: 859. Edges are not additional removed-row counts. No new conflicting-label family was found; the predecessor v2 corpus had already quarantined 12 conflicting rows and exposed v1 families.

Cross-period/source/partition families are quarantined in full. Previously exposed test rows are exclusion references, never fresh evidence. Near matching uses inherited unfitted hashing and trigram Jaccard, which cannot guarantee detection of every paraphrase. Prior coarse representatives omit some discarded variants, and quarantine changes campaign frequency.

| Static artifact pattern | Training raw rows | Remaining normalized matches |
| --- | --- | --- |
| collector | 0 | 0 |
| folder_path | 45 | 0 |
| generator_line | 1 | 0 |
| injected_metadata | 16 | 0 |
| label_prefix | 1 | 0 |

Repeated training-line groups with >=20 observations: **155**. Only hashes/counts are preserved. These groups may be signatures, mailing-list notices or repeated templates; they were not manually relabeled or used to learn test-dependent removal rules.

## Source-identity diagnostic

| Accuracy | Balanced accuracy | Majority-source baseline | Extremely predictable (>90%) |
| --- | --- | --- | --- |
| 0.95012 | 0.96379 | 0.59861 | True |

This is a separate development-only text-to-source classifier. High accuracy signals surviving language, topic or collection distinctions; it does not by itself prove malicious label leakage. No external or final corpus fits this diagnostic, and it never affects production inference.

## Partitions, reality tags and temporal integrity

| Partition | Total | Legit | Malicious | REAL | SYNTHETIC | UNKNOWN |
| --- | --- | --- | --- | --- | --- | --- |
| date_unknown | 20 | 0 | 20 | 20 | 0 | 0 |
| external | 786 | 604 | 182 | 786 | 0 | 0 |
| synthetic_stress | 11719 | 1538 | 10181 | 0 | 11719 | 0 |
| test | 596 | 187 | 409 | 596 | 0 | 0 |
| train | 15051 | 12584 | 2467 | 15051 | 0 | 0 |
| validation | 124 | 70 | 54 | 124 | 0 | 0 |
| validation_historical | 2903 | 2473 | 430 | 2903 | 0 | 0 |
| Actually fitted after cap | 7137 | 4765 | 2372 | 7137 | 0 | 0 |

Training uses real historical v2 training plus SpaPhish through 2022. Thresholds use only SpaPhish 2023; the mixed validation report also includes historical v2 development validation. That historical portion is previously exposed development evidence, not a chronological or fresh holdout. The newest SpaPhish 2024–2025 slice is the final temporal test. Missing dates stay out of training and temporal evaluation.

Historical dates use a conservative publisher collection bound through 2022; SpaPhish dates follow its documented DD/MM/YYYY schema. Chronology is conditional on these source reports, not independently authenticated delivery timestamps. The pinned CSV is comma-delimited despite the landing page's semicolon description.

SmishX is entirely external and was read for evaluation only after selection, artifact/code/data/policy hashes and thresholds were locked. Preparation used its text solely for fixed normalization/deduplication and aggregate admission checks. It never fit TF-IDF, a classifier, calibration, thresholds, model selection or the source diagnostic. This is independent **SMS** transfer, not external email validation.

## Models, selection and threshold trade-offs

The four inherited fixed TF-IDF models use word uni/bigrams, min_df=2, max_df=0.98, at most 50,000 features, sublinear TF and Unicode accent stripping. LR/SVM use C=1 and balanced class weights; NB uses alpha=1. Sigmoid calibration learns out-of-fold predictions with TF-IDF fitted within each training fold. Seed: 20260904. No hyperparameter sweep or synthetic fitting.

| Candidate | Mixed-val precision | Recall | F1 | Brier | Worst LOSO error | Selection score | p95 ms | Review / high |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linear SVM + sigmoid | 0.81359 | 0.96488 | 0.88280 | 0.01515 | 0.87398 | 0.38796 | 1.95506 | [0.05, 0.995] |
| Logistic Regression | 0.51776 | 0.99380 | 0.68082 | 0.02412 | 0.90408 | 0.27037 | 1.20008 | [0.13, 0.995] |
| Logistic Regression + sigmoid | 0.80696 | 0.95868 | 0.87630 | 0.02058 | 0.90031 | 0.36580 | 1.86087 | [0.05, 0.995] |
| Multinomial Naive Bayes | 0.72241 | 0.89256 | 0.79852 | 0.02319 | 0.98495 | 0.22586 | 1.66982 | [0.05, 0.995] |

The locked research choice is **Linear SVM + sigmoid**, using the unchanged source-aware ranking (50% specificity of the worst source, 25% macro recall, 15% mixed F1, 10% calibration; gate passes first). Selection is a research comparison, not promotion. Ties prefer simplicity/latency. The final holdout never selects a winner.

| Candidate | 2023 validation FP | FN | Review target met | High target met | Review threshold | High threshold |
| --- | --- | --- | --- | --- | --- | --- |
| Linear SVM + sigmoid | 12 | 14 | False | False | 0.05000 | 0.99500 |
| Logistic Regression | 30 | 2 | False | False | 0.13000 | 0.99500 |
| Logistic Regression + sigmoid | 7 | 17 | False | False | 0.05000 | 0.99500 |
| Multinomial Naive Bayes | 3 | 50 | False | False | 0.05000 | 0.99500 |

Bands are low below review, suspicious from review to below high, and high at or above high. When the recall/FPR target is infeasible the inherited selector records failure and chooses a validation F2 fallback; that is not a usable deployment threshold. High-band infeasibility similarly remains explicit. Full validation threshold grids and high-band final confusion matrices are preserved in JSON; no threshold was adjusted after test.

## Final temporal real-email test, 2024–2025

| Candidate | N | Accuracy | Precision | Recall | F1 | FP | FN | CM [[TN,FP],[FN,TP]] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linear SVM + sigmoid | 596 | 0.79866 | 0.92625 | 0.76773 | 0.83957 | 25 | 95 | [[162, 25], [95, 314]] |
| Logistic Regression | 596 | 0.80201 | 0.79633 | 0.95599 | 0.86889 | 100 | 18 | [[87, 100], [18, 391]] |
| Logistic Regression + sigmoid | 596 | 0.70134 | 0.90813 | 0.62836 | 0.74277 | 26 | 152 | [[161, 26], [152, 257]] |
| Multinomial Naive Bayes | 596 | 0.37919 | 0.86792 | 0.11247 | 0.19913 | 7 | 363 | [[180, 7], [363, 46]] |

| Candidate | ROC-AUC | PR-AUC (AP) | Brier | Log loss | ECE |
| --- | --- | --- | --- | --- | --- |
| Linear SVM + sigmoid | 0.88591 | 0.92691 | 0.37000 | 1.33967 | 0.42590 |
| Logistic Regression | 0.83842 | 0.87062 | 0.38671 | 1.00851 | 0.45385 |
| Logistic Regression + sigmoid | 0.83842 | 0.87062 | 0.52397 | 1.86305 | 0.57477 |
| Multinomial Naive Bayes | 0.81087 | 0.86379 | 0.66039 | 3.46514 | 0.67076 |

## Fresh external SmishX transfer

| Candidate | N | Accuracy | Precision | Recall | F1 | FP | FN | CM [[TN,FP],[FN,TP]] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linear SVM + sigmoid | 786 | 0.46819 | 0.26953 | 0.75824 | 0.39769 | 374 | 44 | [[230, 374], [44, 138]] |
| Logistic Regression | 786 | 0.27481 | 0.23569 | 0.95055 | 0.37773 | 561 | 9 | [[43, 561], [9, 173]] |
| Logistic Regression + sigmoid | 786 | 0.53053 | 0.29540 | 0.74176 | 0.42254 | 322 | 47 | [[282, 322], [47, 135]] |
| Multinomial Naive Bayes | 786 | 0.27608 | 0.23529 | 0.94505 | 0.37678 | 559 | 10 | [[45, 559], [10, 172]] |

| Candidate | ROC-AUC | PR-AUC (AP) | Brier | Log loss | ECE |
| --- | --- | --- | --- | --- | --- |
| Linear SVM + sigmoid | 0.69659 | 0.52813 | 0.17726 | 0.68276 | 0.14887 |
| Logistic Regression | 0.69618 | 0.51449 | 0.15927 | 0.50095 | 0.09083 |
| Logistic Regression + sigmoid | 0.69618 | 0.51449 | 0.18135 | 0.70045 | 0.13289 |
| Multinomial Naive Bayes | 0.69663 | 0.54833 | 0.15740 | 0.50180 | 0.09500 |

## Previously exposed synthetic stress test

| Candidate | N | Accuracy | Precision | Recall | F1 | FP | FN | CM [[TN,FP],[FN,TP]] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linear SVM + sigmoid | 11719 | 0.91305 | 0.91532 | 0.99165 | 0.95196 | 934 | 85 | [[604, 934], [85, 10096]] |
| Logistic Regression | 11719 | 0.86978 | 0.86978 | 0.99980 | 0.93027 | 1524 | 2 | [[14, 1524], [2, 10179]] |
| Logistic Regression + sigmoid | 11719 | 0.91416 | 0.92231 | 0.98409 | 0.95220 | 844 | 162 | [[694, 844], [162, 10019]] |
| Multinomial Naive Bayes | 11719 | 0.88890 | 0.89049 | 0.99440 | 0.93958 | 1245 | 57 | [[293, 1245], [57, 10124]] |

| Candidate | ROC-AUC | PR-AUC (AP) | Brier | Log loss | ECE |
| --- | --- | --- | --- | --- | --- |
| Linear SVM + sigmoid | 0.95681 | 0.99334 | 0.08710 | 0.27272 | 0.11795 |
| Logistic Regression | 0.95434 | 0.99295 | 0.15504 | 0.46909 | 0.27168 |
| Logistic Regression + sigmoid | 0.95434 | 0.99295 | 0.10684 | 0.33154 | 0.14750 |
| Multinomial Naive Bayes | 0.96436 | 0.99468 | 0.12582 | 0.38660 | 0.20698 |

## Unknown-date real-email diagnostic

| Candidate | N | Accuracy | Precision | Recall | F1 | FP | FN | CM [[TN,FP],[FN,TP]] |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linear SVM + sigmoid | 20 | 0.95000 | — | 0.95000 | — | 0 | 1 | [[0, 0], [1, 19]] |
| Logistic Regression | 20 | 1.00000 | — | 1.00000 | — | 0 | 0 | [[0, 0], [0, 20]] |
| Logistic Regression + sigmoid | 20 | 0.60000 | — | 0.60000 | — | 0 | 8 | [[0, 0], [8, 12]] |
| Multinomial Naive Bayes | 20 | 0.05000 | — | 0.05000 | — | 0 | 19 | [[0, 0], [19, 1]] |

| Candidate | ROC-AUC | PR-AUC (AP) | Brier | Log loss | ECE |
| --- | --- | --- | --- | --- | --- |
| Linear SVM + sigmoid | — | — | 0.39568 | 1.06738 | 0.60123 |
| Logistic Regression | — | — | 0.54977 | 1.37103 | 0.72743 |
| Logistic Regression + sigmoid | — | — | 0.82294 | 2.71310 | 0.88292 |
| Multinomial Naive Bayes | — | — | 0.94426 | 5.73598 | 0.95833 |

Calibration metrics and ten-bin reliability tables are preserved for every candidate and cohort. Brier is influenced by discrimination/prevalence as well as calibration; small samples and class imbalance limit ECE interpretation. These scores do not establish calibrated operational probabilities.

## Selected-model real/synthetic class separation

| Partition | Cohort | N | FPR | FNR | Brier |
| --- | --- | --- | --- | --- | --- |
| test | REAL_legitimate | 187 | 0.13369 | — | 0.03010 |
| test | REAL_malicious | 409 | — | 0.23227 | 0.52541 |
| test | SYNTHETIC_legitimate | 0 | — | — | — |
| test | SYNTHETIC_malicious | 0 | — | — | — |
| test | UNKNOWN_legitimate | 0 | — | — | — |
| test | UNKNOWN_malicious | 0 | — | — | — |
| external | REAL_legitimate | 604 | 0.61921 | — | 0.11161 |
| external | REAL_malicious | 182 | — | 0.24176 | 0.39512 |
| external | SYNTHETIC_legitimate | 0 | — | — | — |
| external | SYNTHETIC_malicious | 0 | — | — | — |
| external | UNKNOWN_legitimate | 0 | — | — | — |
| external | UNKNOWN_malicious | 0 | — | — | — |
| synthetic_stress | REAL_legitimate | 0 | — | — | — |
| synthetic_stress | REAL_malicious | 0 | — | — | — |
| synthetic_stress | SYNTHETIC_legitimate | 1538 | 0.60728 | — | 0.07199 |
| synthetic_stress | SYNTHETIC_malicious | 10181 | — | 0.00835 | 0.08938 |
| synthetic_stress | UNKNOWN_legitimate | 0 | — | — | — |
| synthetic_stress | UNKNOWN_malicious | 0 | — | — | — |
| date_unknown | REAL_legitimate | 0 | — | — | — |
| date_unknown | REAL_malicious | 20 | — | 0.05000 | 0.39568 |
| date_unknown | SYNTHETIC_legitimate | 0 | — | — | — |
| date_unknown | SYNTHETIC_malicious | 0 | — | — | — |
| date_unknown | UNKNOWN_legitimate | 0 | — | — | — |
| date_unknown | UNKNOWN_malicious | 0 | — | — | — |

REAL/SYNTHETIC/UNKNOWN per-class and per-source metrics for **all four** models are included in the frozen final JSON. Unsupported single-class precision/F1/AUC are null. Unknown-date messages are still REAL; temporal quality and provenance tags are distinct. Synthetic rows contribute zero deployment evidence.

## Per-source generalization and source macro results

| Candidate | Held-out source | N | Recall | FPR | Worst class error | Brier | ECE |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Linear SVM + sigmoid | ling | 1375 | — | 0.00364 | 0.00364 | 0.00554 | 0.01716 |
| Linear SVM + sigmoid | nazario | 834 | 0.46643 | — | 0.53357 | 0.30342 | 0.42635 |
| Linear SVM + sigmoid | nigerian_fraud | 1595 | 0.12602 | — | 0.87398 | 0.53827 | 0.68138 |
| Linear SVM + sigmoid | spamassassin | 2365 | — | 0.01607 | 0.01607 | 0.02101 | 0.04459 |
| Linear SVM + sigmoid | spaphish | 428 | 0.84211 | 0.86154 | 0.86154 | 0.72599 | 0.78578 |
| Linear SVM + sigmoid | trec06_ham | 8454 | — | 0.01810 | 0.01810 | 0.02645 | 0.06126 |
| Logistic Regression | ling | 1375 | — | 0.00000 | 0.00000 | 0.02607 | 0.14364 |
| Logistic Regression | nazario | 834 | 0.09592 | — | 0.90408 | 0.45195 | 0.65568 |
| Logistic Regression | nigerian_fraud | 1595 | 0.10408 | — | 0.89592 | 0.44103 | 0.65030 |
| Logistic Regression | spamassassin | 2365 | — | 0.00169 | 0.00169 | 0.03328 | 0.15999 |
| Logistic Regression | spaphish | 428 | 0.28947 | 0.03590 | 0.71053 | 0.23810 | 0.39972 |
| Logistic Regression | trec06_ham | 8454 | — | 0.00520 | 0.00520 | 0.03955 | 0.17695 |
| Logistic Regression + sigmoid | ling | 1375 | — | 0.00436 | 0.00436 | 0.00907 | 0.02832 |
| Logistic Regression + sigmoid | nazario | 834 | 0.41367 | — | 0.58633 | 0.35732 | 0.48202 |
| Logistic Regression + sigmoid | nigerian_fraud | 1595 | 0.09969 | — | 0.90031 | 0.65878 | 0.76987 |
| Logistic Regression + sigmoid | spamassassin | 2365 | — | 0.01734 | 0.01734 | 0.02006 | 0.04538 |
| Logistic Regression + sigmoid | spaphish | 428 | 0.81579 | 0.61282 | 0.61282 | 0.50237 | 0.62071 |
| Logistic Regression + sigmoid | trec06_ham | 8454 | — | 0.01940 | 0.01940 | 0.02755 | 0.06349 |
| Multinomial Naive Bayes | ling | 1375 | — | 0.00073 | 0.00073 | 0.00441 | 0.02944 |
| Multinomial Naive Bayes | nazario | 834 | 0.05755 | — | 0.94245 | 0.71173 | 0.81951 |
| Multinomial Naive Bayes | nigerian_fraud | 1595 | 0.01505 | — | 0.98495 | 0.98808 | 0.99316 |
| Multinomial Naive Bayes | spamassassin | 2365 | — | 0.00127 | 0.00127 | 0.01519 | 0.06651 |
| Multinomial Naive Bayes | spaphish | 428 | 0.28947 | 0.03590 | 0.71053 | 0.16435 | 0.28459 |
| Multinomial Naive Bayes | trec06_ham | 8454 | — | 0.00509 | 0.00509 | 0.01301 | 0.05779 |

| Candidate | Macro recall | Macro FPR | Macro Brier | Macro ECE | Worst error | Min source N |
| --- | --- | --- | --- | --- | --- | --- |
| Linear SVM + sigmoid | 0.47818 | 0.22484 | 0.27011 | 0.33609 | 0.87398 | 428 |
| Logistic Regression | 0.16316 | 0.01070 | 0.20499 | 0.36438 | 0.90408 | 428 |
| Logistic Regression + sigmoid | 0.44305 | 0.16348 | 0.26252 | 0.33497 | 0.90031 | 428 |
| Multinomial Naive Bayes | 0.12069 | 0.01074 | 0.31613 | 0.37517 | 0.98495 | 428 |

Each macro averages only supported source metrics, with denominators recorded in JSON. LOSO/transfer use training partitions only. Model and thresholds are fitted without the checking source. The SpaPhish training-era phishing class is sparse, which limits source-specific conclusions.

| Candidate | Unseen source pair | Recall | FPR | F1 | FP | FN |
| --- | --- | --- | --- | --- | --- | --- |
| Linear SVM + sigmoid | ["ling", "nazario"] | 0.53717 | 0.00436 | 0.69565 | 6 | 386 |
| Linear SVM + sigmoid | ["nigerian_fraud", "spamassassin"] | 0.16426 | 0.01311 | 0.27754 | 31 | 1333 |
| Linear SVM + sigmoid | ["spaphish", "trec06_ham"] | 0.89474 | 0.05179 | 0.12830 | 458 | 4 |
| Logistic Regression | ["ling", "nazario"] | 0.09712 | 0.00000 | 0.17705 | 0 | 753 |
| Logistic Regression | ["nigerian_fraud", "spamassassin"] | 0.21818 | 0.02199 | 0.34887 | 52 | 1247 |
| Logistic Regression | ["spaphish", "trec06_ham"] | 0.18421 | 0.00339 | 0.18667 | 30 | 31 |
| Logistic Regression + sigmoid | ["ling", "nazario"] | 0.37410 | 0.00364 | 0.54214 | 5 | 522 |
| Logistic Regression + sigmoid | ["nigerian_fraud", "spamassassin"] | 0.20878 | 0.02156 | 0.33653 | 51 | 1262 |
| Logistic Regression + sigmoid | ["spaphish", "trec06_ham"] | 0.84211 | 0.04331 | 0.14128 | 383 | 6 |
| Multinomial Naive Bayes | ["ling", "nazario"] | 0.06595 | 0.00000 | 0.12373 | 0 | 779 |
| Multinomial Naive Bayes | ["nigerian_fraud", "spamassassin"] | 0.02508 | 0.02748 | 0.04706 | 65 | 1555 |
| Multinomial Naive Bayes | ["spaphish", "trec06_ham"] | 0.31579 | 0.00441 | 0.26966 | 39 | 26 |

## Temporal year cohorts: selected model

| Year | N | Precision | Recall | FPR | F1 | FP | FN |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2024 | 201 | 0.84416 | 0.64356 | 0.12000 | 0.73034 | 12 | 36 |
| 2025 | 347 | 0.94545 | 0.79087 | 0.14286 | 0.86128 | 12 | 55 |

## Every deployment gate: selected model

| Stage | Gate | Observed | Operator | Limit | Result |
| --- | --- | --- | --- | --- | --- |
| inherited_gates | all_source_folds_evaluated | True | is | True | PASS |
| inherited_gates | independent_real_both_class_sources | 1 | >= | 2 | FAIL |
| inherited_gates | inference_p95_ms | 1.95506 | <= | 25 | PASS |
| inherited_gates | loso_macro_brier_score | 0.27011 | <= | 0.10000 | FAIL |
| inherited_gates | loso_macro_ece_10_equal_width | 0.33609 | <= | 0.10000 | FAIL |
| inherited_gates | loso_macro_false_positive_rate | 0.22484 | <= | 0.05000 | FAIL |
| inherited_gates | loso_macro_recall | 0.47818 | >= | 0.90000 | FAIL |
| inherited_gates | loso_worst_brier | 0.72599 | <= | 0.15000 | FAIL |
| inherited_gates | loso_worst_source_error | 0.87398 | <= | 0.10000 | FAIL |
| inherited_gates | representative_external_holdout | False | is | True | FAIL |
| inherited_gates | source_sample_support | 428 | >= | 100 | PASS |
| inherited_gates | transfer_max_fpr | 0.05179 | <= | 0.05000 | FAIL |
| inherited_gates | transfer_min_f1 | 0.12830 | >= | 0.90000 | FAIL |
| inherited_gates | transfer_min_recall | 0.16426 | >= | 0.90000 | FAIL |
| inherited_gates | validation_band_targets | False | is | True | FAIL |
| inherited_gates | validation_brier | 0.01515 | <= | 0.10000 | PASS |
| inherited_gates | validation_ece | 0.00901 | <= | 0.05000 | PASS |
| inherited_gates | validation_f1 | 0.88280 | >= | 0.90000 | FAIL |
| inherited_gates | validation_fpr | 0.04208 | <= | 0.05000 | PASS |
| inherited_gates | validation_precision | 0.81359 | >= | 0.90000 | FAIL |
| inherited_gates | validation_recall | 0.96488 | >= | 0.95000 | PASS |
| inherited_gates | validation_worst_source | 0.25926 | <= | 0.10000 | FAIL |
| additional_gates | external_brier_score | 0.17726 | <= | 0.10000 | FAIL |
| additional_gates | external_ece_10_equal_width | 0.14887 | <= | 0.05000 | FAIL |
| additional_gates | external_f1 | 0.39769 | >= | 0.90000 | FAIL |
| additional_gates | external_false_positive_rate | 0.61921 | <= | 0.05000 | FAIL |
| additional_gates | external_precision | 0.26953 | >= | 0.90000 | FAIL |
| additional_gates | external_real_email_support_0 | 0 | >= | 100 | FAIL |
| additional_gates | external_real_email_support_1 | 0 | >= | 100 | FAIL |
| additional_gates | external_recall | 0.75824 | >= | 0.95000 | FAIL |
| additional_gates | external_worst_source_error | 0.61921 | <= | 0.10000 | FAIL |
| additional_gates | modern_real_email_support | 409 | >= | 100 | PASS |
| additional_gates | synthetic_dominance | 0.00000 | <= | 0.50000 | PASS |
| additional_gates | temporal_brier_score | 0.37000 | <= | 0.10000 | FAIL |
| additional_gates | temporal_ece_10_equal_width | 0.42590 | <= | 0.05000 | FAIL |
| additional_gates | temporal_f1 | 0.83957 | >= | 0.90000 | FAIL |
| additional_gates | temporal_false_positive_rate | 0.13369 | <= | 0.05000 | FAIL |
| additional_gates | temporal_precision | 0.92625 | >= | 0.90000 | PASS |
| additional_gates | temporal_recall | 0.76773 | >= | 0.95000 | FAIL |
| additional_gates | temporal_validation_support_0 | 70 | >= | 20 | PASS |
| additional_gates | temporal_validation_support_1 | 54 | >= | 20 | PASS |
| additional_gates | temporal_worst_source_error | 0.23227 | <= | 0.10000 | FAIL |
| additional_gates | unknown_malicious_provenance | 0.00000 | <= | 0.10000 | PASS |

All inherited v2 numeric values remain unchanged. Temporal and external failures are additional blockers; excellent pooled performance cannot override them. The external real-email support gate is intentionally not satisfied by SMS, and only one qualifying modern real-email collection exists. Missing evidence fails closed.

| Candidate | Status | Inherited gates failed | Additional gates failed | Active |
| --- | --- | --- | --- | --- |
| Linear SVM + sigmoid | UNVALIDATED | 15 | 15 | False |
| Logistic Regression | UNVALIDATED | 15 | 14 | False |
| Logistic Regression + sigmoid | UNVALIDATED | 14 | 15 | False |
| Multinomial Naive Bayes | UNVALIDATED | 15 | 15 | False |

Deployment evidence counts: {"external_real_email_counts": {"0": 0, "1": 0}, "malicious_count": 591, "modern_real_email_phishing": 409, "synthetic_malicious_fraction": 0.0, "unknown_malicious_fraction": 0.0}. No model is recommended for activation. Retaining the legacy fallback does not validate its accuracy; the ML output remains one evidence source among authentication, identity, reputation, relay and attachments.

## Files changed and tests

- README.md; docs/architecture.md; docs/real-world-validation-corpus.md.
- ml/validation_corpus/{__init__,text,data,fetch,evaluate,report}.py.
- ml/data/sources_real_world_v1.json; ml/data/manifest_real_world_v1.json.
- ml/models/candidate_real_world_v1/{logistic,logistic_sigmoid,linear_svm_sigmoid,multinomial_nb}/metadata.json.
- ml/reports/candidate_real_world_v1_selection.json, its .test-opened marker, candidate_real_world_v1_final.json, and this report.
- tests/test_real_world_corpus.py.

**294 offline tests pass** (217 existing plus 77 new). Tests use invented fixtures, temporary local files and mocked download calls; they require no raw corpus, candidate binary, private email, API key or network. They cover reality tags, overlap, dates/future leakage, duplicates/conflicts, external isolation, artifacts, source diagnostics, all gates, immutable locks, single-use finalization, inactive metadata and protected legacy hashes.

Raw/processed text, temporary runs and candidate binaries stay ignored. No dependencies were added. No model activation, Git commit, remote or push is part of this milestone.

## Remaining limitations and interpretation

SpaPhish is Spanish while most historical fitting data is English; temporal behavior mixes age, language, topic, class-prior and source shifts. Its early phishing support is small and later phishing dominates. The external SMS collection has short text, live-URL selection bias in its original study, and mixed underlying origins. Neither supplies an independent modern English business-email test. BEC coverage is not separately adjudicated. Real provenance is publisher-reported; anonymization and identifier masking alter linguistic clues. Temporal bounds are not cryptographically verified. Exact/template/near screening is practical, not exhaustive. Repeated campaign removal and cap-based fitting alter prevalence. The revealed final corpora are now spent for future tuning; any future improved model needs another untouched external email collection.

See [methodology and reproduction](../../docs/real-world-validation-corpus.md), [source catalog](../data/sources_real_world_v1.json), [locked development results](candidate_real_world_v1_selection.json) and [complete final metrics](candidate_real_world_v1_final.json).
