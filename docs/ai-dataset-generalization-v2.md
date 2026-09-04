# AI Dataset Generalization v2

Protected checkpoint: `a56e87675657cbfbde3f70be7c440db203bed76a`.

This research extension lives in `ml/generalization/`. The active 16-example
TF-IDF/Logistic Regression artifacts, runtime loader, 50/70-percent bands, UI,
forensic analyzers and evidence-fusion weights are unchanged. The v1 code,
normalizer, sealed reports and unvalidated model metadata are preserved.
No research command activates a model or writes to the active artifact paths.

## Data and provenance

`ml/data/sources_v2.json` records the source review, licenses, actual pinned CSV
assets, admitted labels, rejected alternatives and the predeclared protocol.
`ml/data/manifest_v2.json` records measured counts, quarantine, partitions and a
training-only artifact audit. Raw/derived text and every new model binary remain
ignored. Only local defensive research is performed. CC-BY-SA source text and
learned artifacts are not redistributed by this milestone; attribution is kept
in the recipe. No message link, attachment, script or remote model is fetched.
Kaggle may wrap one requested CSV in a ZIP; the fetcher accepts only that exact
single filename, applies byte limits, decodes text and verifies its SHA-256.

The existing four corpora are joined by TREC-06 legitimate mail, Adjei's synthetic
BEC originals and Kuladeep's synthetic two-class corpus. TREC generic spam is
excluded. Missing labels are never inferred. Publisher release years and a
2026 dataset title are not email sent timestamps. The synthetic corpus supplies
both classes but deliberately uses separate prompts for benign and malicious
text; this is evidence of residual generation/topic bias, not its resolution.

## Leakage boundaries

Only readable subject/body is projected into features. The frozen v1 normalizer
is reused, with v2-only removal of embedded dataset/label metadata, corpus
markers and filenames. CSV severity, confidence, source, label and category
columns never enter text. URL addresses, email addresses, IDs and numbers remain
masked. The same v2 text function is used by research inference.

Exact/template/body components are connected first, then the existing unfitted
hashing cosine >=0.90 and exact word-trigram Jaccard >=0.85 near matcher is applied
to their representatives. Conflicting labels remain attached until the entire
graph closes, so removing an early conflict cannot resurrect a later close copy.
One representative per consistent component is retained with merged provenance.
Short strings, heavy paraphrases and different variants of collapsed components
can evade this practical detector. It is not a guarantee of campaign separation.

The v1 validation/test set has already been examined. Its representatives and
their detected duplicate families are quarantined, including matches in new
sources. Any remaining component with old-source provenance is development-only
(85/15 train/validation). Fresh new-source strata use 70/15/15. Strata with fewer
than eight examples are training-only and reported. Splits are deterministic
under input reordering, seeded at 20260904, and group/hash disjoint.

Consequently, final v2 test results apply only to new-source representatives;
they do not claim fresh test coverage of the four old sources. All old and new
sources receive validation and training-only leave-one-source-out assessment.
There is no rebranding of a reshuffled v1 test as an independent final holdout.

After splitting, a deterministic cap of 1,500 training representatives per
source/class stratum limits source-size dominance. No validation or test examples
are oversampled, capped or used to fit vocabulary. Source balance is improved,
but equal sizes cannot make a synthetic collection representative of real mail.

## Models and source evaluation

Four fixed TF-IDF candidates reuse v1 settings: Logistic Regression, sigmoid
calibrated Logistic Regression, sigmoid calibrated Linear SVM, and Multinomial
Naive Bayes. Word unigrams/bigrams, min_df=2, max_df=0.98, 50,000 maximum features,
sublinear TF, C=1 for linear models and NB alpha=1 are unchanged. No sweep, neural
model, LLM generation API or GPU dependency is introduced. Sigmoid calibration
uses training-only three-fold predictions, with vocabulary fitting inside each
fold and a single final training-only estimator.

For each candidate:

1. Fit on the capped mixed training data, evaluate mixed validation and select
   its review/high bands using validation only.
2. Leave out each corpus in turn. Fit and internally validate using only the
   other sources, including threshold selection and calibration. Purge merged
   provenance crossing the source boundary. Report metrics on the unseen source.
3. Repeat with the predeclared held-out pairs Ling/Nazario,
   SpamAssassin/Nigerian Fraud, and TREC-06/Adjei BEC. Each pair tests transfer of
   both classes. These development stress tests use the training partition only.
4. Compute unweighted per-source macro summaries and worst-source error, alongside
   pooled results and per-source Brier, log loss, ECE and reliability bins.

Phishing precision/F1 are reported as unavailable for single-class source folds;
recall/FNR require positives and FPR requires legitimate samples. Missing metrics
are not zero or safe. Macro summaries record the number of supporting sources.
Thresholds chosen for a fold never see its held-out source, unlike tuning one
shared threshold on validation containing the supposedly unseen source.

A separate text-to-source classifier is a training/validation diagnostic of
remaining corpus identity. It is not used to produce phishing probabilities.
Repeated boilerplate is audited on training text using counts and hashed lines;
ordinary repeated prose is not deleted using information learned from test.

## Deployment gates and final test

Exact values and rationales live in `ml/generalization/evaluate.py:POLICY` and are
copied into the locked selection report before final testing:

| Gate | Required value |
|---|---|
| Mixed validation precision / recall / F1 | >=0.90 / >=0.95 / >=0.90 |
| Mixed validation FPR | <=0.05 |
| Mixed validation Brier / ECE | <=0.10 / <=0.05 |
| Worst validation-source and LOSO class error | <=0.10 |
| LOSO macro recall / FPR | >=0.90 / <=0.05 |
| LOSO macro Brier / worst-source Brier / macro ECE | <=0.10 / <=0.15 / <=0.10 |
| Each paired transfer recall / FPR / F1 | >=0.90 / <=0.05 / >=0.90 |
| Each held-out source support | >=100 independent representatives |
| Source evaluation coverage | Every expected fold evaluated |
| Inference p95 on this CPU | <=25 ms per normalized text |
| Review / high bands | Both inherited validation targets feasible |
| Independently collected modern real sources with both classes | >=2 |
| Representative fresh external real-mail holdout | Required |

These are research eligibility gates, not guarantees of operational safety.
The 10% worst-source ceiling is stricter than v1's 20%; it is not relaxed to
force activation. Current evidence cannot satisfy the real-source/holdout gates.
Temporal evaluation is unavailable because no reliable cross-source chronology
was established. A synthetic release-date comparison is not called temporal
validation. This absence and all metric failures remain explicit.

The existing band selector targets review recall >=95% and FPR <=5% on a fixed
validation grid, with review <=0.70. High requires precision >=98%, FPR <=1%, at
least 20 predictions, and a threshold >=max(0.70, review+0.10). Infeasible targets
remain failures. Candidates are ranked by the predeclared source-first composite
in POLICY, with development gate passes preferred and simplicity/latency ties.

Selection never opens `test.jsonl`. The lock records every candidate, each
threshold, model/code hashes, data-manifest digest and policy. An additional lock
digest stored beside local models detects edits to the lock. Finalization consumes
a single-use marker before reading test and checks partition integrity/disjointness.
All candidate test metrics are reported, but they never change the chosen model
or bands. Do not tune against the now-revealed final research test. A new attempt
after reviewing these results needs genuinely new independent final evidence.

Models are labeled RESEARCH during selection and UNVALIDATED or VALIDATED after
final confirmation. Only the preselected candidate can become eligible after all
development and confirmation gates pass. Eligibility still has no activation
side effect. The v2 research loader rejects unvalidated candidates by default;
`research=True` is an explicit local research opt-in. It preserves
`phishing_probability` (0-100) and `verdict`, adding version, validation status,
bands and input-quality information. Empty text is not evidence about an email.

The active fusion rule is unchanged: AI contributes 0.35 times its probability,
at most 35 risk points. ML alone cannot reach the 40-point SUSPICIOUS threshold.

## Reproduction

Use the pinned existing requirements and project virtual environment. No new
runtime dependency is required. On this working copy, v1 and v2 outputs are
already sealed; commands refuse overwriting research outputs. The report renderer
can safely rerun because it reads aggregate metrics only.

On a fresh checkout with no local data, first recreate the v1 exclusion reference:

```bash
python -m ml.fetch_data
python -m ml.data_pipeline --manifest ml/data/processed/public_email_v1/rebuilt_manifest.json
python -m ml.generalization.fetch
python -m ml.generalization.data --output ml/data/processed/public_email_v2_reproduction --manifest ml/data/processed/public_email_v2_reproduction/rebuilt_manifest.json
python -m ml.generalization.evaluate select --dataset ml/data/processed/public_email_v2_reproduction --run ml/runs/candidate_v2_reproduction --lock ml/runs/candidate_v2_reproduction_selection.json
python -m ml.generalization.evaluate finalize --dataset ml/data/processed/public_email_v2_reproduction --run ml/runs/candidate_v2_reproduction --lock ml/runs/candidate_v2_reproduction_selection.json --destination ml/models/candidate_v2_reproduction --report ml/runs/candidate_v2_reproduction_final.json
python -m unittest discover -s tests
```

Reproduction outputs deliberately stay in ignored locations so the preserved
manifests/reports are not overwritten. Random seeds, counts and partition hashes
should agree; timings, training timestamps and compressed model hashes may vary
by runtime. Reproduction is not permission to tune against a revealed test.
See the aggregate results in `ml/reports/AI_DATASET_GENERALIZATION_V2.md`.
