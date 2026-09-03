# AI Model Readiness

Protected reference: `666c31dc9deedc09a3301daaff0b791f33e1ddcd`.

## Inspected baseline and fusion contract

The active fallback has 16 examples (8 per class), 185 word unigram/bigram
TF-IDF features, and Logistic Regression. Its artifact hashes are preserved in
`ml/models/legacy_demo/metadata.json`. The original training script writes directly
to active artifacts and runs on import; the replacement pipeline must not do so.
Model loading already resolves paths relative to source rather than working directory.

Fusion reads `ai_analysis.phishing_probability` on a 0-100 scale and computes
`0.30 * sender + 0.35 * authentication + 0.35 * AI`, followed by existing
reputation, attachment, and relay bonuses. AI alone contributes at most 35 points;
it cannot reach the 40-point SUSPICIOUS or higher malicious-risk thresholds.
AI >=50 also adds a language finding and participates in authentication-PASS
behavioral warnings. Correlation has a separate case-link score and does not
feed numeric points back into this formula. Nothing in this milestone changes
these forensic weights, UI, or saved-case contracts.

The fallback remains active until evaluation and source-generalization gates
support replacement. A stronger result on a confounded historical benchmark
is insufficient evidence for default activation.

## Reproduction and data boundaries

Install `requirements.txt`, then run from the repository root:

```bash
python -m ml.fetch_data
python -m ml.data_pipeline
python -m ml.train_model select
python -m ml.train_model finalize
python -m unittest discover -s tests -v
```

Downloads are limited to the four reviewed Zenodo CSV assets with publisher
MD5 verification; their SHA-256 hashes, licensing, source counts and selection
rules are recorded in `ml/data/manifest.json`. The source recipe is
`ml/data/sources.json`. No remote model, executable archive, attachment payload,
or URL embedded in an email is downloaded. Nothing is sent to external services
while normalizing, deduplicating, fitting, evaluating, or running offline tests.

Raw CSVs, derived JSONL text and experiment/model binaries are ignored by Git.
Metadata, aggregate metrics, recipes, hashes and code are reviewable source files.
Only the legitimate rows of Ling and SpamAssassin are admitted. Their generic
spam rows are excluded, not relabeled as phishing. Nazario and Nigerian Fraud
supply phishing/social-engineering fraud examples. The publisher marks this
release CC BY 4.0; attribution and underlying-source usage notes are in the
manifest. Corpus labels are inherited and are not new expert annotations.
Source: [Phishing Email Curated Datasets](https://zenodo.org/records/8339691).

The prepare/select/finalize commands refuse to overwrite existing output. For an
independent reproduction, pass fresh `--output`/`--manifest` to preparation and
fresh `--run`, `--lock`, `--destination`, and `--report` paths to the two training
phases. Use exactly the same dataset and paths across select/finalize. Do not
reuse the revealed test set to improve parameters or thresholds. Future model
selection after reviewing this report needs a new independent final holdout.
The `.test-opened` marker records that the lock has been consumed, including if a
final evaluation is interrupted. Reproductions should verify counts/split hashes
and metrics; timestamps, timings and compressed artifact hashes may differ across
runtimes. Candidate loading requires the recorded scikit-learn version and exact
normalization code hash.

## Leakage controls

Normalization uses readable subject/body text, Unicode NFKC, inert HTML parsing,
and safe empty-field handling. Features exclude labels, source IDs, sender/date
columns, transport and spam-filter headers, quoted reply lines, collector tokens,
URL destinations, addresses and numerical identifiers. Text is capped at 40,000
characters per field; this cap also applies to candidate inference. Masking can
remove useful cues and does not remove all topical or source bias.

All sources are pooled before deduplication. Exact normalized duplicates are
collapsed; conflicting labels are quarantined. Masked templates and identical
substantive bodies are then grouped, followed by near-duplicate connected
components. The near pass uses an unfitted hashed word-trigram cosine prefilter
(>=0.90) and verifies Jaccard similarity >=0.85. Components retain one deterministic
representative, avoiding both split leakage and repeated-template metric inflation.
Short texts with fewer than eight shingles use exact/template checks only. This
is a practical detector for close copies, not proof that paraphrases, substantially
edited templates, quoted material or campaigns never overlap. No classifier or
fitted TF-IDF vocabulary sees validation/test text during deduplication.

Split assignment is stable under input reordering, seeded at 20260904, and
stratified by source and label (class-only fallback for small test fixtures).
Approximately 70/15/15 percent goes to train/validation/test. Content, template
and component IDs cannot intersect partitions. Original and normalized text stays
in ignored local files; the manifest contains counts and checksums rather than
email examples.

## Model and evaluation protocol

Four predeclared candidates share word unigrams/bigrams, min_df=2, max_df=0.98,
50,000-feature cap, Unicode accent stripping and sublinear TF. Logistic Regression
and Linear SVM use C=1 and balanced class weights; Multinomial Naive Bayes uses
alpha=1. No hyperparameter sweep, transformers, GPU dependencies or deep learning
are used. CPU thread limits and random seeds are fixed.

Calibrated candidates use sigmoid calibration from three-fold out-of-fold
predictions on training data only. TF-IDF lives inside each fold's pipeline,
preventing calibration-fold vocabulary leakage. The final estimator is refitted
on training data only (`ensemble=False`); validation is never used for fitting.
Calibration reports include Brier, log loss, ten-bin reliability data and ECE.
Brier reflects discrimination as well as calibration, so it is not interpreted
alone. See [scikit-learn calibration documentation](https://scikit-learn.org/stable/modules/calibration.html).

For source generalization, two additional training-only experiments fit on one
benign/phishing source pair and assess the other, then reverse the roles. Records
with mixed provenance crossing a holdout boundary are purged. Both held-out pairs
contain both classes. Their worst false-negative/false-positive rate affects
selection and the promotion gate. This stress test is distinct from the sealed
final holdout. A source-ID-only classifier would perfectly predict the retained
labels; therefore a source-balanced external dataset remains a promotion
requirement even when pooled metrics look strong.

Selection uses a predeclared weighted combination of validation F1, recall,
specificity, Brier and worst source-transfer error; simplicity and latency break
ties. Raw accuracy does not decide. All candidate final-test metrics are produced
only after the selected model, artifact hashes, preprocessing code, feature
configuration and thresholds have been written into a lock. Seeing a better
final-test score from another candidate does not switch the selected model.

Threshold search uses only validation: review aims for >=95% phishing recall
and <=5% FPR, restricted to <=0.70; if infeasible, validation F2 is used and
the target failure is explicit. High aims for >=98% precision, <=1% FPR and
at least 20 positive predictions, at least 0.10 above review and no lower than
0.70. Unmet targets are recorded rather than silently claimed. Final-test
thresholds are never tuned. Percent output bands use raw probability boundaries
before display rounding. The operational phishing prevalence is unknown;
benchmark calibration/precision does not automatically transfer to an inbox.

## Integration and fallback

The active `nlp_detector.py` still loads the original two artifacts, returns the
original two-field schema, and retains its 50/70-percent bands. Its only runtime
change safely handles non-dictionary/non-text input; existing valid-text scores
remain unchanged. The old training examples remain reproducible through
`train_legacy_demo(new_directory)` and cannot overwrite the original artifacts.
Importing training code has no training or write side effects.

The separate `ml.inference` API can inspect a locally trained candidate with
`load_candidate(research=True)`. Default loading refuses an unvalidated candidate.
The helper preserves phishing_probability/verdict and adds version, thresholds,
band, status and input-quality fields. Empty input is flagged as no_readable_text;
its mathematical model prior is not evidence about an email. This research helper
is not wired into the application when promotion gates fail. No model-file
auto-discovery silently switches the active model. Fusion weights, campaign
correlation, authentication, geolocation, attachments, VirusTotal and UI are unchanged.
