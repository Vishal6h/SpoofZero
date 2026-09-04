# Real-World Validation Corpus: protocol and reproduction

Protected reference: bfa6d958631cdafa3c893d2ca439931f4cc22f71.

The active model is the original 16-example fallback. This experiment cannot
activate a model. V1/v2 code, reports, model binaries, deployment gates, forensic
modules, UI and fusion behavior remain unchanged. Research is isolated in
ml/validation_corpus/. The fallback is retained for continuity, not because it
has been validated for real inboxes.

## What the inspection established

V1's deduplicated mixed test concealed source-transfer error above its 20% gate.
V2 tightened that ceiling to 10%, added leave-one-source-out (LOSO), source macro
calibration and source identity diagnostics. Its preselected calibrated SVM still
had 66.96% worst-source error and about 96.87% source-classification accuracy.
All v2 final-test phishing examples were synthetic. Those exposed tests cannot
be called fresh external evidence in a later milestone.

The application still loads ml/vectorizer.joblib and ml/phishing_model.joblib
relative to its source location. AI contributes 35% of the initial fusion score,
alongside sender (30%) and authentication (35%), before other evidence bonuses.
AI alone cannot reach the suspicious score boundary. This milestone changes
none of that behavior.

## Source decisions and permitted scope

The complete catalog is ml/data/sources_real_world_v1.json. Measured construction
counts are in ml/data/manifest_real_world_v1.json. Existing v2 decisions remain
documented; newly reviewed sources include SpaPhish, SmishX, Phishing Pot,
realprogrammersusevim/email-dataset, Sting9 and BanglaPhish. The Phishing Codebook
review is corrected: its primary paper identifies the emails as Nazario
2015–2021, so the codebook does not establish an independent source.

- SpaPhish version 5: Lazaro Bustio-Martinez and coauthors,
  [Mendeley DOI 10.17632/hz2d6gz7pc.5](https://data.mendeley.com/datasets/hz2d6gz7pc/5),
  CC-BY-4.0. Authors voluntarily published manually anonymized personal and
  institutional messages; expert majority labels distinguish phishing from
  legitimate mail. Only the plain CSV and JSON schema are obtained.
- SmishX: Yizhu Wang and coauthors,
  [SOUPS 2025 materials](https://github.com/yizhu-joy/SmishX) and
  [paper](https://www.usenix.org/system/files/soups2025-wang.pdf).
  The publisher's repository uses MIT licensing. Its real SMS were relabeled
  from public collections and 22 author-contributed messages. Generic spam is
  excluded, rather than relabeled as phishing. No user-study responses,
  companion code, live URLs, screenshots or crawler are obtained or executed.
- Historical and synthetic text reuse the locally pinned v2 representatives and
  original attribution/usage notes. CC-BY and CC-BY-SA terms remain attached to
  those sources. Downloaded/derived text and learned binaries are not distributed.

A publisher's dataset label is evidence of origin, not independent reannotation.
SpaPhish has both classes from one collection, but its multiple authors are not
counted as independent collections. SmishX has both classes after relabeling,
yet its underlying sources vary and are not identified per row. It is SMS,
not representative business-email evidence. Dates in release metadata are
never substituted for message dates.

## Frozen partition and model design

1. Reuse real v2 training representatives; real v2 validation remains a clearly
   marked historical development diagnostic. Exposed real v2 test families are
   quarantined. V2 had already excluded exposed v1 evaluation families.
2. Assign SpaPhish by its schema-documented DD/MM/YYYY date: through 2022 to
   training, 2023 to threshold validation, 2024–2025 to final temporal test.
   Missing/invalid dates are excluded from fitting and temporal claims and
   scored only as a post-lock diagnostic.
3. Keep every admitted SmishX record external. Its source never enters fitting,
   calibration, threshold selection, model selection, or source diagnostics.
4. Keep all synthetic v2 records in a post-lock stress partition. None enter
   fitting or deployment evidence. These records were exposed in previous
   research and are not called a fresh synthetic benchmark.
5. Globally normalize and deduplicate before sealing. Preserve prior family
   identifiers. Close exact, template/body and near-duplicate components before
   deciding whether to retain or quarantine them. A family spanning dates,
   development/evaluation roles, external sources, conflicting labels, or a
   protected old test is quarantined in full. Mixed-origin tags become UNKNOWN.
6. Fit the same four fixed TF-IDF candidates, using training-only calibration:
   LR, sigmoid-calibrated LR, sigmoid-calibrated Linear SVM, and MNB. The inherited
   1,500-representative source/class cap is applied after splitting. No neural
   models, GPU dependencies, hyperparameter search or synthetic augmentation.
7. Choose per-candidate review/high thresholds using only SpaPhish 2023. Mixed
   validation reports combine that later slice with historical development
   validation. The mixed slice is not a chronological test. LOSO and paired
   unseen-source transfer use training records only, with thresholds learned
   from internal validation among the fitting sources.
8. Use the inherited source-aware ranking. Freeze all candidate binaries,
   thresholds, code hashes, policies, data-manifest hash and the selected name.
   Only then read final temporal, external, unknown-date and synthetic partitions.
   Test results cannot switch the selected model or thresholds.

Data preparation must parse external text mechanically for normalization and
cross-source contamination screening. This is distinct from opening it for
model evaluation: no external vocabulary, performance, feature selection,
learned preprocessing or tuning is used before the selection lock. Only schema,
provenance, label/date aggregates and static duplicate checks inform admission.

Historical collection bounds use the publisher compilation's conservative
1995–2022 envelope. SpaPhish supplies documented message dates. The temporal
claim is conditional on these reported dates/bounds; delivery timestamps were
not independently verified, and sender-provided dates may be inaccurate.
This is forward-time evaluation within SpaPhish, not an independent email source.
SmishX is the separate, source-independent SMS transfer evaluation.

## Leakage and source identity

The new normalizer layers static label-prefix, folder-path, generator-marker and
injected-header removal over frozen v1/v2 readable text and identifier masking.
Only subject/body enter features. It never uses Label, source, filenames, dates,
persuasion annotations, annotator explanations, attachment metadata or reality
tags as features. All links remain inert. No attachments or harmful payloads are
downloaded or executed.

Unfitted hashing and inherited trigram/Jaccard near matching find obvious
variants; they do not prove that every semantic paraphrase has been found.
Coarse representatives rather than every original pair are compared. Global
cross-period quarantine removes entire recurring campaigns and can make the
remaining temporal distribution less operationally realistic. Static scrubbing
can also remove useful content if a genuine email resembles a wrapper.

A separate TF-IDF/LR diagnostic predicts source from normalized development
text. Its accuracy, balanced accuracy and majority-source baseline are reported.
Accuracy above 90% is flagged as strong remaining source predictability.
Language/topic differences can explain this as well as collection artifacts.
It does not affect production inference or select phishing features. Repeated
training-line audits publish hashes and counts, never raw message snippets.

## Deployment gates

All v2 gates are inherited unchanged, including:

- Mixed validation: precision >=0.90, recall >=0.95, F1 >=0.90, FPR <=0.05,
  Brier <=0.10, ECE <=0.05 and worst-source class error <=0.10.
- LOSO: worst error <=0.10, macro recall >=0.90, macro FPR <=0.05,
  macro Brier <=0.10, worst Brier <=0.15 and macro ECE <=0.10.
- Paired transfer: minimum recall >=0.90, maximum FPR <=0.05 and minimum F1 >=0.90.
- At least 100 representatives per held-out source; all source folds evaluated;
  at least two independent modern real-email collections containing both classes;
  representative external holdout required.
- Inference p95 <=25 ms; both review and high-band validation targets feasible.
  Review targets recall >=0.95/FPR <=0.05. High targets precision >=0.98/FPR <=0.01
  with >=20 positive predictions and a threshold >=0.70 and >=review+0.10.

Additional requirements are fixed before evaluation:

- Temporal test and external holdout each independently require precision >=0.90,
  recall >=0.95, F1 >=0.90, FPR <=0.05, Brier <=0.10, ECE <=0.05 and
  worst-source error <=0.10.
- At least 100 modern (2024 onward) real phishing **email** representatives.
- At most 50% of malicious deployment evidence synthetic; at most 10% UNKNOWN.
  Zero synthetic examples cannot compensate for missing real-email evidence.
- External support of at least 100 real emails per class. SMS does not count.
- Later threshold validation has at least 20 examples per class.

Missing/unsupported metrics fail closed. Single-class cohorts use null for
unsupported discrimination metrics, not invented perfect scores. These support
floors are not confidence guarantees. Only the preselected candidate can become
VALIDATED if every inherited and additional gate passes. Its status would be
“VALIDATED — eligible for activation review”; active remains false in all cases.
This milestone provides no activation command or production loader integration.

## Reproduction

Run from the repository root with the existing environment. All imports resolve
artifact paths relative to the repository; installed dependencies are unchanged.

~~~bash
.venv/bin/python -m ml.validation_corpus.fetch
.venv/bin/python -m ml.validation_corpus.data
.venv/bin/python -m ml.validation_corpus.evaluate select
.venv/bin/python -m ml.validation_corpus.evaluate finalize
.venv/bin/python -m ml.validation_corpus.report --test-count 294
.venv/bin/python -m unittest discover -s tests -v
~~~

The default real_world_v1 corpus/run/report names are immutable and already used.
To reproduce without overwriting frozen results, use a fresh checkout of the
source plus the preserved recipe and prerequisite v2 data, or distinct paths:

~~~bash
.venv/bin/python -m ml.validation_corpus.data --destination ml/data/processed/real_world_reproduction
.venv/bin/python -m ml.validation_corpus.evaluate select --dataset ml/data/processed/real_world_reproduction --run ml/runs/real_world_reproduction --lock ml/runs/real_world_reproduction_selection.json
.venv/bin/python -m ml.validation_corpus.evaluate finalize --dataset ml/data/processed/real_world_reproduction --run ml/runs/real_world_reproduction --lock ml/runs/real_world_reproduction_selection.json --destination ml/models/real_world_reproduction --report ml/runs/real_world_reproduction_final.json
~~~

Data preparation currently also writes the aggregate manifest to its canonical
path; its deterministic content should match for the same pinned inputs. The
source-normalization version and candidate code hashes remain those of the
published experiment. A rerun of an already revealed test is reproduction only,
never a new unbiased validation. Do not erase the single-use .test-opened marker
or edit a lock to retry a partially exposed evaluation.

The prerequisite v2 processed corpus is reconstructed using
[the v2 recipe](ai-dataset-generalization-v2.md), which in turn references v1.
There is no need to refit or rerun either frozen older experiment. Downloads are
explicitly separated from offline preparation, fitting and testing.

The downloader permits only the three reviewed CSV/JSON assets and verifies
size and SHA-256. The SpaPhish release is actually comma-separated despite the
landing page describing semicolons; the pinned schema specifies day-first dates.
Unknown new versions must be reviewed as new corpora, not accepted silently.

## Artifacts

- Tracked: source catalog, aggregate manifest, source/evaluation code, test code,
  candidate metadata, frozen selection/final reports and methodology.
- Ignored: ml/data/raw/real_world_v1, ml/data/processed/real_world_v1,
  ml/runs/candidate_real_world_v1 and candidate model.joblib files.
- Preserved: production modules, original model files, all v1/v2 code and reports,
  .env, secrets, local databases, private email artifacts and exports.

The full measured report is
[REAL_WORLD_VALIDATION_CORPUS.md](../ml/reports/REAL_WORLD_VALIDATION_CORPUS.md).
