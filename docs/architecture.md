# Architecture and repository review

## Existing architecture, inspected before changes

The repository contains a Streamlit frontend, an independent Python analysis
backend, local ML artifacts and training code, two original sample EML files,
and an existing WSL virtual environment. No AGENTS.md, tests, dependency manifest,
README, persistent case storage, or Git metadata were present in this checkout.
The `.env` value was not read; its required variable name comes from source code.

`frontend/app.py` is the active, styled Streamlit interface. It writes the
uploaded EML to a temporary file, calls `backend.analyze.analyze_email`, and
retains the latest result in session state. Summary cards and the Overview,
Email Forensics, Threat Intelligence, Attachments, and Raw Evidence tabs render
that result. `frontend/app_backup.py` is an older UI and is left untouched.

`backend/analyze.py` sequences these modules and returns a JSON-compatible dict:

| Module | Responsibility |
| --- | --- |
| `email_parser.py` | MIME parsing, selected headers, text body |
| `header_analyzer.py` | From / Reply-To / Return-Path domain mismatches |
| `auth_analyzer.py` | Reported SPF, DKIM, DMARC Authentication-Results |
| `ioc_extractor.py` | URL, IPv4, email-address, domain regex extraction; file hashing helper |
| `relay_tracer.py` | Received chronology, continuity scores, first public origin candidate |
| `nlp_detector.py` | Local TF-IDF and logistic-regression inference |
| `attachment_analyzer.py` | Decode attachments and compute size and SHA-256 |
| `threat_intel.py` | DNS and RDAP domain lookups |
| `reputation_analyzer.py` | VirusTotal domain, IP and file-hash lookups |
| `geo_analyzer.py` | Candidate infrastructure geolocation via ipwho.is |
| `fusion_engine.py` | Weighted identity/authentication/NLP score plus reputation and relay bonuses |

External lookups use timeouts and report status fields for failures. Demo
domains and non-public IPs are generally skipped. Only attachment hashes are
sent to VirusTotal, not attachment contents. `VT_API_KEY` is loaded with dotenv.

`ml/train_model.py` uses 16 short example messages to train the two local joblib
artifacts. The inspected venv uses Python 3.14.4, Streamlit 1.63.0,
scikit-learn 1.9.0, joblib 1.6.0, dnspython 2.8.0 and python-dotenv 1.2.3.
The baseline offline `test.eml` result was HIGH RISK at 69/100, NLP 58.05%,
three relay hops, and no public origin candidate. The original UI AppTest
completed without exceptions.

## Issues found in the original implementation

- Only the latest result was retained, and only in the current Streamlit session.
- No test suite, reproducible dependency list, or project documentation existed.
- Multipart parsing collects text/plain parts, including text attachments, but
  skips HTML alternatives. HTML-only multipart emails can lose body evidence.
- Authentication trusts reported headers and uses substring matching; a pass
  takes precedence over a conflicting fail. There is no independent signature
  verification or trusted-receiver boundary.
- Relay trust is a continuity heuristic. Selecting the first public IP does not
  prove origin authenticity; the Received chain can contain forged data.
- IOC regexes can capture domain-like filenames and invalid IPv4 values. They do
  not extract IPv6 or track body/header provenance for individual indicators.
- Model loading happens at import time relative to the launch directory. The
  tiny training set has no held-out evaluation or probability calibration.
- DNS/RDAP/VT lookups are sequential and uncached, with fixed per-email limits.
  This can make batches slow and omit enrichment for later indicators.
- Failed enrichment contributes zero reputation points; DNS/RDAP domain-risk
  scores are displayed but not incorporated into the final fusion score.
- Existing dynamic HTML card values are not escaped, and the single-email upload
  handler has no per-file exception display.
- The installed Streamlit emits deprecation warnings for the existing
  `use_container_width` argument, although the original UI still runs.

Persistent cases, correlation-specific normalization, batch error handling,
documentation, and regression tests were addressed at the campaign-correlation
baseline. The analyzer limitations listed above describe that original baseline;
the Real Email Readiness changes below record the subsequent corrections.

## Additive campaign / case integration

- `backend/case_store.py`: local SQLite cases and JSON analysis snapshots. The
  `(case_id, raw_eml_sha256)` primary key prevents duplicate membership, with
  foreign keys, parameterized SQL, transactions, and a 200-email case limit.
- `backend/case_analysis.py`: a batch adapter over the same `analyze_email`
  function, with per-file outcomes, deduplication before expensive lookups,
  size/count limits, and unconditional temporary-directory cleanup.
- `backend/analyzers/campaign_correlator.py`: a pure, offline function over saved
  results. It builds a normalized inverted indicator index, records direct pair
  matches with source paths, caps each evidence family's score, and computes
  candidate connected components above the selected threshold.
- `frontend/case_ui.py`: named case controls, batch upload, saved-email reopening,
  inventory, candidate groups, direct evidence drill-down, shared indicators,
  threshold/filter controls, and JSON export.
- `frontend/app.py`: imports the case views, adds a collapsed case workspace
  below the existing upload flow, and appends a Campaign / Cases tab. Existing
  CSS, cards, single-email analysis, five evidence tabs, and empty state remain.
- `backend/analyze.py`: adds Reply-To, Return-Path, Message-ID and the raw EML
  SHA-256 to the existing `email` metadata. Existing result fields, analyzer
  sequencing, model artifacts, and threat-scoring formula are unchanged.

The correlation score never feeds back into an email's threat score. Stored
snapshots and direct evidence make candidate groups reviewable, including
indirect membership. Common-provider domains and non-public IPs remain visible
as context. Correlation quality is bounded by the original extraction and
trusted-evidence limitations; a shared indicator is not proof of a common actor.


## Real Email Readiness changes

Protected reference: `d83e88d80a6bf8b39760e6d8ed543ca88663b8e2`.

- `email_parser.py` now separates main-body MIME parts from attachments and
  related resources, decodes plain/HTML content with safe fallbacks, and merges
  equivalent alternatives. Distinct HTML text is retained to avoid hiding a
  phishing HTML alternative behind benign plain text. `html_parts` is additive
  transient parser evidence used by the IOC extractor; it is not added to saved
  analysis snapshots or rendered by the UI.
- `ioc_extractor.py` validates IPv4/IPv6 and host syntax, canonicalizes duplicates,
  removes obvious prose/filename noise, and inspects inert HTML reference values
  and literal web URLs. It preserves the existing `urls`, `ips`, `emails`, and
  `domains` lists. Mailbox matching ignores local-part case, consistent with the
  existing correlation policy; this is an investigation convention, not a claim
  about every mail server's delivery rules.
- `nlp_detector.py` resolves the two existing joblib files relative to its source
  file. No training or artifact replacement occurs.
- New parser, IOC, subprocess model-path, and end-to-end compatibility tests
  complement the original suite. External lookups are mocked in integration tests.

Compatibility: corrected body content and normalized/new indicators can change a
fresh email assessment or its correlation matches without changing the model,
fusion weights, or correlation algorithm. The original plain-text sample still
has NLP probability 58.05% and risk 69/100. Attachment hashes remain unchanged.
Saved snapshots stay untouched. Authentication remains a reported-header
heuristic, and relay reconstruction/origin selection still uses its original
IPv4 extraction; the IPv6 improvement here applies to IOC extraction. Readable
HTML extraction is not a full browser/CSS layout engine, and literal URL scanning
does not evaluate dynamically constructed JavaScript destinations.


## Email Authentication Readiness changes

Protected reference: `1ad4d20982e0dccde442a55ac77f4726e44607da`.

`auth_results.py` now parses separate reported checks and identities;
`auth_analyzer.py` selects reporter evidence and exposes confidence/alignment;
`domain_alignment.py` supplies offline public-suffix comparisons shared with the
sender analyzer. The parser retains duplicate From and DKIM-Signature evidence.
Fusion adds behavioral context and uncertainty labels while retaining numeric
weights. The existing UI maps the two new labels to its existing amber style.
The pipeline root schema, case storage, external enrichment, model artifacts,
and body/IOC readiness behavior remain compatible. See
[authentication interpretation and limitations](authentication.md) for details.


## AI Model Readiness changes

Protected reference: `666c31dc9deedc09a3301daaff0b791f33e1ddcd`.

- `ml/fetch_data.py` downloads only reviewed checksum-pinned public CSVs.
- `ml/text.py` provides deterministic readable-text normalization and bands.
- `ml/data_pipeline.py` retains provenance, removes exact/template/near copies,
  quarantines label conflicts and produces sealed seeded partitions.
- `ml/experiment.py` compares four fixed models, performs training-only
  calibration/source-transfer checks, locks validation decisions, and evaluates
  the final holdout exactly once per lock. `ml/report.py` renders frozen metrics.
- `ml/inference.py` gates locally trained research candidates by status,
  normalization hash, dependency version and artifact hash. It is not called by
  the active pipeline because the selected candidate failed source generalization.
- `ml/train_model.py` is safe to import, provides the experiment CLI, and retains
  the original 16 examples behind a separate-output-only demo training function.
- `nlp_detector.py` keeps the original artifacts, scores and schema; only
  malformed/non-text input handling changes. ML still contributes 35% of fusion.

The source manifest and model/report metadata are safe aggregate artifacts. Raw
CSV/processed text, model binaries under `ml/models`, and working runs are ignored.
Original `ml/vectorizer.joblib` and `ml/phishing_model.joblib` remain byte-for-byte
unchanged. No other forensic module or UI behavior is modified. The validation
and final metrics do not establish current-inbox performance: each admitted
source supplies one class, and held-source transfer exposes substantial bias.
See [the model readiness methodology](ai-model-readiness.md) and
[the frozen evaluation report](../ml/reports/AI_MODEL_READINESS.md).

## AI Dataset Generalization v2

`ml/generalization/` layers versioned metadata scrubbing and source-aware data
preparation over the preserved v1 normalizer, hashing/Jaccard duplicate detector,
model factory, calibration and metric functions. It adds leave-one-source-out and
paired-source transfer with fitting-source-only threshold selection, macro and
worst-source statistics, explicit deployment gates and sealed final evaluation.
Raw/derived text and all fitted research binaries stay in ignored paths.

V1 validation/test families are quarantined; any remaining old-source component
is development-only. Fresh final test coverage therefore concerns new sources
only. Synthetic corpora do not satisfy modern real-mail deployment evidence.
Versioned v2 inference is separate from the application loader. The active legacy
artifacts, v1 frozen code/reports, UI, fusion weights and forensic modules are
unchanged. See [v2 methodology](ai-dataset-generalization-v2.md).

## Real-World Validation Corpus

Protected reference: bfa6d958631cdafa3c893d2ca439931f4cc22f71.

`ml/validation_corpus/` reuses the frozen normalization/deduplication primitives,
model factory, calibration, metrics and source-transfer evaluators. It adds
explicit provenance tags, cross-role family quarantine, publisher-date temporal
partitions, separate real/synthetic cohorts and mandatory external evidence
gates. Selection cannot read final or external partitions; a hash-bound lock and
single-use marker precede final evaluation. Candidate metadata never sets active
to true. No production module imports this namespace. Original model artifacts,
active inference, fusion, forensic modules and UI are unchanged.
See [the protocol](real-world-validation-corpus.md).
## AI Honesty & Production Safety

Protected reference: `8cbe862af712e83fbab6c5db2fe089c6e838f9b6`.

`ml/model_policy.py` is the shared trust boundary for active legacy loading,
controlled UI labels, and candidate eligibility. `nlp_detector.py` preserves its
score and verdict fields while adding version, experimental status, validation
status, evidence role and a concise limitation. `frontend/ai_ui.py` displays the
controlled labels and supplies safe unknown defaults for old saved snapshots;
case storage does not migrate or rewrite those snapshots.

The v1 and v2 research loaders now require exact validated states, Boolean
validation and eligibility flags, empty blockers, and complete internally
consistent deployment-gate evidence before a model can be considered eligible.
Eligibility never activates a model. The legacy fallback remains an explicit
byte-pinned compatibility exception and is not eligible as a validated
replacement. All research candidates remain unvalidated and inactive.

`fusion_engine.py` keeps the original 30/35/35 base weights and all numeric
thresholds. Its additive `ai_context` describes the 35% AI weight, exact weighted
points, supporting role, and lack of calibration. Details and the future
weighting recommendation are in
[AI honesty and production safety](ai-honesty-and-production-safety.md).

## AI Fusion Safety

Protected reference: `edef5030b635085eb89ea7711edd03a730bb7d11`.

`backend/fusion_policy.py` defines immutable policy identifiers, the exact
historical v1 calculation, the current 6:7 sender/authentication v2 base, and a
separate model-bound authorization type for any future AI weight. The default
application path supplies no authorization, so experimental and merely eligible
models contribute zero points. `fusion_engine.py` retains existing bonus and
verdict behavior and emits additive policy, weight, contribution and explanation
metadata.

`frontend/ai_ui.py` distinguishes current v2, explicit v1 and metadata-free
legacy snapshots without recalculating them. The case inventory shows the stored
policy, and duplicate raw emails cannot overwrite an earlier case row. Uploading
an EML through the main analyzer produces a fresh v2 result. At the AI Fusion
Safety milestone, storing both versions required separate cases; the later
Reports + Case Management milestone below adds explicit history in one case. Campaign
correlation remains based on indicators and infrastructure, independent of the
risk score. See [AI fusion safety](ai-fusion-safety.md).


## Risk Score Calibration & Evidence Weighting

Protected reference: `7a239173cf28f16551a8571ab6abbd16cae21e57`.

`backend/risk_calibration.py` validates and evaluates the versioned, structured
offline corpus in `data/calibration/fusion_v2_scenarios.json`. Its deterministic
output is frozen in `data/calibration/fusion_v2_results.json` and checked for
exact reproducibility. This evaluation layer calls the production fusion engine
but has no production runtime or network dependency.

`backend/fusion_policy.py` centralizes the unchanged 20/40/60/80 thresholds.
`fusion_engine.py` adds a structured contribution ledger and preserves the
existing v2 arithmetic. `frontend/ai_ui.py` prepares display-safe rows whose
components plus explicit rounding/cap adjustment equal the stored final score;
snapshots without contribution metadata are not recalculated. The existing raw
evidence table remains available. See [risk score calibration](risk-score-calibration.md).


## Reports + Case Management Polish

Protected reference: `917f8d002879037949d8770f0965a1dc33df14cf`.

The prior unversioned case schema is preserved under a version-1 additive
migration. `case_emails` remains the immutable raw-email identity/original
snapshot table; `analysis_versions` stores append-only history. A verified
pre-migration SQLite backup is created before recognized legacy data changes.
Unknown schemas fail closed. Latest-only records preserve the correlation API,
while full history serves timelines, comparison, and reporting.

`backend/case_reporting.py` is a pure offline projection layer. It builds
structured comparisons, allowlisted and redacted schema-v2 reports, canonical
content hashes, sanitized filenames, and standalone printable HTML.
`frontend/case_ui.py` adds metadata editing, archive/restore, search/filter/sort,
timeline, explicit re-analysis, comparison, and dual report downloads in the
existing case areas. `frontend/app.py` gives each fresh run a transient analysis
ID and UTC timestamp for later persistence.

These changes do not alter analysis output, fusion, correlation weights, model
state, or existing snapshot JSON. See
[reports and case management](case-management-and-reports.md).
