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
