# SpoofZero

SpoofZero analyzes raw EML files with sender identity checks, reported email
authentication, local NLP classification, IOC extraction, SMTP relay analysis,
IP geolocation, DNS/RDAP and VirusTotal intelligence, attachment hashing, and
an evidence-fusion threat assessment. The existing Streamlit dashboard remains
the single-email investigation interface.

## Run the existing application

From the repository root in WSL / Linux:

```bash
source .venv/bin/activate
python -m streamlit run frontend/app.py
```

For a fresh environment, install `requirements.txt`. Its direct dependency
versions match the existing working virtual environment; the correlation feature
uses only Python's standard library and the already installed Streamlit package.
Keep the existing `ml/vectorizer.joblib` and `ml/phishing_model.joblib` files.
Model paths resolve from the code location, independent of the working directory.
The commands above still use the repository root for Python module discovery and
relative input paths; from another directory, make the repository importable
(for example with `PYTHONPATH`) and supply absolute input paths.

Set `VT_API_KEY` in the environment or the existing `.env` for VirusTotal lookups.
If no key is configured, other analyzers still run and VT reports unavailable.
Do not commit `.env` or investigation databases.

The existing CLI also remains available:

```bash
python -m backend.analyze data/samples/test.eml
```

## Campaign / Case Correlation

1. Open **Campaign / Case Correlation** below the original EML upload area.
2. Create a named case, or select an existing one.
3. Analyze one email with the original **Analyze** button and choose **Add current
   result to case**, or select several EML files and choose **Analyze batch**.
4. Open **Campaign / Cases** in the evidence tabs to inspect candidate groups,
   direct relationships, and the exact shared indicators and their sources.
5. Use **Open email in dashboard** to review any saved analysis in the original
   tabs. **Export case evidence (JSON)** downloads snapshots and correlation data.

Saved cases can also be inspected before opening any single-email result.
A batch accepts up to 25 emails, 10 MiB each; each case supports 200 unique emails.
Identical raw EML bytes are counted once per case, even after renaming the file.
A duplicate skips repeated external lookups. Failures are reported per file and
successful files stay saved. External enrichment still runs sequentially and may
be slow or rate limited; correlation itself makes no network requests.

For a demonstration, batch-upload these three files from `data/samples/campaign`:

- `related_1.eml`
- `related_2.eml`
- `unrelated.eml`

The first two share a normalized URL and sender domain. The third shares only
receiving infrastructure and should remain outside the candidate group at the
default threshold. The fixtures use reserved domains and documentation IPs.

## Storage and interpretation

SQLite stores cases and full analysis snapshots at
`data/cases/spoofzero.sqlite3`. Set `SPOOFZERO_CASE_DB` to change the location.
Snapshots contain email metadata, relay headers, indicators, and intelligence
results, but no raw EML file, message-body field, or attachment payload. Batch
payload files are temporary and are removed after analysis. Case snapshots persist
across Streamlit/browser restarts. This is local, unencrypted storage shared by
sessions using the same database; no multi-user access controls are introduced.

The link score is an explainable heuristic, separate from the existing threat
score. Its maximum is 100 and the default candidate-group threshold is 50.
Only the strongest shared signal in each evidence family contributes:

| Family | Signals and maximum strengths |
| --- | --- |
| Attachment | Non-empty SHA-256: 60 |
| Content | Exact normalized URL: 50; known shared-provider URL: 10 |
| Identity | Exact sender mailbox: 30; exact domain: 10 |
| Infrastructure | Public IP: 10–20; relay/MX/nameserver host: 3; network: 2; ASN: 1 |

Common provider domains, non-public IPs, and empty attachment hashes are visible
as context but contribute zero. Infrastructure alone cannot form a candidate
group. The provider list is a conservative starting point, not an exhaustive
allowlist. Sender mailbox comparisons ignore display names and letter case.
Domains are lowercased, IDNA-normalized, and matched exactly (no guessed
registrable-domain grouping). URL scheme/host casing and default ports normalize;
path case, query order, and fragment are preserved. Invalid IPs, URLs, domains,
and SHA-256 strings are excluded by the correlation layer.

Candidate groups are connected components: A can connect to C through B without
A and C sharing evidence directly. Group IDs are deterministic for their member
set and change if membership changes. Shared evidence, including weak links,
remains inspectable. Correlation does not prove maliciousness or a common actor,
and cannot recover indicators the original parser/extractor missed. DNS, RDAP,
and network intelligence reflect stored lookup snapshots, not a historical
infrastructure verification or a fresh lookup at correlation time.

## Validation

```bash
python -m unittest discover -s tests -v
```

Tests run offline with temporary databases and cover matching/normalization,
context-only evidence, transitive groups, duplicate raw emails, case isolation,
persistence, temporary-file cleanup, batch failures, original analysis output,
and Streamlit single-email and case workflows. Live intelligence-service
availability and browser pixel layout are not validated by these tests.

## Real Email Readiness

The parser now reads plain text and HTML, merges distinct body text without
repeating equivalent alternatives, and retains HTML references for IOC extraction.
Scripts, styles and markup are not treated as readable body text or executed.
Text attachments, named inline files, and attached emails remain separate from
this message's body. Malformed encodings use replacement decoding where possible;
unrecoverable multipart boundaries leave the body empty rather than guessing
that an opaque payload is readable text.

IOCs retain the existing four-list schema. IPv4 and IPv6 are validated and
normalized, URL and mailbox hosts are normalized, and common filename noise is
filtered in prose. HTML link/resource/form targets, literal URLs in CSS/scripts,
refresh targets, and srcset values are inspected without fetching anything.
Relative references resolve only against an explicit absolute HTML base; without
one, scheme-relative references contribute a host only. URL path case, query
order and fragments remain meaningful. Scoped IPv6 interface identifiers are
excluded, and dynamic JavaScript/CSS/browser rendering is not performed.

Fresh analyses can legitimately have different IOCs or NLP probabilities because
HTML evidence is now available and attachment text is no longer mixed into the
body. Model artifacts, the scoring formula, authentication interpretation,
VirusTotal logic and the case-correlation policy are unchanged. Existing saved
snapshots are not migrated; batch deduplication still skips an email already in
that case. Analyze into a new case to retain a refreshed snapshot.

See [the repository architecture review](docs/architecture.md) for the original
module map, findings, and the integration boundaries.


## Email Authentication Readiness

Authentication analysis now preserves individual reports, status values,
identities, source confidence, and offline organizational alignment evidence.
Unknown, malformed, and conflicting results are explicit. PASS does not suppress
suspicious behavior; the current dashboard shows a warning when reported PASS
coexists with sender, AI, reputation, attachment, or relay concerns. Numeric
fusion weights remain unchanged. Low-score uncertain results can now display
INCONCLUSIVE or REVIEW REQUIRED using the existing amber style.

Install the updated `requirements.txt` to include `tldextract==5.3.2`. Its bundled
public-suffix snapshot is used offline, without a network refresh or local cache.
Authentication findings describe parsed reports, not independently verified SPF,
DKIM, or DMARC. Current DNS lookup context remains separate from message evidence.
See [authentication interpretation and compatibility](docs/authentication.md)
for reporter selection, schema additions, scoring details, and exact limitations.


## AI Model Readiness

The public-data experiment is separate from the active 16-example fallback. It
normalizes licensed CSV text, removes duplicate templates before splitting,
compares four lightweight linear/Naive Bayes candidates, calibrates using training
folds, locks model choice and validation thresholds, then evaluates the final
holdout once. Raw/processed email text and candidate binaries are ignored by Git.

The selected research candidate is sigmoid-calibrated Linear SVM. It performs
strongly on the mixed-corpus holdout but fails source-transfer checks, so it is
**not activated**. The original model artifacts and 50/70-percent bands remain
active; neither the UI nor forensic fusion weights changed. Missing or malformed
NLP inputs now receive safe empty-text handling.

See [the complete evaluation report](ml/reports/AI_MODEL_READINESS.md) for source
counts, leakage controls, per-model metrics, calibration, thresholds and the
reason promotion was blocked. [Reproduction and methodology](docs/ai-model-readiness.md)
describes commands, artifact locations and the single-use final-test lock. The
public benchmark's metrics must not be presented as real-inbox accuracy.

## AI Dataset Generalization v2

The isolated v2 research pipeline adds source-aware evaluation, cross-source
duplicate quarantine, source-balanced training caps, per-source calibration and
mandatory generalization gates. New synthetic evidence is labeled explicitly.
The protected legacy model remains active; research candidates are not activated.
See [v2 methodology](docs/ai-dataset-generalization-v2.md) and
[measured results](ml/reports/AI_DATASET_GENERALIZATION_V2.md).

## Real-World Validation Corpus

The isolated research path now supports explicit REAL/SYNTHETIC/UNKNOWN provenance,
forward-time email evaluation, a sealed external SMS holdout, and additional
evidence gates. Only real older emails fit this experiment; synthetic data is
separate post-lock stress evidence. The legacy model remains active and unchanged.
See [methodology and reproduction](docs/real-world-validation-corpus.md) and
[measured results](ml/reports/REAL_WORLD_VALIDATION_CORPUS.md).
