# Reports and case-management polish

Protected reference: `917f8d002879037949d8770f0965a1dc33df14cf`.

## Storage and migration

The original case database was unversioned: SQLite `user_version=0`, a
`cases(case_id, name, created_at)` table, and one `case_emails` row for each
case/raw-EML SHA-256 pair. That layout could neither describe/archive a case nor
retain intentional re-analysis.

The additive schema is version 1. It keeps both original tables and every
original column. It adds `description`, `updated_at`, and `archived` to
`cases`, plus an `analysis_versions` table:

```text
(case_id, raw email SHA-256) -> immutable email evidence identity
    analysis_id, version 1, recorded timestamp, filename, JSON snapshot
    analysis_id, version 2, recorded timestamp, filename, JSON snapshot
    ...
```

Opening a recognized version-0 database performs one transactionally locked
migration. Before changing the schema, SpoofZero creates a SQLite backup beside
the database with a `.pre-v1-<random>.bak` suffix and verifies it with
`PRAGMA integrity_check`. The original `case_emails.analysis_json` text is
copied without deserializing or rewriting it. Its corresponding migrated history
record receives a deterministic identifier. Unknown schema versions or column
layouts fail closed before modification.

Database triggers reject updates and deletes on both evidence tables. The public
API only appends. Cases can be renamed and archived/restored; archiving hides the
case by default and blocks new evidence while retaining every row. Permanent case
or evidence deletion is not exposed.

The backup and working database are local, ignored, unencrypted files. They may
contain investigative metadata and require normal host access controls and
backup retention practices.

## Analysis history

A default duplicate save still returns the existing latest snapshot and skips
new external lookups. This preserves existing automation and avoids accidental
history inflation. An investigator must explicitly select the new-version
control after running **Analyze** again, or enable explicit re-analysis for a
batch. Each distinct raw payload is analyzed at most once during one batch.

Every version retains its analysis identifier, raw-EML SHA-256, recorded UTC
timestamp, original first-analysis timestamp, filename, complete forensic
snapshot, fusion-policy label, model metadata, and stored score. Version numbers
are assigned transactionally. Reusing an analysis ID is idempotent only for
exactly the same raw identity and JSON; attempts to bind it to other evidence
fail.

`list_analyses` remains the compatibility view and now returns the latest
version of each distinct raw email. `list_analysis_history` returns all versions.
Correlation deliberately consumes the compatibility view, so stale versions do
not duplicate indicators or change group membership. Reports and comparison use
the complete history.

The prior `analyzed_at` value represented when a snapshot was saved. A migrated
record preserves that exact timestamp because no independent analysis-run time
was recorded in the old schema. Fresh dashboard analyses now receive a run ID and
UTC timestamp before saving.

## Case discovery

Cases support an optional 1,000-character description and show created/updated
timestamps, unique-email count, analysis-version count, highest recorded risk,
and archive state. Search is case-insensitive across case ID, name, description,
saved subjects, and visible senders. Filters cover exact stored verdict, sender
or IOC domain substring, UTC recorded-analysis date range, archive state, and
presence/absence of a candidate correlation group at the default threshold.

Sort choices are newest creation, oldest creation, highest risk across preserved
history, and most recently updated. Correlation filtering uses only the latest
analysis per email. Date filtering uses recorded UTC analysis times rather than
the untrusted message Date header.

## Comparison and correlation

Any two versions or two different saved emails can be compared. The structured
comparison includes score, verdict, fusion policy, visible sender, sender
findings, SPF/DKIM/DMARC, AI score/validation, URLs, domains, IPs, attachment
hashes, relay reconstruction, domain/IP reputation, and attachment reputation.
It separately lists exact shared senders, sender domains, URLs, domains, IPs, and
attachment hashes.

The existing correlation algorithm and weights are unchanged. Cases and reports
show related latest emails, direct pair scores, contributing evidence, candidate
groups, and shared indicators. Every comparison/report states that shared
evidence does not prove attacker identity, authorship, or common control.

## Forensic reports

Two offline formats are generated from an allowlisted projection of stored
evidence:

1. deterministic-key-order JSON for downstream processing;
2. standalone UTF-8 HTML with print styling, suitable for browser printing or
   later PDF generation.

Both use report schema `spoofzero.forensic-report`, version 2, and include:

- report/case identity and generated UTC timestamp;
- every selected analysis ID, version, original/current timestamps, filename,
  and raw-email SHA-256;
- executive summary, stored score/verdict/policy, contribution ledger, and reasons;
- sender identity and reported SPF/DKIM/DMARC evidence;
- IOC summary and relay reconstruction;
- stored origin/geolocation, DNS/RDAP, and threat-intelligence evidence;
- stored VirusTotal domain/IP and attachment-hash reputation;
- attachment metadata and SHA-256 values;
- AI score, model status, validation status, role, and numeric contribution;
- campaign groups, direct relationships, scores, and shared evidence;
- limitations and confidence notes.

The HTML report escapes every displayed value, contains no script or external
resource, opens detailed evidence sections by default, and includes print page
rules. It displays the checksum and clearly says the checksum is not a legal
digital signature.

## Integrity and privacy

A SHA-256 is calculated over canonical UTF-8 JSON containing the complete
forensic record except its own `integrity` object. The integrity object records
algorithm, scope, digest, and `legal_digital_signature=false`. Verification
detects subsequent changes. The checksum supports content-integrity checks; it
does not authenticate the investigator, host, or collection process.

Export filenames are lowercase, ASCII, bounded, path-free names derived from a
sanitized case label and short case ID. Windows reserved names, path separators,
and unsupported extensions are handled safely.

Report data is selected from known analysis fields. Keys associated with API
keys, credentials, passwords, authorization, or tokens are removed; recognizable
credential assignments, bearer tokens, and local system paths are redacted.
Unknown body/raw-EML/environment keys are excluded. Full raw EML and attachment
payloads are never exported.

Default handling is `summary_only`. An investigator may explicitly select one
analysis and supply readable body text for the current download. That text is
neither read from storage automatically nor persisted by SpoofZero; it is
bounded and passed through credential/path redaction. This option does not add
raw MIME bytes or attachment contents.

Every report states exactly:

> IP geolocation represents approximate infrastructure location and does not identify a person's physical location.

> Experimental/unvalidated AI signals are supporting evidence and do not contribute numerically under the current fusion policy.

## UI workflow

The existing professional dashboard remains the entry point. Its collapsed case
workspace now follows:

```text
Analyze Email
    -> Save to Case
    -> Case Timeline / Evidence
    -> Compare / Correlate
    -> Export JSON or printable HTML
```

Search/filter controls and case metadata are inside expanders to avoid crowding
the primary analysis surface. The Campaign / Cases tab adds the history count,
latest/historical labels, comparison controls, relationship evidence, and report
downloads.

## Compatibility and limitations

No forensic analyzer, fusion formula, verdict threshold, correlation algorithm,
model loader, or candidate metadata changed. Fresh analysis still uses
`validated_evidence_fusion_v2`; unvalidated AI remains zero-weighted. Old
snapshots report their stored score and policy metadata without recalculation.

Search and report generation currently load a case's JSON snapshots locally and
do not paginate. Very large histories can therefore increase UI latency and
report size. Case databases and migration backups are not encrypted or
multi-user. The HTML is designed for print/PDF conversion but SpoofZero does not
yet create PDF files directly. Checksums detect record modification but are not
signatures or chain-of-custody attestation. Correlation remains heuristic and
enrichment data remains a time-specific stored lookup snapshot.


## Verification and changed files

The complete offline suite passed **372 tests**. New coverage exercises fresh and
legacy database schemas, migration backup fidelity, append-only history,
idempotent identifiers, duplicate and explicit re-analysis, latest selection,
case discovery, mixed-policy comparison, JSON/HTML content, canonical checksum
verification, filename and secret handling, explicit body handling, AI and
geolocation disclosures, correlation compatibility, and the Streamlit history
workflow.

Changed implementation files:

- `backend/case_store.py`: schema v1, migration/backup, case metadata,
  archive/restore, discovery, and immutable analysis history.
- `backend/case_analysis.py`: explicit batch re-analysis with default duplicate
  reuse.
- `backend/case_reporting.py`: comparison, JSON/HTML reports, canonical
  integrity checks, privacy filtering, and safe filenames.
- `frontend/app.py`: fresh analysis IDs and UTC timestamps.
- `frontend/case_ui.py`: searchable case workflow, timeline, comparison,
  correlation integration, and report downloads.

Tests and documentation:

- `tests/test_case_reporting.py`
- `tests/test_case_ui.py`
- `README.md`
- `docs/architecture.md`
- `docs/ai-fusion-safety.md`
- `docs/case-management-and-reports.md`

`validated_evidence_fusion_v2`, all verdict thresholds, the correlation
algorithm, the legacy model artifacts, active inference, and all research
candidate states are unchanged.
