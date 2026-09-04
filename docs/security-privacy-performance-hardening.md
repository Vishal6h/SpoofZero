# Security, privacy, performance, and failure hardening

Protected reference: `1bff7273a95e1edb5a271d1b70f9cdc6dcb23d75`.

## Risks found and boundaries added

Before this milestone, the single-file upload had no size or exception boundary, MIME
traversal and decoded content were unbounded, attachment names were used as supplied,
and a failed external check could surface raw exception text or abort analysis.
DNS transport failure could resemble a domain with no records. VirusTotal, RDAP,
DNS, and geolocation were uncached and largely sequential. Repeated attachment
hashes could cause repeated VirusTotal calls. SQLite creation relied on the host's
default permissions, and new snapshots accepted unexpected body/payload fields.

SpoofZero now reads an EML through one shared bounded loader. It never executes an
attachment, invokes a shell command with email data, opens an extracted URL, renders
message HTML, or uploads an attachment. VirusTotal attachment reputation remains a
SHA-256 lookup only.

## Resource limits

| Resource | Limit | Behavior |
| --- | ---: | --- |
| Raw EML | 10 MiB | Upload rejected before parsing |
| MIME parts | 200 | Message rejected |
| MIME nesting | 20 levels | Message rejected |
| Attachments | 50 | Excess entries skipped and reported |
| One decoded attachment | 5 MiB | Skipped; no partial hash |
| Total decoded attachments | 8 MiB | Remaining data skipped |
| Retained readable body/HTML text | 1 MiB UTF-8 | Truncated and marked PARTIAL |
| HTTP JSON response | 2 MiB | Rejected as malformed/excessive |
| HTTP concurrency | 4 workers process-wide | Bounded semaphore |
| HTTP attempts | 2 maximum | One bounded retry for transient failures |
| Attachment hash requests | 10 unique hashes/analysis | Remaining hashes UNKNOWN |

The complete EML is already held by Streamlit's upload component, but SpoofZero
does not copy more than 10 MiB into its parser. MIME data is parsed inertly.
Attachment decoding is preflighted conservatively; skipped content never receives
a misleading partial-file hash.

## External evidence states

Every hardened service result retains compatible lowercase `status` fields and
adds one of `SUCCESS`, `UNAVAILABLE`, `TIMEOUT`, `RATE_LIMITED`,
`NOT_FOUND`, `ERROR`, or `SKIPPED` as `service_status`. Network failure,
malformed JSON, incomplete VirusTotal data, authorization failure, and unavailable
DNS produce UNKNOWN evidence. They never produce a safe verdict.

Timeouts, connection failures, and HTTP 5xx responses receive at most one retry
with a 200 ms exponential-backoff step. HTTP 401, 403, 404, and 429 are not
retried. A VirusTotal 429 starts a 60-second in-process cooldown so subsequent IOC
requests do not immediately repeat the failure. The helper never returns or logs
response bodies, request URLs, authorization headers, or API keys.

Independent domain intelligence, domain/IP reputation, attachment-hash reputation,
and geolocation jobs run through four bounded workers. A service exception becomes
structured unavailable evidence while local parsing, authentication, relay, model,
and fusion work continue. The UI says **Some evidence could not be checked** and
does not present an availability failure as “safe.”

## Cache policy

Caches are in-memory, bounded, thread-safe, and disappear when the process exits.
Cache keys are SHA-256 digests of service and normalized IOC identity; plaintext
credentials are never keys.

| Evidence | Success/not-found TTL | Failure TTL |
| --- | ---: | ---: |
| VirusTotal | 5 minutes | 20 seconds |
| DNS | 5 minutes | 20 seconds |
| RDAP | 15 minutes | 20 seconds |
| IP geolocation | 15 minutes | 20 seconds |

Short TTLs prevent old reputation from becoming a permanent current conclusion.
Saved cases still preserve the time-specific result that existed when the immutable
analysis snapshot was recorded.

## Privacy and local persistence

New case snapshots always remove raw message bodies, HTML bodies, raw EML fields,
attachment payloads, environment values, API keys, credentials, passwords, bearer
tokens, and secret query values. Standard mode retains the subject, addressing
metadata, IOC values, attachment names, hashes, authentication, relay, reputation,
model metadata, stored score, policy, and contribution ledger.

Optional **Privacy-safe case storage** also removes subject, full mailbox headers,
message ID, mailbox IOCs, and original attachment filenames. It retains raw-email
and attachment hashes, domains, authentication, relay/infrastructure, reputation,
scores, and policy metadata. This reduces correlation detail and is intentionally
an investigator choice. Existing historical rows are never rewritten.

SQLite and migration backups are local and are not encrypted at rest. On POSIX,
new database and backup files use mode `0600`; newly created private database
directories use `0700`. Relative configured database paths are anchored to the
project instead of the launch directory. Database symlinks are refused. Corrupt
databases produce a safe error and are not rewritten. The versioned backup,
transaction, immutable triggers, and historical migration behavior remain.

The Streamlit session can retain the current analysis until the user selects
**Clear current session evidence** or the process/session ends. Investigator-supplied
report body text is transient session input. It is never written to the case
database by the report feature.

## Safe observability

Operational events are JSON with an allowlist: event, analyzer, analysis ID, case
ID, duration, service status, cache hit, and attempt count. Invalid/control-bearing
identifiers become `unavailable`. The logging API has no body, attachment, URL,
header, credential, or exception-text field. Host logging configuration and
retention remain deployment responsibilities.

## Performance measurement

The benchmark uses `data/samples/test.eml`, performs 30 warmed runs, and mocks
every external service. It measures local parse/analyzer/fusion overhead rather
than internet performance:

```bash
.venv/bin/python scripts/benchmark_hardening.py
```

The pre-change run measured median **3.005 ms**, p95 **3.591 ms** (30 runs).
The hardened run measured median **4.149 ms**, p95 **4.824 ms**, minimum **3.486 ms**, and maximum **4.840 ms** (30 runs). Against the same pre-change method, median overhead was **1.144 ms** and p95 overhead was **1.233 ms**. These small-run figures characterize local regression overhead only. Synthetic concurrency
and cache tests prove at least two independent jobs overlap while never exceeding
four workers. Duplicate attachment hashes are one request per unique SHA-256; a
second identical cached HTTP lookup executes zero external requests. No claim is
made about live-service latency because live services were not benchmarked.

## Public deployment requirements

This milestone does not deploy SpoofZero. A public service still needs:

- HTTPS termination, HSTS, and suitable browser security headers at a maintained
  reverse proxy;
- user authentication, authorization, case isolation, and administrative controls;
- a production secret manager with API keys outside source, images, logs, and
  client-side state;
- proxy and application upload limits aligned with the limits above;
- per-user/IP rate limiting, abuse prevention, quotas, and bounded worker queues;
- reviewed Streamlit session/cookie settings and CSRF/origin protections;
- an isolated database/object store with backups, monitoring, access control, and
  an evidence retention/deletion policy;
- malware-safe download handling, content disposition, and an incident-response
  process;
- centralized redacted logging, metrics, alerting, dependency patching, and restore
  exercises.

Streamlit alone does not supply all of these production security controls.
