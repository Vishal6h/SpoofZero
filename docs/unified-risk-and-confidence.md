# Unified risk and evidence confidence — Phase 2

## Scope and architecture

Fresh analyses use `validated_evidence_fusion_v3`. The existing fusion engine
still computes the canonical score once. It normalizes the completed analyzer
outputs, classifies assertion reliability, and attaches a projection of its
existing contribution ledger to `result["final_assessment"]`.

The normalization adapter in `backend/evidence.py` performs no network requests
and calculates no threat score. `backend/evidence_confidence.py` classifies
reliability and coverage without changing points. Individual parsers, enrichment
implementations, the correlation algorithm and model artifacts are unchanged.

```text
Existing analyzers and bounded enrichment
    → existing versioned fusion arithmetic
    → normalize observations and classify confidence
    → bind the existing contribution ledger
    → unified final_assessment
    → Streamlit / immutable JSON snapshots / reports
```

Normalization occurs inside fusion after the existing arithmetic so derived
authentication/behavior context can also be referenced. The adapter can also
normalize an analyzer bundle by itself; before ledger binding, all observations
are contextual or unavailable and carry zero applied points.

## Versioned assessment contract

Existing fields remain available, including `risk_score`, `verdict`,
`contributions`, `score_explanation`, and AI gate metadata. Fresh v3 adds:

| Field | Meaning |
| --- | --- |
| `assessment_schema_version` | Integer 1; covers the additive assessment/finding contract |
| `threat_score` | Canonical rounded score, identical to compatibility `risk_score` |
| `risk_level` | Numeric band under v3 |
| `scoring_version` | Same identifier as `fusion_policy_version` |
| `score_breakdown` | Six category contributions plus the existing rounding/cap adjustment |
| `normalized_findings` | Minimized observations, source references, roles and contribution ownership |
| `evidence_confidence` | Reliability of contributing assertions, counts and explanation |
| `evidence_coverage` | Recorded observation availability and known omissions |
| `review_required`, `review_reasons` | Separate investigator-review status |
| `strongest_findings` | Up to three positive aggregate finding IDs, sorted by contribution |

For example, the maintained demo yields score **75 / 100**, risk level **HIGH**,
contributing-evidence confidence **LOW**, coverage **PARTIAL**, and review
**REQUIRED**. The score is an engineering risk index, not a calibrated
maliciousness probability.

### Canonical score and alias validation

The engine assigns `threat_score` from the already computed `risk_score`.
Neither field is independently calculated. New v3 snapshots are rejected before
storage if score aliases disagree, the band or version markers disagree, the
breakdown total disagrees, or required metadata containers are malformed.

Either version marker claiming v3 requires validation. Conflicting markers
cannot silently downgrade an invalid record to a historical fallback. UI and
reports flag invalid metadata and show no canonical score. This validation is a
contract check, not a cryptographic authenticity check or a recomputation of
every historical ledger.

Numeric scores must be finite, non-Boolean integers in 0–100. Band classification
does not coerce strings or independently round input.

## Exact bands and retained verdicts

| Canonical score | v3 risk level |
| --- | --- |
| 0–20 | LOW |
| 21–40 | GUARDED |
| 41–60 | MEDIUM |
| 61–80 | HIGH |
| 81–100 | CRITICAL |

The legacy `verdict` field remains separate for compatibility, including
`REVIEW REQUIRED` and `INCONCLUSIVE`. Its existing thresholds remain 20, 40,
60 and 80. Consequently, score 80 has new risk level HIGH and retained forensic
verdict CRITICAL. This distinction is intentional; fresh UI risk badges use the
new band, while the old verdict remains available in evidence and reports.

A LOW band does not override incomplete evidence or review status. Score 18,
LOW, PARTIAL coverage and REQUIRED review is a supported, tested result.

## Arithmetic and contribution ownership

For the default zero-AI path, the existing base is:

```text
identity × (6/13) + authentication × (7/13)
+ domain/IP reputation bonus + attachment reputation bonus + relay bonus
→ existing round() → clamp to 0–100
```

The exact multiplication/addition order remains unchanged. Each reputation
observation has the existing raw detection value
`min(100, 20 × malicious + 10 × suspicious)`. Each family takes its maximum
observation, then applies its existing bonus:

| Maximum detection value | Family bonus |
| --- | --- |
| 0 | 0 |
| Greater than 0, below 20 | 5 |
| 20–49 | 10 |
| 50–79 | 15 |
| 80–100 | 20 |

Domain and IP results share one family maximum. Attachment hashes share a
separate maximum. Any number of relay mismatches produces one 10-point bonus.

The six ledger owners are Identity Risk, Authentication Risk, Domain/IP
Reputation Risk, Attachment Reputation Risk, Relay/Infrastructure Anomaly Risk,
and ML Supporting Evidence. A positive aggregate is CONTRIBUTING; its source
observations are CONTEXTUAL references. A VT observation therefore contributes
through its family owner, rather than receiving duplicate per-observation points.

For aggregate owners, `raw_contribution` and `applied_contribution` record the
existing family points **before the global rounding/cap adjustment**. They are
not raw analyzer risk scores. Observation-only findings have null raw
contribution and zero applied contribution. The existing ledger remains
authoritative:

```text
sum(category applied contributions)
+ rounding_and_cap_adjustment
= threat_score
= risk_score
```

The same equation holds for the sum of finding applied contributions. The
breakdown records the pre-adjustment total, adjustment, final total and
`cap_applied`. It does not invent a per-finding allocation of the global cap.

### Explicit v3 input qualification

No weights, valid-provider arithmetic, bonuses, rounding rules or verdict
thresholds changed. V3 additionally rejects malformed base inputs and excludes
malformed or contradictory provider observations from scoring. Boolean,
negative, string or non-finite detection counts are not valid detections;
`status=success` together with a timeout is not successful evidence.

This is an explicit, versioned qualification at the fusion boundary. Valid
provider adapters already enforce this contract. V1/v2 retain their historical
input and scoring behavior. The complete 33-scenario frozen v2 corpus has equal
numeric results, contribution ledgers and verdicts when valid inputs are also
evaluated by v3.

## Normalized finding schema

| Fields | Representation |
| --- | --- |
| `finding_id`, `signal_code`, `category` | Deterministic opaque ID and controlled classification |
| `source_analyzer`, `source_paths` | Analyzer name and paths from the analysis root, e.g. `/reputation/domains/0` |
| `observed_value` | Controlled status, numeric count/signal or short summary; no copied message text |
| `availability` | Independent observation state |
| `evidence_identity` | SHA-256 of a structured identity, separate from the observation ID |
| `confidence`, `confidence_explanation` | HIGH/MEDIUM/LOW/null and a qualified assertion explanation |
| `evidence_role` | CONTRIBUTING, CONTEXTUAL or UNAVAILABLE |
| `rule_id`, `scoring_policy_version`, `ledger_key` | Rule/version and optional aggregate ledger ownership |
| `raw_contribution`, `applied_contribution` | Existing family points or observation-only zero |
| `suppression_reason`, `related_groups` | Deduplication/aggregation explanation and related evidence groups |
| `occurrence_count`, `coverage_scope` | Merged occurrence count and inclusion in the coverage inventory |

Identical observations with the same identity merge their references. IDs do
not depend on provider-list order. A change in observation/availability can
produce a different finding ID while preserving the underlying evidence
identity. Duplicate claims retain their weakest recorded confidence independent
of order.

Related SPF/DMARC, DKIM/DMARC, Return-Path/authentication identity mismatches and
derived behavior are annotated. No new overlap deductions are applied. Repeated
domains, IPs, engines, attachment hashes and relay mismatches remain subject to
the existing maxima/one-time bonus. Campaign relationships stay outside the
individual-email assessment and cannot inherit another email's points.

## Confidence rules

Confidence describes **reliability of the assertion**, not severity, numeric
risk, ML probability, relay trust or a person's location.

| Assertion | Confidence | Qualification |
| --- | --- | --- |
| Complete-byte SHA-256 identity | HIGH | Hash identity does not establish maliciousness or authenticity |
| Complete deterministic local extraction | HIGH | Extracted claims have not been independently verified |
| Partial extraction | LOW | Only retained evidence was inspected |
| Structured sender-domain comparison | MEDIUM | A difference alone does not establish impersonation |
| Receiver-associated reported authentication | MEDIUM | No independent SPF/DKIM/DMARC or header-origin verification |
| Untrusted/conflicting/malformed retained authentication | LOW | Weakly attributable reported claim |
| Successful provider observation | MEDIUM | Provider quality and freshness remain qualified |
| Relay continuity/origin inference | LOW | Header heuristic, not authenticated infrastructure |
| ML inference | LOW | Experimental text signal, not calibrated phishing probability |
| IP geolocation | LOW | Approximate infrastructure location |
| Correlation inference classification | LOW | Relationship context, not maliciousness or common authorship |
| Absent/unusable evidence or unknown authentication provenance | null | No confidence invented |

The assessment-level confidence is the **least certain positive aggregate
contributor**. Contextual HIGH-confidence hashes cannot inflate it. If any
contributor is unclassified, or there are no positive contributors, the
aggregate is unclassified. Counts and scope explain this conservative
aggregation; it is not a probability or weighted confidence score.

## Availability and coverage

Availability includes AVAILABLE, PARTIAL, MISSING, NOT_FOUND, TIMEOUT, ERROR,
SKIPPED, UNAVAILABLE, RATE_LIMITED, MALFORMED, NOT_CHECKED and NOT_APPLICABLE.
Explicit malformed provider error types remain MALFORMED. Missing nested
DNS/RDAP data does not inherit an aggregate success state.

Coverage inventories relevant observations. Any partial/unavailable observation
or known omission makes it PARTIAL. Examples include:

- Known domain/IP or relay-origin IP with no retained VT observation.
- Complete attachment SHA-256 with no retained hash-reputation lookup.
- Known domain with no retained DNS/RDAP observation.
- Missing relay evidence, unknown authentication provenance, or partial parsing.
- Disabled, timed-out, rate-limited, malformed or budget-skipped enrichment.

COMPLETE means the recorded inventory has no known gaps; it never means that all
possible email threats were tested. NOT_APPLICABLE is excluded from gaps (for
example, geolocation when no origin candidate exists). A provider NOT_FOUND is
not a benign verdict. DNS partial failure is not authoritative record absence.

Review is required when the retained verdict needs interpretation, coverage is
partial, or a contributing assertion has LOW/unclassified confidence.

## ML and other non-scoring context

Default ML contribution remains exactly zero. A future numeric contribution
still requires the existing validated model/output gates and a separate
model-metadata-bound, **policy-specific** authorization. A v2 authorization
does not authorize v3. No model is activated, trained or replaced here.

DNS/RDAP aggregate risk, URLs without a supported reputation capability,
geolocation and campaign correlation contribute no numeric points. This phase
adds no network service, query, model weight or geographic threat rule.

## Persistence, privacy and history

SQLite remains at schema version 1. Extended assessments round-trip inside the
existing analysis JSON. The only storage additions are the v3 contract check
and an optional risk-level filter. The filter matches recorded v3 bands among
case history; it does not infer bands from historical scores.

Existing immutable rows and append-only triggers remain intact. Reanalysis
explicitly appends a new version. Historical v1/v2 and metadata-free snapshots
remain readable with stored scores/verdicts; absent unified fields are displayed
as not recorded and are never synthesized.

Normalized observations contain source references, counts, controlled labels
and opaque digests, rather than duplicate mailboxes, bodies, headers, full URLs,
filenames or IOC values. Existing storage privacy filtering remains in force.
Deterministic digests support linkage and are **not encryption or guaranteed
anonymization**. Original source references may point to values removed by
privacy-safe storage; normalized explanations remain readable without them.

## UI and report compatibility

The active Streamlit dashboard displays SpoofZero Threat Score, explicit five-band
colors, neutral unknown styling, scoring version, confidence, coverage and review.
An expander exposes strongest contributors and normalized observations.
The original reconciled score explanation remains available. Historical views
retain their forensic score/verdict and policy disclosure.

Forensic report schema version 3 adds the new assessment fields and strongest
finding details to JSON and printable HTML. Existing report integrity generation
covers those fields. HTML remains escaped. Older v1/v2 snapshots and pre-v3
report objects render with explicit missing metadata. No saved report/export is
rewritten. Report integrity detects accidental content changes; it is not a
digital signature.

## Verification and remaining scope

`tests/test_unified_assessment.py` and `tests/test_evidence_confidence.py`
cover schema/IDs, exact boundaries, arithmetic parity, deduplication,
confidence/severity separation, missing/malformed evidence, version-bound AI
gates, aliases, immutable JSON history, privacy, report integrity/fallbacks,
and a Streamlit LOW/PARTIAL/REQUIRED scenario.

Historical fusion and report fixtures are explicitly pinned to v2. The frozen
calibration generator remains bound to v2, and its checked-in corpus/results are
unchanged. Existing protected-model and security regression tests continue to
run.

Phase 2 does not establish statistical risk calibration, cryptographic email
authentication, improved DNS per-record semantics, geographic attribution, or
campaign maliciousness. A suitable Phase 3 is evidence-quality refinement:
per-record DNS/RDAP availability, clearer source provenance, and reviewed
evaluation fixtures before proposing any additional scoring semantics.
