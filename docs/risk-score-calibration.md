# Risk score calibration and evidence weighting

Protected reference: `7a239173cf28f16551a8571ab6abbd16cae21e57`.

## Scope and interpretation

This milestone evaluates the deterministic `validated_evidence_fusion_v2`
engineering policy. It is not statistical probability calibration and the output
remains a **forensic risk score**, not a probability that an email is phishing.
The expected LOW, REVIEW, HIGH, and CRITICAL labels are review targets chosen for
this engineering exercise. They are not real-world ground truth.

No model was trained or activated. Experimental and unvalidated AI remains
visible as qualitative supporting evidence and contributes exactly zero numeric
points. No saved case is migrated or recalculated.

## Exact policy evaluated

With sender risk `S` and reported-authentication risk `A`, each bounded to
0-100, the current base is:

```text
sender contribution         = (6 / 13) * S
authentication contribution = (7 / 13) * A
AI contribution             = 0

raw total = sender contribution
          + authentication contribution
          + reputation bonus
          + attachment bonus
          + relay bonus

final score = clamp(0, 100, round(raw total))
```

The base weights are 46.1538% sender identity, 53.8462% authentication, and
0% unvalidated AI. They sum to 100%.

Domain/IP reputation and attachment reputation each use the strongest successful
item. An item's raw detection value is
`min(100, 20 * malicious + 10 * suspicious)`. Each family then adds 0, 5, 10,
15, or 20 points for raw values 0, greater than 0, at least 20, at least 50, and
at least 80. One or more relay-chain mismatches add 10 points once.

Numeric thresholds remain:

| Final score | Numeric verdict |
| ---: | --- |
| 0-19 | LIKELY SAFE, unless incomplete authentication produces INCONCLUSIVE or authenticated suspicious behavior produces REVIEW REQUIRED |
| 20-39 | LOW RISK |
| 40-59 | SUSPICIOUS |
| 60-79 | HIGH RISK |
| 80-100 | CRITICAL |

The special below-20 verdicts are qualitative review controls and add no points.

## Reproducible corpus

The corpus contains 33 structured scenarios. Thirty-two are controlled synthetic
fusion inputs and one records aggregate analyzer outputs from the repository's
safe `data/samples/test.eml`. It contains no message bodies, private email,
secrets, malware, executable content, or network-fetched data. Randomness is not
used.

Coverage includes legitimate business mail, newsletter/service mail, benign
third-party delivery, Reply-To and Return-Path differences, SPF/DKIM/DMARC
failures, missing and malformed authentication, suspicious URLs without
reputation, domain/IP reputation, attachment-hash reputation, relay mismatches,
authenticated BEC-style language, obvious spoofing, multiple weak and strong
signals, isolated strong signals, duplicate evidence, cross-family bonus
stacking, score caps, threshold boundaries, and the maintained demo.


Synthetic stress cases deliberately vary aggregate inputs independently of header
status and include sender scores above the current sender analyzer's ordinary
70-point maximum. These cases exercise the fusion API's bounds, not a claimed
real-mail distribution. The safe demo's scores, status values, and untrusted
reporter designation are checked against the actual offline analyzers.

Reproduce the frozen JSON report from the repository root:

```bash
python -m backend.risk_calibration \
  --output data/calibration/fusion_v2_results.json
python -m unittest discover -s tests -p 'test_risk_calibration.py' -v
```

The regression test rebuilds the report and requires exact equality with the
frozen result.

## Results

Scores ranged from 0 to 100, with mean 31.6667, median 20, and population
standard deviation 30.5631.

| Score band | Scenarios |
| --- | ---: |
| 0-19 | 16 |
| 20-39 | 6 |
| 40-59 | 4 |
| 60-79 | 3 |
| 80-100 | 4 |

| Verdict | Scenarios |
| --- | ---: |
| LIKELY SAFE | 6 |
| INCONCLUSIVE | 2 |
| REVIEW REQUIRED | 8 |
| LOW RISK | 6 |
| SUSPICIOUS | 4 |
| HIGH RISK | 3 |
| CRITICAL | 4 |

The high-level target distribution was LOW 3, REVIEW 17, HIGH 9, and CRITICAL 4.
Actual mapped classes were LOW 6, REVIEW 20, HIGH 3, and CRITICAL 4. Twenty-two
scenarios matched their engineering target. One was higher and ten were lower.
This is a policy-behavior comparison on a designed set, so these counts are not
accuracy, false-positive-rate, or false-negative-rate estimates.

The one higher case was benign third-party infrastructure: target LOW, score 14,
verdict REVIEW REQUIRED. Authentication PASS plus a nonzero sender-identity
difference intentionally triggers the existing qualitative behavioral review
warning. This exposes a specificity trade-off for legitimate mailing providers.

The ten lower cases were:

| Scenarios | Observed result | Finding |
| --- | --- | --- |
| SPF failure; DKIM failure | 16, LIKELY SAFE | An isolated 30-point authentication input remains below 20 after weighting. |
| Suspicious URL without reputation | 0, LIKELY SAFE | Raw IOC suspiciousness has no direct fusion input. |
| Malicious reputation and duplicate variant | 20, LOW RISK | One reputation family is capped at 20. |
| Malicious attachment reputation and duplicate variant | 20, LOW RISK | One attachment family is capped at 20. |
| Maximum authentication alone | 54, SUSPICIOUS | A single base family cannot reach HIGH. |
| Maximum sender identity alone | 46, SUSPICIOUS | A single base family cannot reach HIGH. |
| Near-low target | 18, LIKELY SAFE | Rounding remains below the first numeric boundary. |

Several repeated variants appear separately because duplicate handling is itself
under test. The results reflect conservative corroboration requirements, plus a
real gap for raw suspicious URLs and a review-label gap for isolated SPF/DKIM
failures. Those gaps should be evaluated with an independently labeled,
representative email corpus before changing numeric policy.

Ten scenarios were within three points of a numeric threshold: Reply-To mismatch,
DMARC failure, single and duplicated reputation evidence, single and duplicated
attachment evidence, multiple weak signals, and the three designed 20/40/60
boundary cases. Boundary tests confirm scores 20, 40, 60, and 80 map to LOW RISK,
SUSPICIOUS, HIGH RISK, and CRITICAL respectively.

## Sensitivity and dominance

Holding every other input at zero gives:

| Input | Sender-only final | Authentication-only final |
| ---: | ---: | ---: |
| 0 | 0 | 0 |
| 10 | 5 | 5 |
| 20 | 9 | 11 |
| 30 | 14 | 16 |
| 40 | 18 | 22 |
| 50 | 23 | 27 |
| 60 | 28 | 32 |
| 70 | 32 | 38 |
| 80 | 37 | 43 |
| 90 | 42 | 48 |
| 100 | 46 | 54 |

Both curves are deterministic and monotonic. Authentication is slightly stronger
by design. Neither base component alone reaches the 60-point HIGH boundary.

For both reputation and attachment, raw detection values
0, 10, 20, 50, 80, and 100 produce bonuses 0, 5, 10, 15, 20, and 20. Relay
mismatch counts 0, 1, 2, and 5 produce 0, 10, 10, and 10. Across corpus scenarios,
the dominant contribution was authentication in 10, sender in 9, reputation in
4, attachment in 3, relay in 2, and none in 5. AI dominated zero scenarios.

## Bonus and overlap review

Repeated detections do not increase a family score: a single and repeated
high-reputation item both finish at 20, a single and repeated attachment item
both finish at 20, and one or five relay mismatches both add 10. Domain and IP
reputation also share one maximum rather than accumulating.

The three different bonus families can add 50 points together. The controlled
bonus-only case therefore reaches 50/SUSPICIOUS but not HIGH. Corroborated base
evidence can raise it further, and the final 100-point cap absorbs excess. The
largest bonus effect observed was 50 points.

Cross-family evidence may be related in practice, such as one campaign causing
both a poor domain reputation and a relay anomaly. V2 does not infer that
dependence. Keeping separate bounded families retains useful corroboration while
limiting repetition, but it is a remaining source of possible overlap.

## Decision

Weights, bonus bands, thresholds, and the `validated_evidence_fusion_v2`
identifier are **kept unchanged**. The controlled corpus confirms monotonicity,
bounded scores, no repeat reward within a family, no HIGH verdict from one base
component, and exact zero AI points. Retuning on hand-authored targets would
encode the fixture authors' assumptions and could weaken real forensic evidence
without measuring representative inbox behavior.

Any future change should use a separate versioned policy and an independently
labeled corpus with benign third-party mail, real authentication failure modes,
confirmed incidents, analyst review outcomes, and enough source diversity to
estimate uncertainty. Raw-IOC handling and isolated authentication failures are
the first questions to study.

## Explainability and compatibility

Fresh results now include an additive `contributions` object for sender,
authentication, reputation, attachment, relay, and AI, plus the pre-rounding
total, explicit rounding/cap adjustment, final total, cap flag, policy version,
thresholds, and reasons. The dashboard shows these actual weighted contributions
alongside the existing raw evidence signals. Display rounding is absorbed by the
shown adjustment so the displayed rows equal the stored final score.

Historical snapshots lacking this object show their existing evidence view and
stored policy disclosure. They are neither rewritten nor recalculated. Campaign
correlation continues to ignore risk scores and uses stored indicators and
infrastructure.

For the maintained demo, the historical `legacy_fusion_v1` score remains 69.
A fresh v2 analysis remains 75: sender contributes 32.3077, authentication
43.0769, AI 0, bonuses 0, and rounding contributes -0.3846. No score changed in
this milestone.


## Validation and changed files

Final offline validation: **351 tests passed** (17 new calibration tests).
The suite also covers the displayed Streamlit breakdown, existing forensic
features, historical case storage, campaign correlation, protected model bytes,
and research activation gates.

Production changes are additive explanations and threshold centralization:

- `backend/fusion_policy.py`: centralized unchanged verdict boundaries.
- `backend/analyzers/fusion_engine.py`: complete contribution ledger and reasons
  for nonzero low-level sender/authentication evidence; numeric policy unchanged.
- `frontend/ai_ui.py`: validates stored ledgers before preparing display rows.
- `frontend/app.py`: shows contributions at four decimals with a reconciling
  rounding/cap adjustment, retaining the original evidence view.

Evaluation, tests, and documentation:

- `backend/risk_calibration.py`
- `data/calibration/fusion_v2_scenarios.json`
- `data/calibration/fusion_v2_results.json`
- `tests/test_risk_calibration.py`
- `tests/test_case_ui.py`
- `docs/risk-score-calibration.md`
- `docs/architecture.md`
- `README.md`

The legacy model and vectorizer are byte-for-byte equal to the protected
reference. All nine research candidates remain unvalidated, inactive, and
unauthorized. Nothing is staged or committed, and no Git remote is configured.
