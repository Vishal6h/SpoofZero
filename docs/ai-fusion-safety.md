# AI fusion safety

Protected reference: `edef5030b635085eb89ea7711edd03a730bb7d11`.

## Policies

SpoofZero has two explicit fusion policy identifiers.

### `legacy_fusion_v1`

This policy reproduces a historical fresh-analysis calculation:

```text
base = 0.30 × sender identity
     + 0.35 × authentication
     + 0.35 × AI phishing signal

score = min(100, round(base + reputation bonus + attachment bonus + relay bonus))
```

The maximum base contributions are 30, 35 and 35 points respectively. It is
available only through an explicit `policy_version="legacy_fusion_v1"` call for
reproducibility and tests. It is not the fresh-analysis default and does not
authorize an AI model.

### `validated_evidence_fusion_v2`

This is the fresh-analysis default. Let `w` be a separately approved,
model-specific AI weight:

```text
base = (1 − w) × (6 × sender identity + 7 × authentication) / 13
     + w × AI phishing signal

score = clamp(0, 100,
              round(base + reputation bonus + attachment bonus + relay bonus))
```

The current application provides no AI authorization, so `w = 0`:

```text
base = (6 × sender identity + 7 × authentication) / 13
```

Current base weights are therefore:

| Evidence | Weight | Maximum base points |
|---|---:|---:|
| Sender identity | 6/13 (46.1538%) | 46.1538 |
| Authentication | 7/13 (53.8462%) | 53.8462 |
| AI model signal | 0 | 0 |

The policy name describes its rule for admitting validated model evidence. It
does not claim that sender heuristics, reported authentication results or the
resulting score are scientifically validated. SpoofZero still parses reported
SPF/DKIM/DMARC evidence rather than independently performing cryptographic
verification.

The 6:7 ratio is the historical 30:35 ratio reduced to whole numbers and
normalized to a complete 100-point base. This preserves the established
relative emphasis between the two non-AI signals without leaving the base
capped at 65 or tuning against the demo email. These are deterministic
engineering risk weights. They are not statistical calibration.

Reputation, attachment and relay handling is retained:

- the strongest successful domain/IP reputation signal adds 5, 10, 15 or 20
  points at the existing greater-than-zero, 20, 50 and 80 thresholds;
- the strongest successful attachment reputation signal uses the same bonus
  bands;
- one or more relay-chain mismatches add 10 points;
- the result is rounded after bonuses and capped at 100. V2 also enforces a
  lower bound of zero.

## AI handling

The legacy classifier remains visible with its 0–100 signal, signal band,
model status, validation status and supporting-evidence role. Under v2 it has:

```json
{
  "ai_numeric_contribution": 0,
  "ai_weight_applied": 0,
  "ai_included_in_numeric_score": false,
  "ai_validation_status": "NOT VALIDATED"
}
```

Its language can still create a qualitative behavioral finding, including the
existing authentication-pass warning. This finding does not add numeric
points. Fusion output records the policy, base weights, per-source base
contributions, pre-bonus base, AI decision, bonuses and a plain-language
formula.

A future AI signal can receive numeric weight only when all of these separate
conditions hold:

1. reviewed model metadata passes the existing validation and deployment gates;
2. the AI output identifies the same validated model/version;
3. trusted application code supplies an immutable `AIWeightAuthorization`;
4. the authorization is bound to the exact model-metadata SHA-256;
5. it names separate evaluation and approval records;
6. it explicitly sets a positive evaluated weight below 40%; and
7. the authorization targets `validated_evidence_fusion_v2`.

A validated or eligible label alone leaves the weight at zero. Saved JSON,
email content and environment variables cannot supply this configuration. The
sub-40% guard keeps AI alone below the existing 40-point suspicious threshold;
it is a ceiling, not a default. The application currently supplies no
authorization and loads no research candidate.

## Historical cases and re-analysis

Case JSON is stored and returned unchanged. Display logic recognizes an
explicit policy, the earlier `ai_context.calculation_version`, or labels missing
metadata as `LEGACY SNAPSHOT`. It never recomputes the stored score. The case
inventory includes the stored fusion-policy label and warns that scores from
different policies should not be compared without their evidence.

Opening a saved case preserves its historical score. Uploading the original EML
and choosing **Analyze** creates a fresh in-memory v2 result. Saving the same raw
email back into the same case cannot replace the existing row because the case
schema intentionally keys it by raw EML SHA-256. The UI explains that the
historical snapshot was retained and that a separate case is needed to retain
both stored versions. Batch duplicate handling continues to reuse the saved
snapshot instead of silently re-analyzing it.

Campaign correlation remains independent of fusion policy and threat score. It
continues to correlate stored indicators and infrastructure.

## Demo and compatibility

For `data/samples/test.eml`:

| Policy | Sender | Authentication | AI signal | AI points | Bonuses | Final |
|---|---:|---:|---:|---:|---:|---:|
| `legacy_fusion_v1` | 70 | 80 | 58.05 | 20.3175 | 0 | 69 |
| `validated_evidence_fusion_v2` | 70 | 80 | 58.05 | 0 | 0 | 75 |

The v2 result is expected to differ. Its weights were not selected to reproduce
69. Old stored scores do not change.

`calculate_final_risk` now defaults to v2. Code that intentionally reconstructs
a historical result must pass `policy_version="legacy_fusion_v1"`. The output
schema is additive, so exact-key consumers must accept the new policy and
contribution fields. The case schema and correlation schema are unchanged.
