# AI honesty and production safety

Protected reference: `8cbe862af712e83fbab6c5db2fe089c6e838f9b6`.

## Active classifier and output contract

SpoofZero continues to load the same `ml/vectorizer.joblib` and
`ml/phishing_model.joblib` artifacts used by the protected reference. Their
SHA-256 digests are pinned in `ml/model_policy.py` and checked before either
joblib artifact is deserialized. The active path is an explicit compatibility
exception; it is not evidence that the model is validated.

The original output fields remain available:

```json
{
  "phishing_probability": 58.05,
  "verdict": "SUSPICIOUS"
}
```

New analyses add:

```json
{
  "model_version": "legacy_demo_16",
  "model_status": "EXPERIMENTAL",
  "validation_status": "NOT VALIDATED",
  "evidence_role": "supporting_evidence_only",
  "validation_note": "Experimental classifier trained on 16 examples; not validated for real-world use. This score is a model signal, not a confirmed probability that the email is phishing."
}
```

The percentage retains its historical name in the programmatic contract for
compatibility. The dashboard calls it an **AI phishing score** and explains
that it is a model signal. It must not be interpreted as an empirical,
calibrated probability for a real inbox.

## Saved cases

Case snapshots remain immutable application data. Loading a snapshot does not
change its stored JSON or use its metadata to authorize a model. A snapshot
without the new fields displays these controlled defaults:

- Model status: `UNKNOWN`
- Validation: `UNKNOWN / LEGACY SNAPSHOT`
- Role: supporting evidence only

This preserves old case and export data while preventing the UI from inventing
a validation claim. A saved snapshot that claims the legacy version is
validated is also rendered with the controlled experimental legacy labels.

## Activation eligibility

`ml/model_policy.py` provides the common eligibility check used by the v1 and
v2 research loaders. A research candidate can be considered eligible for a
separate production review only when all of the following are explicit and
internally consistent:

- every supplied validation state is exactly `VALIDATED`;
- `validated` and `activation_eligible` are Boolean `true`;
- a blocker field is present and empty;
- a complete recognized pair of deployment-gate bundles is present;
- every gate reports Boolean success and its typed evidence satisfies its
  recorded operator and limit.

Missing, partial, contradictory, malformed, truthy-string, non-finite, failed,
or unknown gate evidence fails closed. Eligibility does not load, switch, or
activate a model, and the policy always reports `automatic_activation: false`.
Artifact, source, normalizer, code, and runtime integrity checks remain in the
candidate loaders.

The active 16-example fallback cannot become an eligible replacement through
metadata changes. Its exact bytes are allowed only on the established
compatibility path. All v1, v2, and real-world candidates remain inactive and
unvalidated.

The frozen research reports continue to describe the code and artifacts at
their protected research checkpoints. This safety milestone intentionally
changes loader policy code without rewriting old reports, hashes, test-use
markers, metrics, or candidate metadata. Reproduction that requires an exact
historical code hash should use the report's protected commit.

## Fusion compatibility and recommendation

The numeric fusion calculation is unchanged. The unvalidated AI signal still
has a 35% base weight and can contribute up to 35 points. The assessment now
returns an additive `ai_context` block with the calculation version, weight,
weighted points, validation label, evidence role, and this limitation. The UI
shows the limitation beside AI Analysis. The composite threat score is not a
calibrated probability.

A future production milestone should gate an unvalidated model out of the
numeric production score and retain it as a visible supporting signal. Keep
`legacy_fusion_v1` available for historical snapshots and comparison. Before
changing or redistributing weights, evaluate the full fusion system on an
independent, representative corpus and set alert thresholds against measured
false-positive and false-negative costs. Arbitrarily reducing the 35% weight
would not calibrate either the model signal or the composite score.
