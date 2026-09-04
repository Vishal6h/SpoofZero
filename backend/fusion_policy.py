"""Versioned engineering risk weights, independent of model activation.

Only trusted application code may supply an AIWeightAuthorization and reviewed
model metadata. Email content, saved snapshots and environment variables are
never policy configuration. No model is loaded or activated by this module.
"""
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
import json
import math
from numbers import Real
import re

from ml.model_policy import activation_eligibility, describe_ai_output


LEGACY_FUSION_V1 = "legacy_fusion_v1"
CURRENT_FUSION_POLICY = "validated_evidence_fusion_v2"
SENDER_SHARE = 6 / 13
AUTHENTICATION_SHARE = 7 / 13
V2_NOTE = (
    "Engineering risk weights, not statistically calibrated probabilities. "
    "Unvalidated AI is displayed as supporting evidence and contributes no numeric points."
)


def metadata_fingerprint(metadata):
    """Bind a future weight approval to the exact reviewed model metadata."""
    return sha256(json.dumps(
        metadata, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")).hexdigest()


def valid_number(value):
    if isinstance(value, bool) or not isinstance(value, Real):
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, ValueError, TypeError):
        return False


def bounded_signal(value, name):
    if not valid_number(value):
        raise ValueError(name + " must be a finite numeric risk signal")
    return float(max(0, min(100, value)))


@dataclass(frozen=True)
class AIWeightAuthorization:
    """A separately reviewed scoring configuration, not a model activation.

    The current application supplies no authorization. References are audit
    records for trusted code review, not proof of evaluation by themselves.
    """
    model_version: str
    model_metadata_sha256: str
    weight: float
    approval_reference: str
    evaluation_reference: str
    fusion_policy_version: str = CURRENT_FUSION_POLICY

    def __post_init__(self):
        if self.fusion_policy_version != CURRENT_FUSION_POLICY:
            raise ValueError("AI weight authorization must target the current fusion policy")
        for value in (self.model_version, self.approval_reference, self.evaluation_reference):
            if not isinstance(value, str) or not value.strip():
                raise ValueError("Model version, approval and evaluation references are required")
        if not isinstance(self.model_metadata_sha256, str) or not re.fullmatch(
            r"[a-f0-9]{64}", self.model_metadata_sha256
        ):
            raise ValueError("The exact reviewed model metadata fingerprint is required")
        # AI alone must remain below the existing 40-point suspicious threshold.
        # This is a ceiling for future explicit review, never a default AI weight.
        if not valid_number(self.weight) or not 0 < self.weight < 0.40:
            raise ValueError("An explicit supporting AI weight must be greater than 0 and below 0.40")


def ai_numeric_policy(ai_analysis, *, model_metadata=None, authorization=None):
    """Fail closed unless validation AND a separate exact weight approval agree."""
    ai = ai_analysis if isinstance(ai_analysis, Mapping) else {}
    result = {
        "weight": 0.0, "included": False, "model_eligible": False,
        "validation_status": describe_ai_output(ai)["validation_status"],
        "reason": "No explicit AI scoring authorization; supporting evidence only.",
        "authorization": None,
    }
    if not isinstance(model_metadata, Mapping):
        return result
    eligible = activation_eligibility(model_metadata)["eligible"]
    same_output = (
        ai.get("model_version") == model_metadata.get("model_version")
        and ai.get("validation_status") == "VALIDATED"
        and ai.get("model_status", "VALIDATED") == "VALIDATED"
    )
    result["model_eligible"] = bool(eligible and same_output)
    if not result["model_eligible"]:
        result["reason"] = "Model validation/eligibility is absent, failed or does not match the AI output."
        return result
    result["validation_status"] = "VALIDATED"
    if type(authorization) is not AIWeightAuthorization:
        return result
    try:
        authorization.__post_init__()
        fingerprint = metadata_fingerprint(model_metadata)
    except (TypeError, ValueError, OverflowError):
        result["reason"] = "AI scoring authorization or model metadata is malformed."
        return result
    if (
        authorization.model_version != model_metadata.get("model_version")
        or authorization.model_metadata_sha256 != fingerprint
    ):
        result["reason"] = "AI scoring authorization does not match the reviewed model/version."
        return result
    if not valid_number(ai.get("phishing_probability")) or not 0 <= ai["phishing_probability"] <= 100:
        result["reason"] = "The authorized AI output does not contain a valid 0-100 signal."
        return result
    result.update(
        weight=float(authorization.weight), included=True,
        reason="Explicit reviewed model-specific fusion weight applied.",
        authorization={
            "model_version": authorization.model_version,
            "model_metadata_sha256": fingerprint,
            "weight": float(authorization.weight),
            "approval_reference": authorization.approval_reference,
            "evaluation_reference": authorization.evaluation_reference,
        },
    )
    return result


def calculate_base(sender_score, auth_score, ai_score, ai_analysis, *,
                   policy_version=CURRENT_FUSION_POLICY,
                   model_metadata=None, authorization=None):
    if policy_version == LEGACY_FUSION_V1:
        # Preserve historical arithmetic and evaluation order exactly.
        weights = {"sender_identity": 0.30, "authentication": 0.35, "ai_phishing": 0.35}
        base = sender_score * 0.30 + auth_score * 0.35 + ai_score * 0.35
        decision = {
            "weight": 0.35, "included": True, "model_eligible": False,
            "validation_status": describe_ai_output(ai_analysis)["validation_status"],
            "reason": "Historical legacy formula; not authorization for current AI scoring.",
            "authorization": None,
        }
        explanation = (
            "Historical base: 0.30 × sender + 0.35 × authentication + 0.35 × AI; "
            "add reputation, attachment and relay bonuses, round, then cap at 100. "
            "This historical score may include unvalidated AI."
        )
    elif policy_version == CURRENT_FUSION_POLICY:
        decision = ai_numeric_policy(
            ai_analysis, model_metadata=model_metadata, authorization=authorization
        )
        weight = decision["weight"]
        weights = {
            "sender_identity": (1 - weight) * SENDER_SHARE,
            "authentication": (1 - weight) * AUTHENTICATION_SHARE,
            "ai_phishing": weight,
        }
        base = (1 - weight) * (6 * sender_score + 7 * auth_score) / 13 + weight * ai_score
        explanation = (
            "Base: (1 − applied AI weight) × (6 × sender + 7 × authentication) / 13 "
            "+ applied AI weight × AI signal. Default AI weight is 0. "
            "Add reputation, attachment and relay bonuses, round, then clamp to 0–100. "
            "These are engineering risk weights, not statistically calibrated probabilities."
        )
    else:
        raise ValueError("Unknown fusion policy version")
    contributions = {
        "sender_identity": sender_score * weights["sender_identity"],
        "authentication": auth_score * weights["authentication"],
        "ai_phishing": ai_score * weights["ai_phishing"],
    }
    return {
        "base_score": base, "base_weights": weights, "base_contributions": contributions,
        "ai_policy": decision, "score_explanation": explanation,
        "fusion_policy_version": policy_version,
    }


def snapshot_policy_version(assessment):
    """Identify a saved policy without inferring or recomputing its score."""
    assessment = assessment if isinstance(assessment, Mapping) else {}
    version = assessment.get("fusion_policy_version")
    if version in (CURRENT_FUSION_POLICY, LEGACY_FUSION_V1):
        return version
    if version is not None:
        return "UNKNOWN SNAPSHOT"
    context = assessment.get("ai_context")
    if isinstance(context, Mapping) and context.get("calculation_version") == LEGACY_FUSION_V1:
        return LEGACY_FUSION_V1
    return "LEGACY SNAPSHOT"
