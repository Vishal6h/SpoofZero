"""Shared model eligibility and the explicitly retained legacy compatibility path.

Eligibility is a prerequisite for a separate activation review, never activation.
Saved analysis output is display data and must not be used as model authorization.
"""
from collections.abc import Mapping
from hashlib import sha256
from io import BytesIO
import math
from pathlib import Path
from types import MappingProxyType

import joblib


MODEL_ROOT = Path(__file__).resolve().parent
LEGACY_VERSION = "legacy_demo_16"
LEGACY_HASHES = MappingProxyType({
    "vectorizer.joblib": "8eb8faebe8fb0a94989a36e37702b3bc88c1d0400860259750e8245a0d6ce30f",
    "phishing_model.joblib": "efc92ce20d0a736847148bdeef16aeee902ef91213e7392b29fffa1a96f9fabf",
})
ROLE = "supporting_evidence_only"
SCORE_NOTE = (
    "This score is a model signal, not a confirmed probability that the email is phishing."
)
LEGACY_NOTE = (
    "Experimental classifier trained on 16 examples; not validated for real-world use. "
    + SCORE_NOTE
)
SNAPSHOT_NOTE = (
    "Model validation metadata was not recorded or is not recognized in this snapshot. "
    + SCORE_NOTE
)
FUSION_NOTE = (
    "Legacy fusion still gives the unvalidated AI signal a 35% weight in its base score "
    "(up to 35 points). The composite threat score is not a calibrated probability."
)


def legacy_output_metadata():
    return {
        "model_version": LEGACY_VERSION,
        "model_status": "EXPERIMENTAL",
        "validation_status": "NOT VALIDATED",
        "evidence_role": ROLE,
        "validation_note": LEGACY_NOTE,
    }


def describe_ai_output(value):
    """Return controlled labels without mutating or authorizing a saved snapshot."""
    value = value if isinstance(value, Mapping) else {}
    if value.get("model_version") == LEGACY_VERSION and all(
        key in value for key in ("model_status", "validation_status", "evidence_role")
    ):
        # Even contradictory snapshot claims cannot call the legacy model validated.
        return legacy_output_metadata()
    status = value.get("model_status")
    if isinstance(status, str) and status in {"RESEARCH", "UNVALIDATED", "EXPERIMENTAL"}:
        return {
            "model_version": "UNRECOGNIZED_RESEARCH_MODEL",
            "model_status": status,
            "validation_status": "NOT VALIDATED",
            "evidence_role": ROLE,
            "validation_note": "Research classifier; not validated for production use. " + SCORE_NOTE,
        }
    return {
        "model_version": "UNKNOWN",
        "model_status": "UNKNOWN",
        "validation_status": "UNKNOWN / LEGACY SNAPSHOT",
        "evidence_role": ROLE,
        "validation_note": SNAPSHOT_NOTE,
    }


def _finite_number(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, TypeError, ValueError):
        return False


def _gate_bundle_passes(bundle):
    if (
        not isinstance(bundle, Mapping)
        or bundle.get("passed_all") is not True
        or bundle.get("failed") != []
    ):
        return False
    gates = bundle.get("gates")
    if not isinstance(gates, Mapping) or not gates:
        return False
    for gate in gates.values():
        if not isinstance(gate, Mapping) or gate.get("passed") is not True:
            return False
        actual, limit, operator = gate.get("actual"), gate.get("limit"), gate.get("operator")
        if operator == "is":
            if type(actual) is not bool or type(limit) is not bool or actual is not limit:
                return False
        else:
            if not _finite_number(actual) or not _finite_number(limit):
                return False
            if operator == ">=":
                passed = actual >= limit
            elif operator == "<=":
                passed = actual <= limit
            else:
                return False
            if not passed:
                return False
    return True


def activation_eligibility(metadata):
    """Check reviewed metadata without activating or loading a model.

    Eligibility is only a prerequisite for a separate activation review. Existing
    loaders still verify preprocessing, runtime, source and artifact hashes.
    """
    if not isinstance(metadata, Mapping):
        return {
            "eligible": False,
            "reasons": ["Model metadata is missing or malformed."],
            "automatic_activation": False,
        }

    reasons = []
    version = metadata.get("model_version")
    if not isinstance(version, str) or not version.strip():
        reasons.append("A model version is required.")
    if version == LEGACY_VERSION:
        reasons.append(
            "The legacy fallback is an explicit compatibility exception, not an eligible replacement."
        )

    state_fields = [
        metadata[key]
        for key in ("status", "model_status", "validation_status")
        if key in metadata
    ]
    if not state_fields or any(state != "VALIDATED" for state in state_fields):
        reasons.append("All supplied model validation states must explicitly be VALIDATED.")
    if metadata.get("validated") is not True:
        reasons.append("The validated flag must be the boolean true.")
    if metadata.get("activation_eligible") is not True:
        reasons.append("The activation eligibility flag must explicitly permit review.")

    blocker_fields = [
        metadata[key] for key in ("blockers", "promotion_blockers") if key in metadata
    ]
    if not blocker_fields or any(blockers != [] for blockers in blocker_fields):
        reasons.append("Promotion blockers must be explicitly present and empty.")

    schema_pairs = (
        ("development_gates", "final_confirmation_gates"),
        ("inherited_gates", "additional_gates"),
    )
    bundles = []
    for pair in schema_pairs:
        present = [key in metadata for key in pair]
        if any(present) and not all(present):
            reasons.append("Deployment gate evidence is incomplete: " + " and ".join(pair))
        elif all(present):
            bundles.extend(pair)
    if not bundles:
        reasons.append("Complete deployment-gate evidence is required.")

    for key in bundles:
        if not _gate_bundle_passes(metadata[key]):
            reasons.append("Deployment gate evidence is missing, inconsistent or failed: " + key)

    return {
        "eligible": not reasons,
        "reasons": reasons,
        "automatic_activation": False,
    }


def require_activation_eligible(metadata):
    result = activation_eligibility(metadata)
    if not result["eligible"]:
        raise ValueError(
            "Model is not eligible for production activation: " + " ".join(result["reasons"])
        )
    return result


def load_legacy_compatibility_model():
    """Load only the two exact baseline artifacts, checking both before unpickling.

    No environment variable, candidate status, uploaded path or directory scan can
    silently select a replacement. This is not a grant of validated status.
    """
    artifacts = {name: (MODEL_ROOT / name).read_bytes() for name in LEGACY_HASHES}
    for name, data in artifacts.items():
        if sha256(data).hexdigest() != LEGACY_HASHES[name]:
            raise ValueError(
                "Protected legacy artifact changed; automatic model replacement is prohibited."
            )
    return (
        joblib.load(BytesIO(artifacts["vectorizer.joblib"])),
        joblib.load(BytesIO(artifacts["phishing_model.joblib"])),
    )
