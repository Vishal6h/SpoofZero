"""Explicit local research inference; the application still loads its legacy model."""
import json
from pathlib import Path

import joblib
import sklearn

from ml.data_pipeline import ROOT, digest
from ml.experiment import CANDIDATES
from ml.text import verdict_for_probability
from .text import VERSION, feature_text

MODEL_ROOT = ROOT / "models/candidate_v2"


def load_candidate(name, *, research=False):
    if name not in CANDIDATES:
        raise ValueError("Expected a reviewed v2 candidate name")
    directory = MODEL_ROOT / name
    metadata = json.loads((directory / "metadata.json").read_text())
    status = metadata.get("validation_status")
    if status not in {"RESEARCH", "UNVALIDATED", "VALIDATED"}:
        raise ValueError("Unknown model validation state")
    eligible = (status == "VALIDATED" and metadata.get("validated") is True and
                metadata.get("activation_eligible") is True and not metadata.get("blockers") and
                metadata.get("development_gates", {}).get("passed_all") is True and
                metadata.get("final_confirmation_gates", {}).get("passed_all") is True)
    if not research and not eligible:
        raise ValueError("Candidate is not validated; explicit research use is required")
    if metadata.get("normalization_version") != VERSION or metadata["versions"]["scikit_learn"] != sklearn.__version__:
        raise ValueError("Research preprocessing/runtime mismatch")
    for path in ("text.py", "generalization/text.py"):
        if metadata["code_sha256"].get(path) != digest((ROOT / path).read_bytes()):
            raise ValueError("Research normalization changed since evaluation")
    artifact = directory / "model.joblib"
    if digest(artifact.read_bytes()) != metadata["artifact_sha256"]:
        raise ValueError("Research model artifact checksum mismatch")
    return joblib.load(artifact), metadata


def analyze_candidate(email_data, model, metadata):
    text = feature_text(email_data)
    probability = float(model.predict_proba([text])[0][1])
    verdict = verdict_for_probability(probability, metadata["thresholds"])
    return {"phishing_probability": round(probability * 100, 2), "verdict": verdict,
            "model_version": metadata["model_version"], "validation_status": metadata["validation_status"],
            "confidence_band": {"LOW PHISHING LIKELIHOOD": "low", "SUSPICIOUS": "suspicious",
                                "HIGH PHISHING LIKELIHOOD": "high"}[verdict],
            "thresholds": {key: value * 100 for key, value in metadata["thresholds"].items()},
            "input_quality": "readable_text" if text else "no_readable_text"}
