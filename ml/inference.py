"""Research candidate inference, isolated from the active forensic pipeline."""
import json
from pathlib import Path

import joblib
import sklearn

from .data_pipeline import digest
from .text import VERSION, feature_text, verdict_for_probability

MODEL_ROOT = Path(__file__).resolve().parent / "models"


def load_candidate(version="candidate_v1", *, research=False):
    # Only local version names under the project model directory; never arbitrary
    # uploaded pickle files or remote models. These artifacts were trained locally.
    if Path(version).name != version or version in (".", ".."):
        raise ValueError("Expected a local model version name")
    directory = MODEL_ROOT / version
    metadata = json.loads((directory / "metadata.json").read_text())
    if not metadata.get("validated") and not research:
        raise ValueError("Candidate is not validated for activation; research use must be explicit")
    if metadata.get("normalization_version") != VERSION or metadata["versions"]["scikit_learn"] != sklearn.__version__:
        raise ValueError("Candidate preprocessing/runtime does not match this installation")
    expected_code = metadata.get("code_sha256", {}).get("text.py")
    if expected_code != digest(Path(__file__).with_name("text.py").read_bytes()):
        raise ValueError("Candidate normalization code changed after evaluation")
    artifact = directory / "model.joblib"
    if digest(artifact.read_bytes()) != metadata["artifact_sha256"]:
        raise ValueError("Candidate artifact checksum mismatch")
    return joblib.load(artifact), metadata


def analyze_candidate(email_data, model, metadata):
    text = feature_text(email_data)
    probability = float(model.predict_proba([text])[0][1])
    verdict = verdict_for_probability(probability, metadata["thresholds"])
    band = {"LOW PHISHING LIKELIHOOD": "low", "SUSPICIOUS": "suspicious",
            "HIGH PHISHING LIKELIHOOD": "high"}[verdict]
    return {"phishing_probability": round(probability * 100, 2), "verdict": verdict,
            "model_version": metadata["model_version"], "confidence_band": band,
            "thresholds": {key: value * 100 for key, value in metadata["thresholds"].items()},
            "input_quality": "readable_text" if text else "no_readable_text",
            "model_status": metadata["status"]}
