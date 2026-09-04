from collections.abc import Mapping
from pathlib import Path

from .email_parser import parse_email
from ml.text import safe_string
from ml.model_policy import legacy_output_metadata, load_legacy_compatibility_model


MODEL_DIR = Path(__file__).resolve().parents[2] / "ml"
VECTOR_PATH = MODEL_DIR / "vectorizer.joblib"
MODEL_PATH = MODEL_DIR / "phishing_model.joblib"


vectorizer, model = load_legacy_compatibility_model()


def analyze_text(email_data):
    email_data = email_data if isinstance(email_data, Mapping) else {}
    subject = safe_string(email_data.get("subject"))
    body = safe_string(email_data.get("body"))

    combined_text = f"{subject}\n{body}"

    X = vectorizer.transform([combined_text])

    probability = model.predict_proba(X)[0][1]

    phishing_probability = round(probability * 100, 2)

    if phishing_probability >= 70:
        verdict = "HIGH PHISHING LIKELIHOOD"
    elif phishing_probability >= 50:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW PHISHING LIKELIHOOD"

    return {
        "phishing_probability": phishing_probability,
        "verdict": verdict,
        **legacy_output_metadata(),
    }


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) != 2:
        print(
            "Usage: python -m backend.analyzers.nlp_detector "
            "<email.eml>"
        )
        sys.exit(1)

    email_data = parse_email(sys.argv[1])

    result = analyze_text(email_data)

    print(json.dumps(result, indent=4))
