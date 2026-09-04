"""Allowlisted, repository-safe demonstrations with no live enrichment."""
from pathlib import Path
from uuid import uuid4

from .analyze import analyze_email
from .version import VERSION_LABEL

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEMO_ROOT = PROJECT_ROOT / "data" / "samples"
DEMO_EMAILS = {
    "single_email": {
        "label": "Single-email forensic walkthrough",
        "filename": "test.eml",
        "path": DEMO_ROOT / "test.eml",
    },
    "attachment": {
        "label": "Attachment hashing walkthrough",
        "filename": "attachment_test.eml",
        "path": DEMO_ROOT / "attachment_test.eml",
    },
    "campaign_related_1": {
        "label": "Campaign sample: related email 1",
        "filename": "related_1.eml",
        "path": DEMO_ROOT / "campaign" / "related_1.eml",
    },
    "campaign_related_2": {
        "label": "Campaign sample: related email 2",
        "filename": "related_2.eml",
        "path": DEMO_ROOT / "campaign" / "related_2.eml",
    },
    "campaign_unrelated": {
        "label": "Campaign sample: unrelated email",
        "filename": "unrelated.eml",
        "path": DEMO_ROOT / "campaign" / "unrelated.eml",
    },
}


def demo_choices():
    return {key: value["label"] for key, value in DEMO_EMAILS.items()}


def demo_filename(key):
    if key not in DEMO_EMAILS:
        raise ValueError("Unknown built-in demo selection.")
    return DEMO_EMAILS[key]["filename"]


def run_demo_analysis(key="single_email", *, analysis_id=None):
    if key not in DEMO_EMAILS:
        raise ValueError("Unknown built-in demo selection.")
    item = DEMO_EMAILS[key]
    path = item["path"].resolve()
    if not path.is_relative_to(DEMO_ROOT.resolve()) or not path.is_file():
        raise ValueError("Built-in demo evidence is unavailable.")
    result = analyze_email(
        path, analysis_id=analysis_id or uuid4().hex,
        external_services_enabled=False,
    )
    result["email"].setdefault("processing", {}).update({
        "evidence_source": "BUILT_IN_DEMO",
        "external_intelligence": "DISABLED",
        "product_version": VERSION_LABEL,
    })
    return result
