"""Confidence describes assertion reliability, never severity or probability."""
from collections import Counter
from typing import Literal, TypedDict

ConfidenceLevel = Literal["HIGH", "MEDIUM", "LOW"]
EvidenceRole = Literal["CONTRIBUTING", "CONTEXTUAL", "UNAVAILABLE"]


class Confidence(TypedDict):
    level: ConfidenceLevel | None
    explanation: str


def classify_confidence(assertion, availability, *, source=None, conflicting=False):
    """Classify only explicit evidence; absent provenance cannot become confidence."""
    if availability not in {"AVAILABLE", "PARTIAL"}:
        return {"level": None, "explanation": "No usable observation is available."}
    if assertion == "reported_authentication":
        if not isinstance(source, str) or source not in {"configured_receiver", "receiver_inferred", "untrusted"}:
            return {"level": None, "explanation": "Authentication provenance was not recorded."}
        if source == "untrusted" or conflicting:
            return {
                "level": "LOW",
                "explanation": "Reported authentication is conflicting, malformed or weakly attributable; not independently verified.",
            }
        return {
            "level": "MEDIUM",
            "explanation": "Receiver-associated reported evidence; header origin and SPF/DKIM/DMARC were not independently verified.",
        }
    rules = {
        "hash": ("HIGH", "Complete-byte SHA-256 identity, not a maliciousness or authenticity conclusion."),
        "extraction": ("HIGH", "Deterministic local extraction/comparison of the retained evidence, not verification of its claims."),
        "identity": ("MEDIUM", "Structured sender-domain comparison; a difference does not establish impersonation."),
        "provider": ("MEDIUM", "Successful provider observation; reliability and freshness of the underlying verdict remain qualified."),
        "relay": ("LOW", "Received-header continuity/origin heuristic; it does not authenticate the sending infrastructure."),
        "ml": ("LOW", "Text-model inference; the model score is not evidence confidence or calibrated phishing probability."),
        "geo": ("LOW", "Approximate infrastructure location; it does not identify a person's location."),
        "correlation": ("LOW", "Shared-evidence relationship inference, not maliciousness or common authorship."),
    }
    if assertion not in rules:
        return {"level": None, "explanation": "Reliability cannot be classified from the recorded evidence."}
    level, explanation = rules[assertion]
    if availability == "PARTIAL" and level == "HIGH":
        level, explanation = "LOW", "Extraction was partial; only retained evidence was inspected."
    return {"level": level, "explanation": explanation}


def summarize_confidence(findings):
    """Use the least certain contributing assertion; contextual hashes cannot inflate it."""
    contributing = [f for f in findings if f.get("evidence_role") == "CONTRIBUTING"]
    counts = Counter(f.get("confidence") or "UNCLASSIFIED" for f in contributing)
    levels = [f.get("confidence") for f in contributing]
    rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    level = min(levels, key=rank.get) if levels and all(x in rank for x in levels) else None
    return {
        "level": level,
        "scope": "contributing_assertions",
        "contributing_count": len(contributing),
        "counts": dict(sorted(counts.items())),
        "explanation": (
            "Least certain contributing assertion; contextual evidence does not raise this confidence."
            if level else
            "Contributing evidence is absent or includes unclassified reliability; this is not a safety conclusion."
        ),
    }


def summarize_coverage(findings):
    """Observation inventory, not a percentage of all possible email threats."""
    observations = [f for f in findings if f.get("coverage_scope", True)]
    counts = Counter(f["availability"] for f in observations)
    gaps = [f["finding_id"] for f in observations
            if f["availability"] not in {"AVAILABLE", "NOT_APPLICABLE"}]
    return {
        "status": "PARTIAL" if gaps or not observations else "COMPLETE",
        "observation_count": len(observations),
        "available_count": counts.get("AVAILABLE", 0),
        "partial_count": counts.get("PARTIAL", 0),
        "not_applicable_count": counts.get("NOT_APPLICABLE", 0),
        "unavailable_count": sum(v for k, v in counts.items()
                                 if k not in {"AVAILABLE", "PARTIAL", "NOT_APPLICABLE"}),
        "unavailable_finding_ids": sorted(gaps),
        "note": "Coverage describes recorded observations and known omissions, not safety or exhaustive threat detection.",
    }
