"""Small, controlled AI disclosure views; historical snapshots remain untouched."""
from collections.abc import Mapping
from html import escape
import math
from numbers import Real
import streamlit as st

from ml.model_policy import describe_ai_output
from backend.fusion_policy import (
    CURRENT_FUSION_POLICY, LEGACY_FUSION_V1, snapshot_policy_version,
)

def score_label(ai):
    ai = ai if isinstance(ai, Mapping) else {}
    score = ai.get("phishing_probability")
    if isinstance(score, bool) or not isinstance(score, Real):
        return "Unavailable"
    try:
        valid = math.isfinite(score) and 0 <= score <= 100
    except (OverflowError, TypeError, ValueError):
        valid = False
    if not valid:
        return "Unavailable"
    return f"{score:.2f}%"

def ai_card_html(ai):
    metadata = describe_ai_output(ai)
    verdict = ai.get("verdict") if isinstance(ai, Mapping) else None
    band = verdict if verdict in (
        "LOW PHISHING LIKELIHOOD", "SUSPICIOUS", "HIGH PHISHING LIKELIHOOD"
    ) else "UNKNOWN"
    # Every status/role is a controlled label; raw notes/verdicts are not HTML.
    return (
        '<div class="sz-card">'
        '<div class="sz-label">AI phishing score</div>'
        f'<div class="sz-value">{escape(score_label(ai))}</div>'
        '<div class="sz-small">'
        f'Signal band: {escape(band)}<br>'
        f'Model status: {escape(metadata["model_status"])}<br>'
        f'Validation: {escape(metadata["validation_status"])}<br>'
        'Role: Supporting evidence only'
        '</div></div>'
    )

def render_ai_card(ai):
    st.markdown(ai_card_html(ai), unsafe_allow_html=True)

def fusion_disclosure(assessment):
    """Describe stored policy metadata without recalculating its score."""
    assessment = assessment if isinstance(assessment, Mapping) else {}
    version = snapshot_policy_version(assessment)
    if version == CURRENT_FUSION_POLICY:
        contribution = assessment.get("ai_numeric_contribution")
        if isinstance(contribution, bool) or not isinstance(contribution, Real):
            points = "unknown"
        else:
            try:
                points = f"{float(contribution):g}" if math.isfinite(contribution) else "unknown"
            except (OverflowError, TypeError, ValueError):
                points = "unknown"
        return {
            "policy": "Validated Evidence v2",
            "line": (
                f"Fusion policy: Validated Evidence v2 · AI numeric contribution: {points} points · "
                "AI signal: Supporting evidence only"
            ),
            "note": (
                "The forensic risk score uses deterministic engineering weights; "
                "it is not a statistically calibrated probability."
            ),
            "current": True,
        }
    if version == LEGACY_FUSION_V1:
        return {
            "policy": LEGACY_FUSION_V1,
            "line": "Fusion policy: legacy_fusion_v1",
            "note": (
                "Historical score used legacy fusion and may include experimental AI weighting. "
                "Its stored score has not been recalculated."
            ),
            "current": False,
        }
    return {
        "policy": version,
        "line": f"Fusion policy: {version}",
        "note": (
            "Historical snapshot has no recognized fusion metadata. Its stored score has not "
            "been recalculated and may include experimental AI weighting."
        ),
        "current": False,
    }


def ai_evidence_label(assessment):
    disclosure = fusion_disclosure(assessment)
    included = isinstance(assessment, Mapping) and assessment.get(
        "ai_included_in_numeric_score"
    ) is True
    return "AI model signal" if included or not disclosure["current"] else "AI model signal (0 numeric points)"


def score_breakdown_rows(assessment):
    """Build display values which reconcile without changing a stored score."""
    assessment = assessment if isinstance(assessment, Mapping) else {}
    contributions = assessment.get("contributions")
    final = assessment.get("risk_score")
    if (
        not isinstance(contributions, Mapping)
        or isinstance(final, bool)
        or not isinstance(final, Real)
    ):
        return []
    keys = (
        ("sender_identity", "Sender identity"),
        ("authentication", "Authentication"),
        ("reputation", "Domain/IP reputation bonus"),
        ("attachment", "Attachment reputation bonus"),
        ("relay", "Relay-chain bonus"),
        ("ai", "AI model signal"),
    )
    values = []
    try:
        for key, label in keys:
            value = contributions.get(key)
            if (
                isinstance(value, bool)
                or not isinstance(value, Real)
                or not math.isfinite(value)
            ):
                return []
            values.append((label, round(float(value), 4)))
        final = float(final)
        raw = contributions.get("total_before_rounding_and_cap")
        adjustment = contributions.get("rounding_and_cap_adjustment")
        stored_total = contributions.get("total")
        ledger = (raw, adjustment, stored_total)
        if not math.isfinite(final) or any(
            isinstance(value, bool) or not isinstance(value, Real) or not math.isfinite(value)
            for value in ledger
        ):
            return []
        exact_parts = sum(contributions[key] for key, _ in keys)
        if (
            abs(exact_parts - raw) > 1e-9
            or abs(raw + adjustment - final) > 1e-9
            or stored_total != final
        ):
            return []
    except (OverflowError, TypeError, ValueError):
        return []
    # This includes ordinary score rounding, the 0-100 cap, and display rounding.
    adjustment = round(final - sum(value for _, value in values), 4)
    rows = [{"Evidence": label, "Contribution": value} for label, value in values]
    rows.append({
        "Evidence": "Rounding / score-cap adjustment",
        "Contribution": adjustment,
    })
    rows.append({"Evidence": "Final forensic risk score", "Contribution": final})
    return rows


def render_ai_details(ai, assessment):
    metadata = describe_ai_output(ai)
    disclosure = fusion_disclosure(assessment)
    st.markdown('<div class="section-title">AI Analysis</div>', unsafe_allow_html=True)
    st.caption(metadata["validation_note"])
    st.caption(disclosure["line"])
    st.caption(disclosure["note"])
