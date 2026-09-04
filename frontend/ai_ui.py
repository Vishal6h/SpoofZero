"""Small, controlled AI disclosure views; historical snapshots remain untouched."""
from collections.abc import Mapping
from html import escape
import math
import streamlit as st

from ml.model_policy import describe_ai_output, FUSION_NOTE

def score_label(ai):
    ai = ai if isinstance(ai, Mapping) else {}
    score = ai.get("phishing_probability")
    if type(score) not in (int, float) or not 0 <= score <= 100 or not math.isfinite(score):
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

def render_ai_details(ai, assessment):
    metadata = describe_ai_output(ai)
    st.markdown('<div class="section-title">AI Analysis</div>', unsafe_allow_html=True)
    st.caption(metadata["validation_note"])
    assessment = assessment if isinstance(assessment, Mapping) else {}
    context = assessment.get("ai_context")
    if isinstance(context, Mapping) and context.get("calculation_version") == "legacy_fusion_v1":
        st.caption(FUSION_NOTE)
    else:
        st.caption(
            "This historical snapshot may include an unvalidated AI contribution in its threat score. "
            "Its stored score has not been recalculated; model status and fusion details may be unknown."
        )
