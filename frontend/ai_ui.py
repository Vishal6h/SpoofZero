"""Small, controlled AI disclosure views; historical snapshots remain untouched."""
from collections.abc import Mapping
from html import escape
import math
from numbers import Real
import streamlit as st

from ml.model_policy import describe_ai_output
from backend.fusion_policy import (
    CURRENT_FUSION_POLICY, DETERMINISTIC_POLICIES,
    LEGACY_FUSION_V1, snapshot_policy_version, has_unified_assessment,
    CONTRIBUTION_CATEGORIES, valid_number, claims_unified_assessment,
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
    if version in DETERMINISTIC_POLICIES:
        contribution = assessment.get("ai_numeric_contribution")
        if isinstance(contribution, bool) or not isinstance(contribution, Real):
            points = "unknown"
        else:
            try:
                points = f"{float(contribution):g}" if math.isfinite(contribution) else "unknown"
            except (OverflowError, TypeError, ValueError):
                points = "unknown"
        title = "Validated Evidence v3" if version == CURRENT_FUSION_POLICY else "Validated Evidence v2"
        return {
            "policy": title,
            "line": (
                f"Fusion policy: {title} · AI numeric contribution: {points} points · "
                "AI signal: Supporting evidence only"
            ),
            "note": (
                "The forensic risk score uses deterministic engineering weights; "
                "it is not a statistically calibrated probability."
            ),
            "current": version == CURRENT_FUSION_POLICY,
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
    included = isinstance(assessment, Mapping) and assessment.get(
        "ai_included_in_numeric_score"
    ) is True
    return ("AI model signal (0 numeric points)"
            if not included and snapshot_policy_version(assessment) in DETERMINISTIC_POLICIES
            else "AI model signal")


def score_breakdown_rows(assessment):
    """Build display values which reconcile without changing a stored score."""
    assessment = assessment if isinstance(assessment, Mapping) else {}
    if claims_unified_assessment(assessment) and not has_unified_assessment(assessment):
        return []
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


def risk_level_class(level):
    """Unknown labels are neutral, never silently styled as LOW."""
    return {
        "LOW": "verdict-safe", "GUARDED": "verdict-guarded",
        "MEDIUM": "verdict-suspicious", "HIGH": "verdict-high",
        "CRITICAL": "verdict-critical",
    }.get(level if isinstance(level, str) else "", "verdict-unknown")


def assessment_overview(assessment):
    """Render stored metadata without synthesizing v3 fields for historical data."""
    assessment = assessment if isinstance(assessment, Mapping) else {}
    version = snapshot_policy_version(assessment)
    unified = has_unified_assessment(assessment)
    invalid = claims_unified_assessment(assessment) and not unified
    score = assessment.get("risk_score")
    score_text = (f"{score:g} / 100" if not invalid and valid_number(score) and 0 <= score <= 100
                  else "Unavailable")
    confidence = assessment.get("evidence_confidence") if unified else {}
    coverage = assessment.get("evidence_coverage") if unified else {}
    confidence = confidence if isinstance(confidence, Mapping) else {}
    coverage = coverage if isinstance(coverage, Mapping) else {}
    confidence_level = confidence.get("level")
    coverage_status = coverage.get("status")
    return {
        "unified": unified, "invalid": invalid, "score": score_text,
        "risk_level": assessment.get("risk_level") if unified else "NOT RECORDED",
        "scoring_version": version,
        "confidence": (confidence_level if confidence_level in ("HIGH", "MEDIUM", "LOW") else "UNCLASSIFIED") if unified else "NOT RECORDED",
        "coverage": coverage_status if coverage_status in ("COMPLETE", "PARTIAL") else "NOT RECORDED",
        "review": ("REQUIRED" if invalid or unified and assessment.get("review_required") is True else
                   "NOT FLAGGED" if unified and assessment.get("review_required") is False else "NOT RECORDED"),
    }


def render_assessment_details(assessment):
    overview = assessment_overview(assessment)
    if overview["invalid"]:
        st.warning("The saved assessment has inconsistent score/version metadata. Reanalyze the original evidence to create a new snapshot.")
        return
    if not overview["unified"]:
        st.caption("Historical assessment: unified risk level, confidence and coverage were not recorded. The stored score has not been recalculated.")
        return
    st.caption(
        f"Scoring version: {overview['scoring_version']} · "
        f"Evidence confidence: {overview['confidence']} · "
        f"Evidence coverage: {overview['coverage']} · Review: {overview['review']}"
    )
    st.caption("A LOW score is not a safety guarantee. Confidence describes evidence reliability, not threat severity.")
    if assessment.get("review_required"):
        for reason in assessment.get("review_reasons") or []:
            st.caption(reason)
    with st.expander("Assessment evidence and confidence", expanded=False):
        findings = assessment.get("normalized_findings") or []
        by_id = {f.get("finding_id"): f for f in findings if isinstance(f, Mapping)}
        labels = {category: label for _, category, label in CONTRIBUTION_CATEGORIES}
        strongest = [by_id[key] for key in assessment.get("strongest_findings") or [] if key in by_id]
        st.write("**Strongest contributing evidence**")
        if strongest:
            st.dataframe([{
                "Evidence": labels.get(f.get("category"), f.get("signal_code")),
                "Points before final adjustment": f.get("applied_contribution"),
                "Confidence": f.get("confidence") or "UNCLASSIFIED",
                "Basis": f.get("confidence_explanation"),
            } for f in strongest], hide_index=True, width="stretch")
        else:
            st.info("No positive numeric contributors were recorded; this does not establish safety.")
        st.caption((assessment.get("evidence_confidence") or {}).get("explanation", ""))
        st.write("**Evidence availability**")
        st.json(assessment.get("evidence_coverage") or {}, expanded=False)
        st.write("**Normalized observations**")
        st.dataframe([{
            "Signal": f.get("signal_code"), "Availability": f.get("availability"),
            "Role": f.get("evidence_role"), "Confidence": f.get("confidence") or "UNCLASSIFIED",
            "Contribution": f.get("applied_contribution"),
            "Explanation": f.get("suppression_reason") or f.get("confidence_explanation"),
            "Sources": ", ".join(f.get("source_paths") or []),
        } for f in by_id.values()], hide_index=True, width="stretch")
