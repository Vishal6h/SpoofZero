from collections.abc import Mapping

from ml.model_policy import FUSION_NOTE
from backend.fusion_policy import (
    CURRENT_FUSION_POLICY, LEGACY_FUSION_V1, V2_NOTE,
    VERDICT_THRESHOLDS, bounded_signal, calculate_base, valid_number,
)


def calculate_reputation_score(reputation):
    item_scores = []

    for category in ("domains", "ips"):
        for item in reputation.get(category, []):
            if item.get("status") != "success":
                continue

            stats = item.get("analysis_stats", {}) or {}

            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)

            score = malicious * 20 + suspicious * 10

            item_scores.append(
                min(score, 100)
            )

    return max(item_scores) if item_scores else 0


def calculate_attachment_score(attachment_reputation):
    scores = []

    for item in attachment_reputation or []:

        if item.get("status") != "success":
            continue

        stats = item.get("analysis_stats", {}) or {}

        malicious = int(
            stats.get("malicious", 0) or 0
        )

        suspicious = int(
            stats.get("suspicious", 0) or 0
        )

        score = (
            malicious * 20
            + suspicious * 10
        )

        scores.append(
            min(score, 100)
        )

    return max(scores) if scores else 0


def calculate_final_risk(
    sender_identity,
    authentication,
    relay_trace,
    ai_analysis,
    reputation=None,
    attachment_reputation=None,
    *,
    policy_version=CURRENT_FUSION_POLICY,
    ai_model_metadata=None,
    ai_authorization=None,
):
    if policy_version == CURRENT_FUSION_POLICY:
        ai_analysis = ai_analysis if isinstance(ai_analysis, Mapping) else {}
    reputation = reputation or {}
    attachment_reputation = attachment_reputation or []

    sender_score = sender_identity.get(
        "risk_score",
        0
    )

    auth_score = authentication.get(
        "risk_score",
        0
    )

    ai_score = ai_analysis.get(
        "phishing_probability",
        0
    )

    reputation_score = calculate_reputation_score(
        reputation
    )

    attachment_score = calculate_attachment_score(
        attachment_reputation
    )

    if policy_version == CURRENT_FUSION_POLICY:
        sender_score = bounded_signal(sender_score, "Sender identity")
        auth_score = bounded_signal(auth_score, "Authentication")
        # Malformed AI output cannot affect numeric scoring or qualitative flags.
        ai_score = bounded_signal(ai_score, "AI") if valid_number(ai_score) else 0.0

    base = calculate_base(
        sender_score, auth_score, ai_score, ai_analysis,
        policy_version=policy_version, model_metadata=ai_model_metadata,
        authorization=ai_authorization,
    )
    decision = base["ai_policy"]
    ai_points = base["base_contributions"]["ai_phishing"]
    final_score = base["base_score"]

    reasons = []

    if sender_score >= 50:
        reasons.append(
            "Suspicious sender identity mismatch detected"
        )
    elif sender_score > 0:
        reasons.append(
            "Sender identity checks produced a nonzero risk signal"
        )

    if auth_score >= 50:
        reasons.append(
            "Email authentication problems detected"
        )
    elif auth_score > 0:
        reasons.append(
            "Reported authentication checks produced a nonzero risk signal"
        )

    if ai_score >= 50:
        reasons.append(
            "AI model signal suggests phishing-like language"
            + (" (supporting evidence only; excluded from numeric score)."
               if not decision["included"] else "")
        )

    # Domain/IP reputation bonus
    reputation_bonus = 0

    if reputation_score >= 80:
        reputation_bonus = 20
    elif reputation_score >= 50:
        reputation_bonus = 15
    elif reputation_score >= 20:
        reputation_bonus = 10
    elif reputation_score > 0:
        reputation_bonus = 5

    if reputation_bonus:
        final_score += reputation_bonus

        reasons.append(
            "Threat intelligence detected suspicious "
            "domain or IP reputation"
        )

    # Attachment reputation bonus
    attachment_bonus = 0

    if attachment_score >= 80:
        attachment_bonus = 20
    elif attachment_score >= 50:
        attachment_bonus = 15
    elif attachment_score >= 20:
        attachment_bonus = 10
    elif attachment_score > 0:
        attachment_bonus = 5

    if attachment_bonus:
        final_score += attachment_bonus

        reasons.append(
            "Attachment hash has suspicious "
            "threat-intelligence detections"
        )

    # Relay mismatch
    mismatches = [
        hop
        for hop in relay_trace.get("hops", [])
        if hop.get("chain_status") == "MISMATCH"
    ]

    relay_bonus = 0

    if mismatches:
        relay_bonus = 10
        final_score += relay_bonus

        reasons.append(
            "Suspicious relay-chain mismatch detected"
        )

    # Authentication is a domain-authentication signal, never a safety credit.
    # Preserve qualitative BEC findings even when AI has zero numeric weight.
    passed_methods = [method for method in ("spf", "dkim", "dmarc")
                      if authentication.get(method) == "pass"]
    behavioral_signals = []
    if sender_score > 0:
        behavioral_signals.append("sender_identity")
    if ai_score >= 50:
        behavioral_signals.append("ai_phishing_language")
    if reputation_score > 0:
        behavioral_signals.append("domain_or_ip_reputation")
    if attachment_score > 0:
        behavioral_signals.append("attachment_reputation")
    if mismatches:
        behavioral_signals.append("relay_chain")
    behavioral_finding = None
    if passed_methods and behavioral_signals:
        message = (
            "Authentication passed, but behavioral evidence remains suspicious."
            if len(passed_methods) == 3 or "dmarc" in passed_methods else
            "Some authentication checks passed, but behavioral evidence remains suspicious."
        )
        behavioral_finding = {
            "type": "AUTH_PASS_SUSPICIOUS_BEHAVIOR", "severity": "MEDIUM",
            "message": message + " These are reported results; this does not prove account compromise.",
        }
        reasons.append(behavioral_finding["message"])
    if authentication.get("evidence_state") == "inconclusive":
        reasons.append("Authentication evidence is incomplete or inconclusive; missing or unknown results do not establish safety.")
    if authentication.get("evidence_confidence", {}).get("source") == "untrusted":
        reasons.append("Authentication claims come from a reporter whose receiving-infrastructure association is unverified.")
    if any(f.get("type") in ("FROM_SPF_MISMATCH", "FROM_DKIM_MISMATCH", "DMARC_FROM_MISMATCH", "DMARC_ALIGNMENT_UNSUPPORTED")
           for f in authentication.get("findings", [])):
        reasons.append("Reported authentication identities contain alignment differences; inspect the per-identity evidence.")

    total_before_rounding_and_cap = final_score
    final_score = min(
        round(final_score),
        100
    )

    if policy_version == CURRENT_FUSION_POLICY:
        final_score = max(0, final_score)

    if final_score >= VERDICT_THRESHOLDS["critical"]:
        verdict = "CRITICAL"
    elif final_score >= VERDICT_THRESHOLDS["high_risk"]:
        verdict = "HIGH RISK"
    elif final_score >= VERDICT_THRESHOLDS["suspicious"]:
        verdict = "SUSPICIOUS"
    elif final_score >= VERDICT_THRESHOLDS["low_risk"]:
        verdict = "LOW RISK"
    elif behavioral_finding:
        verdict = "REVIEW REQUIRED"
    elif authentication.get("evidence_state") == "inconclusive":
        verdict = "INCONCLUSIVE"
    else:
        verdict = "LIKELY SAFE"

    return {
        "risk_score": final_score,
        "verdict": verdict,
        "fusion_policy_version": policy_version,
        "ai_numeric_contribution": ai_points,
        "ai_weight_applied": decision["weight"],
        "ai_validation_status": decision["validation_status"],
        "ai_included_in_numeric_score": decision["included"],
        "ai_model_eligible": decision["model_eligible"],
        "ai_scoring_reason": decision["reason"],
        "ai_scoring_authorization": decision["authorization"],
        "score_explanation": base["score_explanation"],
        "base_weights": base["base_weights"],
        "base_contributions": base["base_contributions"],
        "base_score_before_bonuses": base["base_score"],
        "verdict_thresholds": dict(VERDICT_THRESHOLDS),
        "contributions": {
            "sender_identity": base["base_contributions"]["sender_identity"],
            "authentication": base["base_contributions"]["authentication"],
            "reputation": reputation_bonus,
            "attachment": attachment_bonus,
            "relay": relay_bonus,
            "ai": ai_points,
            "total_before_rounding_and_cap": total_before_rounding_and_cap,
            "rounding_and_cap_adjustment": final_score - total_before_rounding_and_cap,
            "total": final_score,
            "cap_applied": round(total_before_rounding_and_cap) > 100
                           or round(total_before_rounding_and_cap) < 0,
        },

        "evidence_scores": {
            "sender_identity": round(sender_score, 2),
            "authentication": round(auth_score, 2),
            "ai_phishing": round(ai_score, 2),
            "threat_reputation": reputation_score,
            "attachment_reputation": attachment_score
        },

        "reputation_bonus": reputation_bonus,
        "attachment_bonus": attachment_bonus,
        "relay_bonus": relay_bonus,

        "reasons": reasons,
        "ai_context": {
            "calculation_version": policy_version,
            "base_weight": decision["weight"],
            "maximum_base_points": 100 * decision["weight"],
            "weighted_points_before_rounding": ai_points,
            "validation_status": decision["validation_status"],
            "evidence_role": "supporting_evidence_only",
            "limitation": FUSION_NOTE if policy_version == LEGACY_FUSION_V1 else V2_NOTE,
        },
        "authentication_context": {
            "reported_pass_methods": passed_methods,
            "behavioral_signals": behavioral_signals,
            "finding": behavioral_finding,
            "account_compromise_proven": False,
        }
    }
