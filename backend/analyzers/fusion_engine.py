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
    attachment_reputation=None
):
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

    # Base SpoofZero score
    final_score = (
        sender_score * 0.30
        + auth_score * 0.35
        + ai_score * 0.35
    )

    reasons = []

    if sender_score >= 50:
        reasons.append(
            "Suspicious sender identity mismatch detected"
        )

    if auth_score >= 50:
        reasons.append(
            "Email authentication problems detected"
        )

    if ai_score >= 50:
        reasons.append(
            "AI detected suspicious phishing language"
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

    final_score = min(
        round(final_score),
        100
    )

    if final_score >= 80:
        verdict = "CRITICAL"
    elif final_score >= 60:
        verdict = "HIGH RISK"
    elif final_score >= 40:
        verdict = "SUSPICIOUS"
    elif final_score >= 20:
        verdict = "LOW RISK"
    else:
        verdict = "LIKELY SAFE"

    return {
        "risk_score": final_score,
        "verdict": verdict,

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

        "reasons": reasons
    }
