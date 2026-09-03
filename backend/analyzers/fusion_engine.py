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

    # Authentication is a domain-authentication signal, never a safety credit.
    # Keep the existing score weights and expose contradictory behavioral evidence.
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
    elif behavioral_finding:
        verdict = "REVIEW REQUIRED"
    elif authentication.get("evidence_state") == "inconclusive":
        verdict = "INCONCLUSIVE"
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

        "reasons": reasons,
        "authentication_context": {
            "reported_pass_methods": passed_methods,
            "behavioral_signals": behavioral_signals,
            "finding": behavioral_finding,
            "account_compromise_proven": False,
        }
    }
