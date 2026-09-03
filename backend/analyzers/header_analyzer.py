import sys
import json

from .email_parser import parse_email
from .domain_alignment import address_domain, compare_domains


def extract_domain(address):
    return address_domain(address)


def analyze_sender_identity(email_data):
    from_domain = extract_domain(email_data.get("from"))
    reply_to_domain = extract_domain(email_data.get("reply_to"))
    return_path_domain = extract_domain(email_data.get("return_path"))

    reply_alignment = compare_domains(from_domain, reply_to_domain)
    return_alignment = compare_domains(from_domain, return_path_domain)

    findings = []
    risk_points = 0

    # FROM vs REPLY-TO
    if (
        from_domain
        and reply_to_domain
        and from_domain != reply_to_domain
        and reply_alignment["status"] != "aligned"
    ):
        findings.append({
            "type": "FROM_REPLY_TO_MISMATCH",
            "severity": "HIGH",
            "message": (
                f"From domain '{from_domain}' does not match "
                f"Reply-To domain '{reply_to_domain}'"
            )
        })

        risk_points += 40

    # FROM vs RETURN-PATH
    if (
        from_domain
        and return_path_domain
        and from_domain != return_path_domain
        and return_alignment["status"] != "aligned"
    ):
        findings.append({
            "type": "FROM_RETURN_PATH_MISMATCH",
            "severity": "MEDIUM",
            "message": (
                f"From domain '{from_domain}' does not match "
                f"Return-Path domain '{return_path_domain}'"
            )
        })

        risk_points += 30

    risk_points = min(risk_points, 100)

    return {
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "alignment": {"reply_to": reply_alignment, "return_path": return_alignment},
        "risk_score": risk_points,
        "findings": findings
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "Usage: python -m backend.analyzers.header_analyzer "
            "<email.eml>"
        )
        sys.exit(1)

    email_data = parse_email(sys.argv[1])

    result = analyze_sender_identity(email_data)

    print(json.dumps(result, indent=4))
