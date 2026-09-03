import sys
import json

from .email_parser import parse_email


def analyze_authentication(email_data):
    auth_headers = email_data.get("authentication_results", [])

    combined = " ".join(auth_headers).lower()

    results = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
        "risk_score": 0,
        "findings": []
    }

    # SPF
    if "spf=pass" in combined:
        results["spf"] = "pass"
    elif "spf=fail" in combined:
        results["spf"] = "fail"
        results["risk_score"] += 30
        results["findings"].append({
            "type": "SPF_FAIL",
            "severity": "HIGH",
            "message": "SPF authentication failed"
        })
    elif "spf=softfail" in combined:
        results["spf"] = "softfail"
        results["risk_score"] += 15
        results["findings"].append({
            "type": "SPF_SOFTFAIL",
            "severity": "MEDIUM",
            "message": "SPF returned softfail"
        })

    # DKIM
    if "dkim=pass" in combined:
        results["dkim"] = "pass"
    elif "dkim=fail" in combined:
        results["dkim"] = "fail"
        results["risk_score"] += 30
        results["findings"].append({
            "type": "DKIM_FAIL",
            "severity": "HIGH",
            "message": "DKIM authentication failed"
        })
    elif "dkim=none" in combined:
        results["dkim"] = "none"
        results["risk_score"] += 10
        results["findings"].append({
            "type": "DKIM_NONE",
            "severity": "LOW",
            "message": "No DKIM authentication result found"
        })

    # DMARC
    if "dmarc=pass" in combined:
        results["dmarc"] = "pass"
    elif "dmarc=fail" in combined:
        results["dmarc"] = "fail"
        results["risk_score"] += 40
        results["findings"].append({
            "type": "DMARC_FAIL",
            "severity": "CRITICAL",
            "message": "DMARC authentication failed"
        })

    results["risk_score"] = min(results["risk_score"], 100)

    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "Usage: python -m backend.analyzers.auth_analyzer "
            "<email.eml>"
        )
        sys.exit(1)

    email_data = parse_email(sys.argv[1])

    result = analyze_authentication(email_data)

    print(json.dumps(result, indent=4))
