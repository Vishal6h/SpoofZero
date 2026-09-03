import json
import sys
import urllib.request

import dns.resolver


RESERVED_DEMO_DOMAINS = (
    "example.com",
    "example.net",
    "example.org",
)


def is_reserved_demo_domain(domain):
    domain = domain.lower().rstrip(".")

    if domain.endswith((".test", ".invalid", ".localhost")):
        return True

    for reserved in RESERVED_DEMO_DOMAINS:
        if domain == reserved or domain.endswith("." + reserved):
            return True

    return False


def dns_lookup(domain):
    results = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": []
    }

    for record_type in results:
        try:
            answers = dns.resolver.resolve(
                domain,
                record_type,
                lifetime=3
            )

            for answer in answers:
                results[record_type].append(
                    str(answer).strip('"')
                )

        except Exception:
            pass

    return results


def rdap_lookup(domain):
    url = f"https://rdap.org/domain/{domain}"

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "SpoofZero/1.0"
        }
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=8
        ) as response:

            data = json.loads(
                response.read().decode("utf-8")
            )

    except Exception as error:
        return {
            "status": "unavailable",
            "message": str(error)
        }

    events = {}

    for event in data.get("events", []):
        action = event.get("eventAction")
        date = event.get("eventDate")

        if action:
            events[action] = date

    nameservers = []

    for ns in data.get("nameservers", []):
        name = ns.get("ldhName")

        if name:
            nameservers.append(name)

    return {
        "status": "success",
        "handle": data.get("handle"),
        "registration_date": events.get("registration"),
        "expiration_date": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "nameservers": nameservers
    }


def analyze_domain(domain):
    domain = domain.lower().strip().rstrip(".")

    # Prevent demo/test domains from being treated as real threats
    if is_reserved_demo_domain(domain):
        return {
            "domain": domain,
            "status": "reserved_demo",
            "risk_score": 0,
            "dns": {},
            "rdap": {},
            "indicators": [
                "Reserved demo/test domain — real reputation lookup skipped"
            ]
        }

    dns_data = dns_lookup(domain)
    rdap_data = rdap_lookup(domain)

    indicators = []
    risk_score = 0

    total_records = sum(
        len(records)
        for records in dns_data.values()
    )

    if total_records == 0:
        indicators.append(
            "No DNS records found"
        )
        risk_score += 20

    if not dns_data["NS"]:
        indicators.append(
            "No authoritative nameserver record found"
        )
        risk_score += 10

    mx_records = dns_data["MX"]

    if mx_records == ["0 ."]:
        indicators.append(
            "Null MX detected — domain intentionally does not receive email"
        )

    elif not mx_records:
        indicators.append(
            "No MX mail-server record found"
        )

    if rdap_data.get("status") != "success":
        indicators.append(
            "Domain registration information unavailable"
        )

    risk_score = min(risk_score, 100)

    return {
        "domain": domain,
        "status": "analyzed",
        "risk_score": risk_score,
        "dns": dns_data,
        "rdap": rdap_data,
        "indicators": indicators
    }


def analyze_domains(domains, limit=8):
    results = []

    unique_domains = sorted(
        set(
            d.lower().strip().rstrip(".")
            for d in domains
            if d
        )
    )

    for domain in unique_domains[:limit]:
        try:
            results.append(
                analyze_domain(domain)
            )

        except Exception as error:
            results.append({
                "domain": domain,
                "status": "error",
                "risk_score": 0,
                "indicators": [
                    f"Lookup failed: {error}"
                ]
            })

    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "Usage: python -m "
            "backend.analyzers.threat_intel <domain>"
        )
        sys.exit(1)

    print(
        json.dumps(
            analyze_domain(sys.argv[1]),
            indent=4
        )
    )
