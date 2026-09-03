import sys
import json
import re
import ipaddress

from .email_parser import parse_email


IP_PATTERN = re.compile(
    r'(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])'
)

FROM_HOST_PATTERN = re.compile(
    r'\bfrom\s+([^\s(;]+)',
    re.IGNORECASE
)

BY_HOST_PATTERN = re.compile(
    r'\bby\s+([^\s(;]+)',
    re.IGNORECASE
)


DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


def classify_ip(ip_string):
    try:
        ip = ipaddress.ip_address(ip_string)
    except ValueError:
        return "invalid"

    for network in DOCUMENTATION_NETWORKS:
        if ip in network:
            return "documentation"

    if ip.is_private:
        return "private"

    if ip.is_global:
        return "public"

    return "special"


def parse_received_header(header):
    from_match = FROM_HOST_PATTERN.search(header)
    by_match = BY_HOST_PATTERN.search(header)

    from_host = from_match.group(1) if from_match else None
    by_host = by_match.group(1) if by_match else None

    raw_ips = IP_PATTERN.findall(header)

    valid_ips = []

    for ip_string in raw_ips:
        try:
            ipaddress.ip_address(ip_string)
            valid_ips.append(ip_string)
        except ValueError:
            continue

    ip_details = [
        {
            "ip": ip_string,
            "type": classify_ip(ip_string)
        }
        for ip_string in valid_ips
    ]

    return {
        "from_host": from_host,
        "by_host": by_host,
        "ips": ip_details,
        "raw_header": header
    }


def trace_relays(email_data):
    received_headers = email_data.get("received", [])

    chronological = list(reversed(received_headers))

    hops = []

    for index, header in enumerate(chronological):
        hop = parse_received_header(header)

        trust_score = 40
        chain_status = "START"

        if hop["from_host"]:
            trust_score += 15

        if hop["by_host"]:
            trust_score += 15

        if hop["ips"]:
            trust_score += 10

        if index > 0:
            previous_hop = hops[index - 1]

            if previous_hop["by_host"] == hop["from_host"]:
                trust_score += 20
                chain_status = "MATCHED"
            else:
                trust_score -= 20
                chain_status = "MISMATCH"

        trust_score = max(0, min(trust_score, 100))

        hop["hop_number"] = index + 1
        hop["trust_score"] = trust_score
        hop["chain_status"] = chain_status

        hops.append(hop)

    candidate_origin_ip = None

    for hop in hops:
        for ip_data in hop["ips"]:
            if ip_data["type"] == "public":
                candidate_origin_ip = ip_data["ip"]
                break

        if candidate_origin_ip:
            break

    return {
        "hop_count": len(hops),
        "candidate_origin_ip": candidate_origin_ip,
        "hops": hops
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "Usage: python -m backend.analyzers.relay_tracer "
            "<email.eml>"
        )
        sys.exit(1)

    email_data = parse_email(sys.argv[1])

    result = trace_relays(email_data)

    print(json.dumps(result, indent=4))
