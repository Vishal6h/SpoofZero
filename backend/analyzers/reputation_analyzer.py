import os
import json
import ipaddress
import urllib.request
import urllib.error
import urllib.parse

from dotenv import load_dotenv
from .threat_intel import is_reserved_demo_domain


load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


def vt_request(endpoint):
    if not VT_API_KEY:
        return {
            "status": "error",
            "message": "VirusTotal API key not configured"
        }

    request = urllib.request.Request(
        VT_BASE_URL + endpoint,
        headers={
            "x-apikey": VT_API_KEY,
            "User-Agent": "SpoofZero/1.0"
        }
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=15
        ) as response:

            return {
                "status": "success",
                "data": json.loads(
                    response.read().decode("utf-8")
                )
            }

    except urllib.error.HTTPError as error:

        if error.code == 429:
            message = "VirusTotal rate limit reached"
        elif error.code == 401:
            message = "VirusTotal API key rejected"
        else:
            message = f"VirusTotal HTTP error {error.code}"

        return {
            "status": "error",
            "message": message
        }

    except Exception as error:
        return {
            "status": "error",
            "message": str(error)
        }


def make_verdict(stats):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious >= 3:
        return "MALICIOUS"

    if malicious > 0 or suspicious >= 2:
        return "SUSPICIOUS"

    return "NO MAJOR DETECTIONS"


def check_domain_reputation(domain):
    domain = domain.lower().strip().rstrip(".")

    if is_reserved_demo_domain(domain):
        return {
            "type": "domain",
            "value": domain,
            "status": "skipped",
            "reason": "Reserved demo/test domain"
        }

    encoded = urllib.parse.quote(
        domain,
        safe=""
    )

    response = vt_request(
        f"/domains/{encoded}"
    )

    if response["status"] != "success":
        return {
            "type": "domain",
            "value": domain,
            **response
        }

    attributes = (
        response["data"]
        .get("data", {})
        .get("attributes", {})
    )

    stats = attributes.get(
        "last_analysis_stats",
        {}
    )

    return {
        "type": "domain",
        "value": domain,
        "status": "success",
        "verdict": make_verdict(stats),
        "analysis_stats": stats,
        "vt_reputation": attributes.get(
            "reputation"
        ),
        "registrar": attributes.get(
            "registrar"
        ),
        "categories": attributes.get(
            "categories",
            {}
        )
    }


def check_ip_reputation(ip_string):
    try:
        ip = ipaddress.ip_address(ip_string)
    except ValueError:
        return {
            "type": "ip",
            "value": ip_string,
            "status": "skipped",
            "reason": "Invalid IP"
        }

    if not ip.is_global:
        return {
            "type": "ip",
            "value": ip_string,
            "status": "skipped",
            "reason": (
                "Private, reserved, documentation "
                "or non-public IP"
            )
        }

    response = vt_request(
        f"/ip_addresses/{ip_string}"
    )

    if response["status"] != "success":
        return {
            "type": "ip",
            "value": ip_string,
            **response
        }

    attributes = (
        response["data"]
        .get("data", {})
        .get("attributes", {})
    )

    stats = attributes.get(
        "last_analysis_stats",
        {}
    )

    return {
        "type": "ip",
        "value": ip_string,
        "status": "success",
        "verdict": make_verdict(stats),
        "analysis_stats": stats,
        "vt_reputation": attributes.get(
            "reputation"
        ),
        "country": attributes.get(
            "country"
        ),
        "asn": attributes.get(
            "asn"
        ),
        "as_owner": attributes.get(
            "as_owner"
        ),
        "network": attributes.get(
            "network"
        )
    }


def analyze_reputation(
    iocs,
    candidate_origin_ip=None,
    domain_limit=5,
    ip_limit=5
):
    domains = sorted(
        set(iocs.get("domains", []))
    )

    ips = list(
        dict.fromkeys(
            iocs.get("ips", [])
        )
    )

    if (
        candidate_origin_ip
        and candidate_origin_ip not in ips
    ):
        ips.insert(
            0,
            candidate_origin_ip
        )

    domain_results = [
        check_domain_reputation(domain)
        for domain in domains[:domain_limit]
    ]

    ip_results = [
        check_ip_reputation(ip)
        for ip in ips[:ip_limit]
    ]

    return {
        "domains": domain_results,
        "ips": ip_results
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print(
            "Usage: python -m "
            "backend.analyzers.reputation_analyzer "
            "<domain|ip> <value>"
        )
        sys.exit(1)

    target_type = sys.argv[1]
    target = sys.argv[2]

    if target_type == "domain":
        result = check_domain_reputation(
            target
        )

    elif target_type == "ip":
        result = check_ip_reputation(
            target
        )

    else:
        result = {
            "status": "error",
            "message": "Use domain or ip"
        }

    print(
        json.dumps(
            result,
            indent=4
        )
    )


def check_file_hash_reputation(sha256):
    sha256 = (sha256 or "").lower().strip()

    if len(sha256) != 64:
        return {
            "type": "file_hash",
            "value": sha256,
            "status": "skipped",
            "reason": "Invalid SHA-256 hash"
        }

    response = vt_request(
        f"/files/{sha256}"
    )

    if response.get("status") != "success":

        message = response.get(
            "message",
            "VirusTotal lookup failed"
        )

        # A previously unseen harmless/demo file will
        # commonly not exist in VirusTotal.
        if "HTTP error 404" in message:
            return {
                "type": "file_hash",
                "value": sha256,
                "status": "not_found",
                "verdict": "UNKNOWN",
                "message": (
                    "Hash was not found in VirusTotal."
                )
            }

        return {
            "type": "file_hash",
            "value": sha256,
            **response
        }

    attributes = (
        response["data"]
        .get("data", {})
        .get("attributes", {})
    )

    stats = attributes.get(
        "last_analysis_stats",
        {}
    )

    return {
        "type": "file_hash",
        "value": sha256,
        "status": "success",
        "verdict": make_verdict(stats),
        "analysis_stats": stats,
        "vt_reputation": attributes.get(
            "reputation"
        ),
        "file_type": attributes.get(
            "type_description"
        ),
        "meaningful_name": attributes.get(
            "meaningful_name"
        ),
        "size": attributes.get(
            "size"
        )
    }


def analyze_attachment_reputation(attachment_data):
    results = []

    for attachment in attachment_data.get(
        "attachments",
        []
    ):
        sha256 = attachment.get("sha256")

        reputation = check_file_hash_reputation(
            sha256
        )

        reputation["filename"] = attachment.get(
            "filename"
        )

        results.append(
            reputation
        )

    return results
