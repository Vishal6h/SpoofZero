"""VirusTotal reputation lookups with classified failures and hash-only attachments."""
import ipaddress
import os
import re
import urllib.parse
from copy import deepcopy
from dotenv import load_dotenv
from backend.external_services import (
    ERROR, NOT_FOUND, RATE_LIMITED, SKIPPED, SUCCESS, UNAVAILABLE, TTLCache, request_json, service_result,
)
from .threat_intel import is_reserved_demo_domain
from backend.input_safety import normalized_domain

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_CACHE = TTLCache(max_entries=512)
VT_COOLDOWN = TTLCache(max_entries=1)
MAX_ATTACHMENT_HASH_LOOKUPS = 10
VT_SUCCESS_TTL_SECONDS = 300
VT_FAILURE_TTL_SECONDS = 20

def clear_reputation_cache():
    VT_CACHE.clear()
    VT_COOLDOWN.clear()

def vt_request(endpoint):
    if not VT_API_KEY:
        return service_result(UNAVAILABLE, "VirusTotal API key is not configured.")
    cooldown = VT_COOLDOWN.get("rate_limit")
    if cooldown is not None:
        return {**cooldown, "attempts": 0, "cache_hit": True}
    result = request_json(
        "virustotal", VT_BASE_URL + endpoint,
        headers={"x-apikey": VT_API_KEY, "User-Agent": "SpoofZero/1.0"},
        timeout=15, cache=VT_CACHE, cache_key=endpoint,
        ttl_seconds=VT_SUCCESS_TTL_SECONDS,
        failure_ttl_seconds=VT_FAILURE_TTL_SECONDS,
    )
    if result.get("service_status") == RATE_LIMITED:
        VT_COOLDOWN.set("rate_limit", result, 60)
    return result

def _valid_stats(attributes):
    if not isinstance(attributes, dict):
        return False
    stats = attributes.get("last_analysis_stats")
    return (
        isinstance(stats, dict) and bool(stats)
        and all(type(value) is int and value >= 0 for value in stats.values())
        and any(key in stats for key in ("malicious", "suspicious", "harmless", "undetected"))
    )

def _count(stats, key):
    value = stats.get(key, 0) if isinstance(stats, dict) else 0
    return value if type(value) is int and value >= 0 else 0

def make_verdict(stats):
    malicious, suspicious = _count(stats, "malicious"), _count(stats, "suspicious")
    if malicious >= 3:
        return "MALICIOUS"
    if malicious > 0 or suspicious >= 2:
        return "SUSPICIOUS"
    return "NO MAJOR DETECTIONS"

def _failure(kind, value, response):
    result = {"type": kind, "value": value, **deepcopy(response)}
    result.setdefault("verdict", "UNKNOWN")
    return result

def _attributes(response):
    payload = response.get("data")
    if not isinstance(payload, dict):
        return None
    record = payload.get("data")
    attributes = record.get("attributes") if isinstance(record, dict) else None
    return attributes if isinstance(attributes, dict) else None

def check_domain_reputation(domain):
    domain = normalized_domain(domain)
    if domain is None:
        return {"type": "domain", "value": "INVALID", **service_result(
            SKIPPED, reason="Invalid domain")}
    if is_reserved_demo_domain(domain):
        return {"type": "domain", "value": domain, **service_result(
            SKIPPED, reason="Reserved demo/test domain")}
    response = vt_request("/domains/" + urllib.parse.quote(domain, safe=""))
    if response.get("service_status") != SUCCESS:
        return _failure("domain", domain, response)
    attributes = _attributes(response)
    if not _valid_stats(attributes):
        return _failure("domain", domain, service_result(
            ERROR, "VirusTotal returned an incomplete domain record.",
            error_type="MALFORMED_RESPONSE"))
    stats = attributes.get("last_analysis_stats", {})
    return {
        "type": "domain", "value": domain, "status": "success", "service_status": SUCCESS,
        "verdict": make_verdict(stats), "analysis_stats": stats,
        "vt_reputation": attributes.get("reputation"), "registrar": attributes.get("registrar"),
        "categories": attributes.get("categories", {}), "cache_hit": response.get("cache_hit", False),
        "attempts": response.get("attempts", 1),
    }

def check_ip_reputation(ip_string):
    try:
        ip = ipaddress.ip_address(ip_string)
    except ValueError:
        return {"type": "ip", "value": str(ip_string), **service_result(
            SKIPPED, reason="Invalid IP")}
    value = str(ip)
    if not ip.is_global:
        return {"type": "ip", "value": value, **service_result(
            SKIPPED, reason="Private, reserved, documentation or non-public IP")}
    response = vt_request("/ip_addresses/" + urllib.parse.quote(value, safe=""))
    if response.get("service_status") != SUCCESS:
        return _failure("ip", value, response)
    attributes = _attributes(response)
    if not _valid_stats(attributes):
        return _failure("ip", value, service_result(
            ERROR, "VirusTotal returned an incomplete IP record.",
            error_type="MALFORMED_RESPONSE"))
    stats = attributes.get("last_analysis_stats", {})
    return {
        "type": "ip", "value": value, "status": "success", "service_status": SUCCESS,
        "verdict": make_verdict(stats), "analysis_stats": stats,
        "vt_reputation": attributes.get("reputation"), "country": attributes.get("country"),
        "asn": attributes.get("asn"), "as_owner": attributes.get("as_owner"),
        "network": attributes.get("network"), "cache_hit": response.get("cache_hit", False),
        "attempts": response.get("attempts", 1),
    }

def analyze_reputation(iocs, candidate_origin_ip=None, domain_limit=5, ip_limit=5):
    domains = sorted(set(iocs.get("domains", [])))
    ips = list(dict.fromkeys(iocs.get("ips", [])))
    if candidate_origin_ip and candidate_origin_ip not in ips:
        ips.insert(0, candidate_origin_ip)
    return {
        "domains": [check_domain_reputation(x) for x in domains[:domain_limit]],
        "ips": [check_ip_reputation(x) for x in ips[:ip_limit]],
    }

def check_file_hash_reputation(sha256):
    value = str(sha256 or "").lower().strip()
    if not re.fullmatch(r"[a-f0-9]{64}", value):
        return {"type": "file_hash", "value": value, **service_result(
            SKIPPED, reason="Invalid or unavailable SHA-256 hash")}
    response = vt_request("/files/" + value)
    if response.get("service_status") == NOT_FOUND:
        return {"type": "file_hash", "value": value, **response,
                "verdict": "UNKNOWN", "message": "Hash was not found in VirusTotal."}
    if response.get("service_status") != SUCCESS:
        return _failure("file_hash", value, response)
    attributes = _attributes(response)
    if not _valid_stats(attributes):
        return _failure("file_hash", value, service_result(
            ERROR, "VirusTotal returned an incomplete file-hash record.",
            error_type="MALFORMED_RESPONSE"))
    stats = attributes.get("last_analysis_stats", {})
    return {
        "type": "file_hash", "value": value, "status": "success", "service_status": SUCCESS,
        "verdict": make_verdict(stats), "analysis_stats": stats,
        "vt_reputation": attributes.get("reputation"), "file_type": attributes.get("type_description"),
        "meaningful_name": attributes.get("meaningful_name"), "size": attributes.get("size"),
        "cache_hit": response.get("cache_hit", False), "attempts": response.get("attempts", 1),
    }

def analyze_attachment_reputation(attachment_data):
    by_hash = {}
    results = []
    for attachment in attachment_data.get("attachments", []):
        digest = attachment.get("sha256")
        if digest not in by_hash:
            if len(by_hash) >= MAX_ATTACHMENT_HASH_LOOKUPS:
                by_hash[digest] = {
                    "type": "file_hash", "value": digest,
                    **service_result(UNAVAILABLE, "Attachment-hash request budget reached."),
                }
            else:
                by_hash[digest] = check_file_hash_reputation(digest)
        item = deepcopy(by_hash[digest])
        item["filename"] = attachment.get("filename")
        item["lookup_method"] = "sha256_only"
        results.append(item)
    return results



if __name__ == "__main__":
    import json
    import sys
    if len(sys.argv) != 3 or sys.argv[1] not in {"domain", "ip"}:
        print("Usage: python -m backend.analyzers.reputation_analyzer <domain|ip> <value>")
        sys.exit(1)
    result = (check_domain_reputation(sys.argv[2]) if sys.argv[1] == "domain"
              else check_ip_reputation(sys.argv[2]))
    print(json.dumps(result, indent=4))
