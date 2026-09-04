"""DNS and RDAP intelligence with bounded, expiring local caches."""
import json
import sys
import socket
import urllib.parse
from copy import deepcopy
import dns.exception
import dns.resolver
from backend.external_services import (
    ERROR, NOT_FOUND, SUCCESS, TIMEOUT, UNAVAILABLE, TTLCache, request_json, service_result,
)
from backend.observability import log_event
from backend.input_safety import normalized_domain
from backend.runtime_config import get_runtime_config

RESERVED_DEMO_DOMAINS = ("example.com", "example.net", "example.org")
DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT")
DNS_CACHE, RDAP_CACHE = TTLCache(256), TTLCache(256)
DNS_TTL_SECONDS, FAILURE_TTL_SECONDS, RDAP_TTL_SECONDS = 300, 20, 900

def clear_threat_intel_cache():
    DNS_CACHE.clear()
    RDAP_CACHE.clear()

def is_reserved_demo_domain(domain):
    domain = str(domain or "").lower().rstrip(".")
    return domain.endswith((".test", ".invalid", ".localhost")) or any(
        domain == reserved or domain.endswith("." + reserved)
        for reserved in RESERVED_DEMO_DOMAINS)

def dns_lookup(domain):
    config = get_runtime_config()
    if not config.dns_enabled:
        return {
            **{kind: [] for kind in DNS_TYPES},
            **service_result(UNAVAILABLE, "DNS intelligence is disabled."),
            "cache_hit": False, "partial": False,
        }
    key = ("dns", str(domain).lower().rstrip("."))
    cached = DNS_CACHE.get(key)
    if cached is not None:
        cached["cache_hit"] = True
        return cached
    results = {kind: [] for kind in DNS_TYPES}
    failures, found_authoritative_absence = [], False
    for record_type in DNS_TYPES:
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=config.dns_timeout_seconds)
            results[record_type].extend(str(answer).strip('"') for answer in answers)
        except dns.resolver.NXDOMAIN:
            found_authoritative_absence = True
            break
        except dns.resolver.NoAnswer:
            continue
        except (dns.exception.Timeout, LifetimeTimeout, socket.timeout):
            failures.append(TIMEOUT)
        except dns.resolver.NoNameservers:
            failures.append(UNAVAILABLE)
        except Exception:
            failures.append(ERROR)
    if found_authoritative_absence:
        status = NOT_FOUND
    elif failures and len(failures) == len(DNS_TYPES):
        status = TIMEOUT if all(x == TIMEOUT for x in failures) else UNAVAILABLE
    else:
        status = SUCCESS
    results.update(service_status=status, status="success" if status == SUCCESS else
                   "not_found" if status == NOT_FOUND else "error",
                   cache_hit=False, partial=bool(failures and status == SUCCESS))
    ttl = (config.dns_cache_ttl_seconds if status in {SUCCESS, NOT_FOUND}
           else config.failure_cache_ttl_seconds)
    DNS_CACHE.set(key, results, ttl)
    log_event("external_request", analyzer="dns", service_status=status, cache_hit=False)
    return results

# dnspython exposes this under resolver on supported versions.
LifetimeTimeout = getattr(dns.resolver, "LifetimeTimeout", dns.exception.Timeout)

def rdap_lookup(domain):
    config = get_runtime_config()
    if not config.rdap_enabled:
        return service_result(UNAVAILABLE, "RDAP intelligence is disabled.")
    response = request_json(
        "rdap", "https://rdap.org/domain/" + urllib.parse.quote(str(domain), safe=""),
        headers={"User-Agent": "SpoofZero/1.0"}, timeout=config.rdap_timeout_seconds,
        cache=RDAP_CACHE, cache_key=str(domain).lower().rstrip("."),
        ttl_seconds=config.rdap_cache_ttl_seconds,
        failure_ttl_seconds=config.failure_cache_ttl_seconds,
    )
    if response.get("service_status") != SUCCESS:
        return response
    data = response.get("data")
    if not isinstance(data, dict):
        return service_result(ERROR, "RDAP returned an incomplete record.",
                              error_type="MALFORMED_RESPONSE")
    event_items = data.get("events") or []
    ns_items = data.get("nameservers") or []
    if not isinstance(event_items, list) or not isinstance(ns_items, list):
        return service_result(ERROR, "RDAP returned malformed record fields.",
                              error_type="MALFORMED_RESPONSE")
    events = {event.get("eventAction"): event.get("eventDate")
              for event in event_items if isinstance(event, dict) and event.get("eventAction")}
    nameservers = [item.get("ldhName") for item in ns_items
                   if isinstance(item, dict) and item.get("ldhName")]
    return {
        "status": "success", "service_status": SUCCESS, "handle": data.get("handle"),
        "registration_date": events.get("registration"), "expiration_date": events.get("expiration"),
        "last_changed": events.get("last changed"), "nameservers": nameservers,
        "cache_hit": response.get("cache_hit", False), "attempts": response.get("attempts", 1),
    }

def analyze_domain(domain):
    domain = normalized_domain(domain)
    if domain is None:
        return {"domain": "INVALID", **service_result(ERROR, "Invalid domain."),
                "risk_score": None, "indicators": ["Invalid domain was not queried."]}
    if is_reserved_demo_domain(domain):
        return {"domain": domain, "status": "reserved_demo", "service_status": "SKIPPED",
                "risk_score": 0, "dns": {}, "rdap": {},
                "indicators": ["Reserved demo/test domain — real reputation lookup skipped"]}
    dns_data, rdap_data = dns_lookup(domain), rdap_lookup(domain)
    indicators, risk_score = [], 0
    dns_status = dns_data.get("service_status")
    if dns_status in {TIMEOUT, UNAVAILABLE, ERROR}:
        risk_score = None
        indicators.append("DNS evidence unavailable; no safety conclusion was made.")
    else:
        total = sum(len(dns_data[kind]) for kind in DNS_TYPES)
        if total == 0:
            indicators.append("No DNS records found")
            risk_score += 20
        if not dns_data["NS"]:
            indicators.append("No authoritative nameserver record found")
            risk_score += 10
        if dns_data["MX"] == ["0 ."]:
            indicators.append("Null MX detected — domain intentionally does not receive email")
        elif not dns_data["MX"]:
            indicators.append("No MX mail-server record found")
    if rdap_data.get("service_status") != SUCCESS:
        indicators.append("Domain registration information unavailable; no safety conclusion was made.")
    partial = bool(dns_data.get("partial")) or dns_status in {TIMEOUT, UNAVAILABLE, ERROR} or rdap_data.get("service_status") != SUCCESS
    return {"domain": domain, "status": "analyzed", "service_status": SUCCESS,
            "evidence_status": "PARTIAL" if partial else "COMPLETE",
            "risk_score": min(risk_score, 100) if risk_score is not None else None,
            "dns": dns_data, "rdap": rdap_data, "indicators": indicators}

def analyze_domains(domains, limit=8):
    unique = sorted(set(str(d).lower().strip().rstrip(".") for d in domains if d))
    results = []
    for domain in unique[:limit]:
        try:
            results.append(analyze_domain(domain))
        except Exception:
            results.append({"domain": domain, **service_result(
                ERROR, "Domain intelligence could not be completed."),
                "risk_score": None, "indicators": ["Lookup failed; no safety conclusion was made."]})
    return results

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m backend.analyzers.threat_intel <domain>")
        sys.exit(1)
    print(json.dumps(analyze_domain(sys.argv[1]), indent=4))
