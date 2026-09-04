"""SpoofZero forensic pipeline with bounded input and partial-enrichment resilience."""
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from time import perf_counter
from uuid import uuid4

from .analyzers.email_parser import parse_email
from .analyzers.header_analyzer import analyze_sender_identity
from .analyzers.auth_analyzer import analyze_authentication
from .analyzers.ioc_extractor import extract_iocs, sha256_file
from .analyzers.relay_tracer import trace_relays
from .analyzers.nlp_detector import analyze_text
from .analyzers.geo_analyzer import geolocate_ip
from .analyzers.threat_intel import analyze_domains
from .analyzers.reputation_analyzer import analyze_reputation, analyze_attachment_reputation
from .analyzers.attachment_analyzer import analyze_attachments
from .analyzers.fusion_engine import calculate_final_risk
from .external_services import ERROR, FAILURE_STATUSES, SKIPPED, UNAVAILABLE, service_result
from .fusion_policy import CURRENT_FUSION_POLICY
from .input_safety import DEFAULT_EMAIL_LIMITS
from .observability import log_event
from .runtime_config import get_runtime_config

EXTERNAL_CONCURRENCY = 4

def _timed(label, function, analysis_id):
    started = perf_counter()
    try:
        return function()
    finally:
        log_event("analyzer_complete", analyzer=label, analysis_id=analysis_id,
                  duration_ms=(perf_counter() - started) * 1000)

def _safe_external(label, function, fallback, analysis_id):
    started = perf_counter()
    try:
        return function()
    except Exception:
        log_event("analyzer_failure", analyzer=label, analysis_id=analysis_id,
                  duration_ms=(perf_counter() - started) * 1000, service_status=ERROR)
        return fallback()

def _failure_items(value, path=""):
    failures = []
    if isinstance(value, dict):
        status = value.get("service_status")
        if status in FAILURE_STATUSES:
            failures.append({"analyzer": path or "enrichment", "status": status})
        if value.get("evidence_status") == "PARTIAL":
            failures.append({"analyzer": path or "enrichment", "status": "PARTIAL"})
        for key, child in value.items():
            failures.extend(_failure_items(child, f"{path}.{key}".strip(".")))
    elif isinstance(value, list):
        for child in value:
            failures.extend(_failure_items(child, path))
    return failures

def analysis_health(result):
    """Summarize availability without changing the established result schema."""
    failures = _failure_items({
        "threat_intelligence": result.get("threat_intelligence", []),
        "reputation": result.get("reputation", {}),
        "attachment_reputation": result.get("attachment_reputation", []),
        "geo_analysis": result.get("geo_analysis", {}),
    })
    for source, processing in (
        ("email_input", (result.get("email") or {}).get("processing") or {}),
        ("attachments", (result.get("attachments") or {}).get("processing") or {}),
    ):
        if processing.get("status") == "PARTIAL":
            failures.append({"analyzer": source, "status": "PARTIAL"})
    failures = list({
        (item["analyzer"], item["status"]): item for item in failures
    }.values())
    return {
        "status": "PARTIAL" if failures else "COMPLETE",
        "message": (
            "Some evidence could not be checked. Unavailable evidence was not treated as safe."
            if failures else "All configured evidence checks completed."
        ),
        "unavailable_evidence": failures,
    }


def analyze_email(
        file_path, *, analysis_id=None, limits=None, external_services_enabled=None):
    started = perf_counter()
    analysis_id = analysis_id or uuid4().hex
    limits = limits or DEFAULT_EMAIL_LIMITS
    email_data = _timed("email_parser", lambda: parse_email(file_path, limits=limits), analysis_id)
    sender_identity = _timed("sender_identity", lambda: analyze_sender_identity(email_data), analysis_id)
    authentication = _timed("authentication", lambda: analyze_authentication(email_data), analysis_id)
    iocs = _timed("ioc_extractor", lambda: extract_iocs(email_data), analysis_id)
    relay_trace = _timed("relay_tracer", lambda: trace_relays(email_data), analysis_id)
    ai_analysis = _timed("nlp_detector", lambda: analyze_text(email_data), analysis_id)
    attachments = _timed(
        "attachment_analyzer", lambda: analyze_attachments(file_path, limits=limits), analysis_id)
    candidate_ip = relay_trace.get("candidate_origin_ip")
    if external_services_enabled is None:
        external_services_enabled = get_runtime_config().external_services_enabled

    domain_failure = lambda: [
        {"domain": domain, **service_result(ERROR, "Domain intelligence could not be completed."),
         "risk_score": None, "indicators": ["Unavailable evidence is not a safe result."]}
        for domain in iocs.get("domains", [])[:8]
    ]
    reputation_failure = lambda: {
        "domains": [
            {"type": "domain", "value": domain,
             **service_result(ERROR, "Reputation lookup could not be completed.")}
            for domain in iocs.get("domains", [])[:5]
        ],
        "ips": [
            {"type": "ip", "value": ip,
             **service_result(ERROR, "Reputation lookup could not be completed.")}
            for ip in iocs.get("ips", [])[:5]
        ],
    }
    attachment_failure = lambda: [
        {"type": "file_hash", "value": item.get("sha256"), "filename": item.get("filename"),
         "lookup_method": "sha256_only",
         **service_result(ERROR, "Attachment hash reputation could not be completed.")}
        for item in attachments.get("attachments", [])
    ]
    if external_services_enabled:
        tasks = {
            "threat_intelligence": (
                lambda: analyze_domains(iocs.get("domains", [])), domain_failure),
            "reputation": (
                lambda: analyze_reputation(iocs, candidate_ip), reputation_failure),
            "attachment_reputation": (
                lambda: analyze_attachment_reputation(attachments), attachment_failure),
        }
        if candidate_ip:
            tasks["geolocation"] = (
                lambda: geolocate_ip(candidate_ip),
                lambda: {"ip": candidate_ip, **service_result(
                    ERROR, "Geolocation could not be completed.")},
            )
        with ThreadPoolExecutor(max_workers=EXTERNAL_CONCURRENCY,
                                thread_name_prefix="spoofzero-enrichment") as executor:
            future_map = {
                name: executor.submit(_safe_external, name, function, fallback, analysis_id)
                for name, (function, fallback) in tasks.items()
            }
            enrichment = {name: future.result() for name, future in future_map.items()}
    else:
        disabled = "External intelligence is disabled for this analysis."
        enrichment = {
            "threat_intelligence": [
                {
                    "domain": domain, **service_result(UNAVAILABLE, disabled),
                    "risk_score": None,
                    "indicators": ["External intelligence disabled; no safety conclusion was made."],
                }
                for domain in iocs.get("domains", [])[:8]
            ],
            "reputation": {
                "domains": [
                    {"type": "domain", "value": domain,
                     **service_result(UNAVAILABLE, disabled)}
                    for domain in iocs.get("domains", [])[:5]
                ],
                "ips": [
                    {"type": "ip", "value": ip, **service_result(UNAVAILABLE, disabled)}
                    for ip in list(dict.fromkeys(
                        ([candidate_ip] if candidate_ip else []) + iocs.get("ips", [])
                    ))[:5]
                ],
            },
            "attachment_reputation": [
                {
                    "type": "file_hash", "value": item.get("sha256"),
                    "filename": item.get("filename"), "lookup_method": "sha256_only",
                    **service_result(UNAVAILABLE, disabled),
                }
                for item in attachments.get("attachments", [])
            ],
        }
        if candidate_ip:
            enrichment["geolocation"] = {
                "ip": candidate_ip, **service_result(UNAVAILABLE, disabled)
            }
    if candidate_ip:
        geo_analysis = enrichment["geolocation"]
    else:
        geo_analysis = {
            "status": "not_available", "service_status": SKIPPED,
            "message": "No reliable public origin IP was identified in the relay chain.",
        }
    threat_intelligence = enrichment["threat_intelligence"]
    reputation = enrichment["reputation"]
    attachment_reputation = enrichment["attachment_reputation"]

    final_assessment = calculate_final_risk(
        sender_identity, authentication, relay_trace, ai_analysis,
        reputation, attachment_reputation, policy_version=CURRENT_FUSION_POLICY)
    health = analysis_health({
        "email": {"processing": email_data.get("processing") or {}},
        "attachments": attachments,
        "threat_intelligence": threat_intelligence,
        "reputation": reputation,
        "attachment_reputation": attachment_reputation,
        "geo_analysis": geo_analysis,
    })
    duration_ms = round((perf_counter() - started) * 1000, 3)
    log_event("analysis_complete", analyzer="pipeline", analysis_id=analysis_id,
              duration_ms=duration_ms,
              service_status=health["status"])
    return {
        "email": {
            "subject": email_data.get("subject"), "from": email_data.get("from"),
            "to": email_data.get("to"), "date": email_data.get("date"),
            "reply_to": email_data.get("reply_to"), "return_path": email_data.get("return_path"),
            "message_id": email_data.get("message_id"), "sha256": sha256_file(file_path),
            "processing": email_data.get("processing") or {},
        },
        "final_assessment": final_assessment, "ai_analysis": ai_analysis,
        "sender_identity": sender_identity, "authentication": authentication,
        "iocs": iocs, "attachments": attachments,
        "attachment_reputation": attachment_reputation, "reputation": reputation,
        "threat_intelligence": threat_intelligence, "relay_trace": relay_trace,
        "geo_analysis": geo_analysis,
    }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m backend.analyze <email.eml>")
        sys.exit(1)
    print(json.dumps(analyze_email(sys.argv[1]), indent=4))
