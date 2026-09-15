"""Privacy-minimal adapters over existing analyzer output; no scoring or network calls."""
from collections.abc import Mapping
from hashlib import sha256
import json
import math
import re
from typing import TypedDict

from .evidence_confidence import ConfidenceLevel, EvidenceRole, classify_confidence
from .fusion_policy import CURRENT_FUSION_POLICY, valid_number

HASH = re.compile(r"[a-f0-9]{64}")
AUTH_RESULTS = frozenset({
    "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror",
    "policy", "bestguesspass", "mixed", "unknown",
})
STATUSES = frozenset({
    "AVAILABLE", "PARTIAL", "MISSING", "NOT_FOUND", "TIMEOUT", "ERROR",
    "SKIPPED", "UNAVAILABLE", "RATE_LIMITED", "MALFORMED", "NOT_CHECKED", "NOT_APPLICABLE",
})


class Finding(TypedDict):
    finding_id: str
    signal_code: str
    category: str
    source_analyzer: str
    source_paths: list[str]
    observed_value: object
    availability: str
    evidence_identity: str
    confidence: ConfidenceLevel | None
    confidence_explanation: str
    evidence_role: EvidenceRole
    rule_id: str
    scoring_policy_version: str
    raw_contribution: float | None
    applied_contribution: float
    suppression_reason: str | None
    related_groups: list[str]
    occurrence_count: int
    coverage_scope: bool
    ledger_key: str | None


def mapping(value):
    return value if isinstance(value, Mapping) else {}


def sequence(value):
    return value if isinstance(value, (list, tuple)) else []


def _identity_value(value):
    """Keep malformed non-finite identities deterministic and JSON-safe."""
    if isinstance(value, float) and not math.isfinite(value):
        return "[non-finite]"
    if isinstance(value, Mapping):
        return {str(key): _identity_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_identity_value(item) for item in value]
    return value


def _digest(value):
    return sha256(json.dumps(_identity_value(value), sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, default=str, allow_nan=False).encode()).hexdigest()


def _number(value):
    return float(value) if valid_number(value) else None


def service_availability(value):
    value = mapping(value)
    if value.get("error_type") == "MALFORMED_RESPONSE":
        return "MALFORMED"
    status = value.get("service_status")
    if status is None:
        legacy_status = value.get("status")
        status = {"success": "SUCCESS", "error": "ERROR", "not_found": "NOT_FOUND",
                  "skipped": "SKIPPED", "reserved_demo": "SKIPPED"}.get(legacy_status if isinstance(legacy_status, str) else "")
    if status == "SUCCESS":
        return "PARTIAL" if value.get("partial") or value.get("evidence_status") == "PARTIAL" else "AVAILABLE"
    return status if isinstance(status, str) and status in STATUSES else "MISSING"


def reputation_availability(item):
    """Validate the same structured detection contract as the provider adapter."""
    item = mapping(item)
    availability = service_availability(item)
    if availability not in {"AVAILABLE", "PARTIAL"}:
        return availability
    stats = item.get("analysis_stats")
    if (item.get("status") != "success" or not isinstance(stats, Mapping) or not stats
            or not all(type(v) is int and v >= 0 for v in stats.values())
            or not any(k in stats for k in ("malicious", "suspicious", "harmless", "undetected"))):
        return "MALFORMED"
    return availability


def normalize_findings(analysis, *, policy_version=CURRENT_FUSION_POLICY):
    """Return deterministic assertions and opaque identities, never raw message values.

    Category aggregates own numeric contributions when later bound to the fusion
    ledger. Their child observations are references, not additional risk points.
    """
    data = mapping(analysis)
    findings = {}

    def add(code, category, path, observed, assertion, *, identity=None,
            availability="AVAILABLE", source=None, conflicting=False, ledger=None,
            groups=(), coverage=True, reason=None):
        identity = _digest([category, identity if identity is not None else code])
        finding_id = "F-" + _digest([code, identity, observed, availability])[:32]
        confidence = classify_confidence(assertion, availability, source=source,
                                         conflicting=conflicting)
        if finding_id in findings:
            previous = findings[finding_id]
            previous["source_paths"] = sorted(set(previous["source_paths"] + [path]))
            previous["occurrence_count"] += 1
            # Duplicate claims with weaker provenance cannot become stronger by order.
            rank = {None: -1, "LOW": 0, "MEDIUM": 1, "HIGH": 2}
            if (rank[confidence["level"]], confidence["explanation"]) < (
                rank[previous["confidence"]], previous["confidence_explanation"]
            ):
                previous["confidence"] = confidence["level"]
                previous["confidence_explanation"] = confidence["explanation"]
            previous["suppression_reason"] = "Repeated observation merged by evidence identity; no additional contribution."
            return previous
        finding = {
            "finding_id": finding_id, "signal_code": code, "category": category,
            "source_analyzer": path.strip("/").split("/")[0],
            "source_paths": [path], "observed_value": observed,
            "availability": availability, "evidence_identity": identity,
            "confidence": confidence["level"], "confidence_explanation": confidence["explanation"],
            "evidence_role": "CONTEXTUAL" if availability in {"AVAILABLE", "PARTIAL", "NOT_APPLICABLE"} else "UNAVAILABLE",
            "rule_id": ledger or code.lower(), "scoring_policy_version": policy_version,
            "raw_contribution": None, "applied_contribution": 0.0,
            "suppression_reason": reason, "related_groups": sorted(set(groups)),
            "occurrence_count": 1, "coverage_scope": coverage, "ledger_key": ledger,
        }
        findings[finding_id] = finding
        return finding

    email = mapping(data.get("email"))
    processing = mapping(email.get("processing"))
    processing_status = processing.get("status")
    input_state = {"COMPLETE": "AVAILABLE", "PARTIAL": "PARTIAL"}.get(
        processing_status if isinstance(processing_status, str) else "", "MISSING")
    add("EMAIL_PROCESSING", "INPUT", "/email/processing", None, "extraction", availability=input_state)
    digest = email.get("sha256")
    add("EMAIL_SHA256", "INPUT", "/email/sha256", "SHA-256", "hash",
        identity=digest if isinstance(digest, str) and HASH.fullmatch(digest) else None,
        availability="AVAILABLE" if isinstance(digest, str) and HASH.fullmatch(digest) else "MISSING",
        coverage=False)

    sender = mapping(data.get("sender_identity"))
    sender_findings = sequence(sender.get("findings"))
    sender_state = "AVAILABLE" if sender.get("from_domain") else "MISSING"
    add("IDENTITY_ASSESSMENT", "IDENTITY", "/sender_identity", _number(sender.get("risk_score")),
        "identity", availability=sender_state, ledger="sender_identity",
        groups=("sender_auth_identity",), reason="Existing aggregate identity weighting; child findings are not added again.")
    for index, item in enumerate(sender_findings):
        code = mapping(item).get("type")
        if isinstance(code, str) and code in {"FROM_REPLY_TO_MISMATCH", "FROM_RETURN_PATH_MISMATCH"}:
            add(code, "IDENTITY", f"/sender_identity/findings/{index}", "DOMAIN_DIFFERENCE",
                "identity", groups=("sender_auth_identity",), coverage=False,
                reason="Explained by the identity aggregate; no separate points.")

    auth = mapping(data.get("authentication"))
    provenance = mapping(auth.get("evidence_confidence"))
    source = provenance.get("source")
    conflicted = (provenance.get("level") == "low" or any(auth.get(m) == "mixed" for m in ("spf", "dkim", "dmarc")))
    auth_state = "PARTIAL" if auth.get("evidence_state") == "inconclusive" or conflicted else "AVAILABLE"
    if not isinstance(source, str) or source not in {"configured_receiver", "receiver_inferred", "untrusted"}:
        auth_state = "MISSING"
    add("AUTHENTICATION_ASSESSMENT", "AUTHENTICATION", "/authentication",
        _number(auth.get("risk_score")), "reported_authentication", availability=auth_state,
        source=source, conflicting=conflicted, ledger="authentication", coverage=auth_state != "AVAILABLE",
        groups=("authentication", "sender_auth_identity"),
        reason="Existing authentication aggregate; SPF/DKIM/DMARC may overlap. No new deduction is applied.")
    for method in ("spf", "dkim", "dmarc"):
        status = auth.get(method)
        observed = status if isinstance(status, str) and status in AUTH_RESULTS else "unknown"
        availability = "MISSING" if observed == "unknown" else "PARTIAL" if observed in {
            "mixed", "temperror", "permerror", "bestguesspass"} else "AVAILABLE"
        add("REPORTED_" + method.upper(), "AUTHENTICATION", "/authentication/" + method,
            observed, "reported_authentication", availability=availability, source=source,
            conflicting=conflicted, groups=("authentication",),
            reason="Method observation belongs to the authentication aggregate.")
    selected = sequence(auth.get("selected_report_indices"))
    for index, report in enumerate(sequence(auth.get("reports"))):
        report = mapping(report)
        for offset, entry in enumerate(sequence(report.get("methods"))):
            entry = mapping(entry)
            method = entry.get("method")
            if not isinstance(method, str) or method not in {"spf", "dkim", "dmarc"}:
                continue
            value = entry.get("result")
            value = value if isinstance(value, str) and value in AUTH_RESULTS else "unknown"
            add("AUTH_REPORT_" + method.upper(), "AUTHENTICATION",
                f"/authentication/reports/{index}/methods/{offset}",
                {"result": value, "selected": report.get("header_index", index) in selected},
                "reported_authentication",
                identity=[report.get("authserv_id"), method, mapping(entry.get("identities"))],
                source=report.get("source"), conflicting=bool(report.get("malformed")) or not entry.get("usable", True),
                availability="AVAILABLE" if entry.get("usable", True) and value != "unknown" else "PARTIAL",
                groups=("authentication",), coverage=False,
                reason="Reported claim retained as context; the selected aggregate owns points.")
    for index, item in enumerate(sequence(auth.get("findings"))):
        code = mapping(item).get("type")
        if isinstance(code, str) and code in {"FROM_SPF_MISMATCH", "FROM_DKIM_MISMATCH", "DMARC_FROM_MISMATCH",
                    "DMARC_ALIGNMENT_UNSUPPORTED", "AUTH_FROM_AMBIGUOUS", "AUTH_RESULTS_MALFORMED"}:
            add(code, "AUTHENTICATION", f"/authentication/findings/{index}", None,
                "reported_authentication", source=source, conflicting=conflicted,
                groups=("authentication", "sender_auth_identity"), coverage=False,
                reason="Alignment/quality context; no extra numeric contribution.")

    iocs = mapping(data.get("iocs"))
    for kind in ("urls", "domains", "ips", "emails"):
        values = iocs.get(kind)
        add("EXTRACTED_" + kind.upper(), "IOC", "/iocs/" + kind,
            {"count": len(values)} if isinstance(values, (list, tuple)) else None, "extraction",
            availability=input_state if isinstance(values, (list, tuple)) else "MISSING",
            reason="Extraction is contextual; indicator presence alone receives no threat points.")

    attachments = mapping(data.get("attachments"))
    attachment_state = mapping(attachments.get("processing")).get("status")
    add("ATTACHMENT_PROCESSING", "ATTACHMENT", "/attachments/processing", None, "extraction",
        availability={"COMPLETE": "AVAILABLE", "PARTIAL": "PARTIAL"}.get(
            attachment_state if isinstance(attachment_state, str) else "", "MISSING"))
    for index, item in enumerate(sequence(attachments.get("attachments"))):
        item = mapping(item)
        digest = item.get("sha256")
        complete = (isinstance(digest, str) and HASH.fullmatch(digest)
                    and item.get("status") in (None, "success")
                    and valid_number(item.get("size_bytes")) and item["size_bytes"] >= 0)
        add("ATTACHMENT_SHA256", "ATTACHMENT", f"/attachments/attachments/{index}/sha256",
            "SHA-256", "hash", identity=digest if isinstance(digest, str) else ["unhashed", index],
            availability="AVAILABLE" if complete else "UNAVAILABLE",
            reason="Hash identity does not establish maliciousness and adds no points by itself.")

    reputation = mapping(data.get("reputation"))
    provider_groups = (
        ("reputation", "REPUTATION", [(f"/reputation/{kind}/{index}", mapping(item))
            for kind in ("domains", "ips") for index, item in enumerate(sequence(reputation.get(kind)))]),
        ("attachment", "ATTACHMENT", [(f"/attachment_reputation/{index}", mapping(item))
            for index, item in enumerate(sequence(data.get("attachment_reputation")))]),
    )
    for ledger, category, items in provider_groups:
        availability = [reputation_availability(item) for _, item in items]
        usable = any(x in {"AVAILABLE", "PARTIAL"} for x in availability)
        aggregate = "AVAILABLE" if usable else "UNAVAILABLE" if items else "NOT_APPLICABLE"
        add("REPUTATION_ASSESSMENT" if ledger == "reputation" else "ATTACHMENT_REPUTATION_ASSESSMENT",
            category, "/reputation" if ledger == "reputation" else "/attachment_reputation",
            None, "provider", availability=aggregate, ledger=ledger, coverage=False,
            groups=(category.lower(),), reason="Existing strongest-observation bonus; repeated IOCs and engine totals do not stack.")
        for (path, item), state in zip(items, availability):
            stats = mapping(item.get("analysis_stats"))
            observed = {k: stats[k] for k in ("malicious", "suspicious", "harmless", "undetected")
                        if type(stats.get(k)) is int and stats[k] >= 0}
            add("VT_OBSERVATION", category, path, observed or None, "provider",
                identity=[item.get("type"), item.get("value", item.get("sha256", path))],
                availability=state, groups=(category.lower(),),
                reason="Provider observation is represented by the category maximum, not added separately.")

    # Account for known omissions without repeating an IOC value or making new calls.
    for kind, expected, actual, label in (
        ("domains", iocs.get("domains"), reputation.get("domains"), "VT_DOMAIN_NOT_CHECKED"),
        ("ips", iocs.get("ips"), reputation.get("ips"), "VT_IP_NOT_CHECKED"),
    ):
        checked = {x.get("value") for x in map(mapping, sequence(actual)) if isinstance(x.get("value"), str)}
        for index, value in enumerate(sequence(expected)):
            if isinstance(value, str) and value not in checked:
                add(label, "REPUTATION", f"/iocs/{kind}/{index}", None, "provider",
                    identity=[kind, value], availability="NOT_CHECKED",
                    reason="No lookup observation was retained; it may be outside the lookup budget.")

    checked_ips = {item.get("value") for item in map(mapping, sequence(reputation.get("ips")))
                   if isinstance(item.get("value"), str)}
    origin = mapping(data.get("relay_trace")).get("candidate_origin_ip")
    if isinstance(origin, str) and origin not in checked_ips:
        add("VT_IP_NOT_CHECKED", "REPUTATION", "/relay_trace/candidate_origin_ip",
            None, "provider", identity=["ips", origin], availability="NOT_CHECKED",
            reason="No reputation observation was retained for the candidate origin IP.")
    checked_hashes = {item.get("value") for item in map(mapping, sequence(data.get("attachment_reputation")))
                      if isinstance(item.get("value"), str)}
    for index, item in enumerate(sequence(attachments.get("attachments"))):
        digest = mapping(item).get("sha256")
        if isinstance(digest, str) and HASH.fullmatch(digest) and digest not in checked_hashes:
            add("VT_HASH_NOT_CHECKED", "ATTACHMENT",
                f"/attachments/attachments/{index}/sha256", None, "provider",
                identity=["file_hash", digest], availability="NOT_CHECKED",
                reason="No hash-reputation observation was retained; unknown does not mean safe.")

    domain_data = sequence(data.get("threat_intelligence"))
    checked_domains = set()
    for index, item in enumerate(domain_data):
        item = mapping(item)
        domain = item.get("domain")
        if isinstance(domain, str):
            checked_domains.add(domain)
        for provider in ("dns", "rdap"):
            observation = mapping(item.get(provider))
            state = service_availability(observation or item)
            if not observation and state == "AVAILABLE":
                state = "MISSING"
            add(provider.upper() + "_CONTEXT", "INFRASTRUCTURE",
                f"/threat_intelligence/{index}/{provider}", None, "provider",
                identity=[provider, domain], availability=state,
                reason="DNS/RDAP is contextual; partial failure is not authoritative record absence.")
    for index, value in enumerate(sequence(iocs.get("domains"))):
        if isinstance(value, str) and value not in checked_domains:
            add("DNS_RDAP_NOT_CHECKED", "INFRASTRUCTURE", f"/iocs/domains/{index}", None,
                "provider", identity=value, availability="NOT_CHECKED",
                reason="No DNS/RDAP observation was retained; no absence conclusion is made.")

    relay = mapping(data.get("relay_trace"))
    hops = sequence(relay.get("hops"))
    add("RELAY_ASSESSMENT", "RELAY", "/relay_trace/hops", None, "relay",
        availability="AVAILABLE" if hops else "MISSING", ledger="relay", coverage=not bool(hops),
        reason="Existing one-time relay bonus; multiple mismatches do not stack.")
    add("RELAY_ORIGIN", "RELAY", "/relay_trace/candidate_origin_ip", "INFRASTRUCTURE_CANDIDATE",
        "relay", availability="AVAILABLE" if relay.get("candidate_origin_ip") else "NOT_APPLICABLE")
    for index, hop in enumerate(hops):
        hop = mapping(hop)
        status = hop.get("chain_status")
        status = status if isinstance(status, str) else None
        add("RELAY_CONTINUITY", "RELAY", f"/relay_trace/hops/{index}",
            status if status in {"START", "MATCHED", "MISMATCH"} else None, "relay",
            identity=[hop.get("from_host"), hop.get("by_host")],
            availability="AVAILABLE" if status in {"START", "MATCHED", "MISMATCH"} else "MALFORMED",
            groups=("relay",), reason="Continuity heuristic belongs to one relay bonus, not one bonus per hop.")

    ai = mapping(data.get("ai_analysis"))
    signal = _number(ai.get("phishing_probability"))
    add("ML_PHISHING_SIGNAL", "ML", "/ai_analysis", signal if signal is not None and 0 <= signal <= 100 else None,
        "ml", availability="AVAILABLE" if signal is not None and 0 <= signal <= 100 else "MALFORMED",
        ledger="ai", reason="Numeric participation requires the existing model validation and policy-specific authorization gates.")
    geo = mapping(data.get("geo_analysis"))
    geo_state = service_availability(geo)
    if not relay.get("candidate_origin_ip") and geo.get("service_status") == "SKIPPED":
        geo_state = "NOT_APPLICABLE"
    add("GEOLOCATION_CONTEXT", "GEOLOCATION", "/geo_analysis", None, "geo",
        availability=geo_state, reason="Infrastructure context only; no geographic threat points.")

    assessment = mapping(data.get("final_assessment"))
    if mapping(assessment.get("authentication_context")).get("finding"):
        add("AUTH_PASS_SUSPICIOUS_BEHAVIOR", "REVIEW",
            "/final_assessment/authentication_context/finding", None, "reported_authentication",
            source=source, conflicting=conflicted, groups=("authentication", "sender_auth_identity"),
            coverage=False, reason="Derived review finding summarizes existing signals and receives no additional points.")

    return sorted(findings.values(), key=lambda f: f["finding_id"])
