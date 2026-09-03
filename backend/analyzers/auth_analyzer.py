"""Reported email authentication, provenance, and offline alignment evidence.

No SPF evaluation, signature verification, or historical DNS lookup occurs here.
"""
import json
import re
import sys

from .auth_results import KNOWN_RESULTS, parse_authentication_results, split_clauses
from .domain_alignment import address_domain, compare_domains, normalize_domain
from .email_parser import parse_email


_WEIGHTS = {"spf": {"fail": 30, "softfail": 15},
            "dkim": {"fail": 30, "none": 10}, "dmarc": {"fail": 40}}
_SOURCE_RANK = {"untrusted": 0, "receiver_inferred": 1, "configured_receiver": 2}


def _headers(value):
    if isinstance(value, str):
        return [value]
    return list(value or [])


def _receiver_host(email_data):
    received = _headers(email_data.get("received"))
    if not received:
        return None
    clauses, _ = split_clauses(received[0])
    # Comments are removed so an address in a comment cannot be the receiver.
    match = re.search(r"(?:^|\s)by\s+([^\s;]+)", clauses[0], re.I) if clauses else None
    return normalize_domain(match[1]) if match else None


def _source(report, receiver, trusted_ids):
    authserv = report["authserv_id"]
    if authserv and authserv in trusted_ids:
        source, level = "configured_receiver", "medium"
        basis = "Authserv-id explicitly configured by the caller; header origin is not verified."
    elif authserv and authserv == receiver:
        source, level = "receiver_inferred", "medium"
        basis = "Exact match to the newest Received by-host; both headers remain forgeable."
    else:
        source, level = "untrusted", "low"
        basis = "No configured or exact receiving-host association was established."
    report.update(source=source, confidence=level, trust_basis=basis)
    if report["malformed"]:
        report["confidence"] = "low"


def _method_entries(reports, method):
    entries = [dict(entry, header_index=report["header_index"])
               for report in reports for entry in report["methods"] if entry["method"] == method]
    if method == "spf":
        # A HELO PASS must never override an explicit MAIL FROM failure.
        mailfrom = [entry for entry in entries if any(key in entry["properties"] for key in
                    ("smtp.mailfrom", "smtp.envelope-from", "envelope-from"))]
        if mailfrom:
            return mailfrom
    return entries


def _summary(entries, method):
    if not entries:
        return "unknown"
    statuses = {entry["result"] if entry["usable"] else "unknown" for entry in entries}
    if len(statuses) == 1:
        return next(iter(statuses))
    # Independent DKIM signatures may legitimately have different results.
    # Only distinct, identified signing domains can produce this aggregate PASS.
    if method == "dkim" and "pass" in statuses and all(
        entry["usable"] and entry["known_result"] and entry["identities"].get("signing_domain")
        for entry in entries
    ):
        by_domain = {}
        for entry in entries:
            by_domain.setdefault(entry["identities"]["signing_domain"], set()).add(entry["result"])
        if all(len(results) == 1 for results in by_domain.values()):
            return "pass"
    return "mixed"


def _comparisons(entries, visible, identity_key):
    comparisons = []
    for entry in entries:
        comparison = compare_domains(visible, entry["identities"].get(identity_key))
        comparison.update(header_index=entry["header_index"], result=entry["result"],
                          usable=entry["usable"], identities=entry["identities"])
        comparisons.append(comparison)
    return comparisons


def _passing_alignment(comparisons):
    by_identity = {}
    for comparison in comparisons:
        by_identity.setdefault(comparison["identity_domain"], set()).add(comparison["result"])
    passing = [c for c in comparisons if c["result"] == "pass" and c["usable"]
               and len(by_identity[c["identity_domain"]]) == 1]
    if any(c["relaxed"] is True for c in passing):
        return True
    if passing and all(c["relaxed"] is False for c in passing):
        return False
    return None


def _declared_signing_domains(email_data):
    domains = []
    for value in _headers(email_data.get("dkim_signatures")):
        clauses, issues = split_clauses(value)
        values = [clause.split("=", 1)[1].strip() for clause in clauses
                  if re.match(r"^d\s*=", clause, re.I)]
        domain = normalize_domain(values[0]) if len(values) == 1 and not issues else None
        if domain and domain not in domains:
            domains.append(domain)
    return domains


def analyze_authentication(email_data, *, trusted_authserv_ids=None):
    """Keep legacy scalar fields while exposing every report and its provenance.

    trusted_authserv_ids is explicit caller configuration, never inferred from
    message content. It raises source confidence only; it cannot prove that an
    uploaded EML crossed a sanitizing receiver trust boundary.
    """
    results = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown",
               "risk_score": 0, "findings": []}
    findings = results["findings"]

    def finding(kind, severity, message):
        findings.append({"type": kind, "severity": severity, "message": message})

    trusted_ids = {str(value).lower().rstrip(".") for value in _headers(trusted_authserv_ids)}
    receiver = _receiver_host(email_data)
    reports = [parse_authentication_results(value, index)
               for index, value in enumerate(_headers(email_data.get("authentication_results")))]
    for report in reports:
        _source(report, receiver, trusted_ids)
    selected = []
    if reports:
        primary = max(reports, key=lambda report: _SOURCE_RANK[report["source"]])
        # Receivers may emit a separate header for each check. Combine only
        # their named reporter, never unrelated reporters along the route.
        selected = [r for r in reports if r["authserv_id"] == primary["authserv_id"]] if primary["authserv_id"] else [primary]
        results["evidence_confidence"] = {
            "level": "low" if any(r["malformed"] for r in selected) else primary["confidence"],
            "source": primary["source"], "authserv_id": primary["authserv_id"],
            "basis": primary["trust_basis"],
        }
    else:
        results["evidence_confidence"] = {
            "level": "none", "source": "missing", "authserv_id": None,
            "basis": "No Authentication-Results header is present.",
        }
        finding("AUTH_RESULTS_MISSING", "LOW", "No reported authentication evidence is available; this does not establish safety.")

    results["reports"] = reports
    results["selected_report_indices"] = [r["header_index"] for r in selected]
    results["verification"] = {
        "mode": "reported_headers_only", "independently_verified": False,
        "source_authenticity_verified": False,
    }
    results["dns_policy_context"] = {
        "used_for_recorded_results": False, "historical_policy_verified": False,
        "current_lookup_location": "threat_intelligence",
        "note": "Live DNS intelligence is present-day context and does not replace message-reported authentication.",
    }
    if reports:
        finding("AUTH_REPORTED_ONLY", "INFO", "Authentication results are header-reported; SpoofZero has not independently verified SPF, DKIM signatures, DMARC, or header origin.")
    if results["evidence_confidence"]["source"] == "untrusted":
        finding("AUTH_UNTRUSTED_SOURCE", "LOW", "The authentication reporter could not be associated with receiving infrastructure; treat its claims as untrusted.")
    if any(report["malformed"] for report in reports):
        finding("AUTH_RESULTS_MALFORMED", "LOW", "Malformed or unsupported authentication evidence was retained with parsing issues; uninterpretable checks remain unknown.")

    entries_by_method = {}
    for method in KNOWN_RESULTS:
        entries = _method_entries(selected, method)
        entries_by_method[method] = entries
        status = _summary(entries, method)
        results[method] = status
        # Unknown/absent checks are uncertainty, not proof of a failed check.
        if status in ("unknown", "mixed") or status not in KNOWN_RESULTS[method]:
            finding(f"{method.upper()}_INCONCLUSIVE", "LOW", f"Reported {method.upper()} evidence is missing, conflicting, unsupported, or unknown; no PASS can be assumed.")
        if status == "mixed":
            results["risk_score"] += max((_WEIGHTS[method].get(e["result"], 0) for e in entries), default=0)
        else:
            results["risk_score"] += _WEIGHTS[method].get(status, 0)
        for reported in dict.fromkeys(e["result"] for e in entries):
            if reported == "pass":
                continue
            severity = "LOW"
            if reported == "fail":
                severity = "CRITICAL" if method == "dmarc" else "HIGH"
            elif reported == "softfail":
                severity = "MEDIUM"
            if reported == "bestguesspass":
                message = "The receiver reported DMARC bestguesspass, a heuristic result that is not equivalent to DMARC PASS."
            elif reported in ("temperror", "permerror"):
                message = f"The receiver reported {method.upper()} {reported}; evaluation was inconclusive, not a verified authentication failure."
            else:
                message = f"A selected header reports {method.upper()} {reported}; inspect its source and identity before interpreting it."
            finding(f"{method.upper()}_{reported.upper()}", severity, message)

    if selected and any(r not in selected for r in reports):
        finding("AUTH_OTHER_REPORTERS", "INFO", "Other reporters' results are retained separately and do not override the selected reporter.")
    for method, entries in entries_by_method.items():
        if len({e["result"] for e in entries}) > 1:
            finding(f"{method.upper()}_MULTIPLE_RESULTS", "LOW", f"Multiple {method.upper()} results were reported; per-identity evidence is retained.")

    from_values = _headers(email_data.get("from_headers", email_data.get("from")))
    visible = address_domain(from_values[0]) if len(from_values) == 1 else None
    if visible is None:
        finding("AUTH_FROM_AMBIGUOUS", "LOW", "A single valid visible From domain could not be established; alignment is unknown.")
    spf = _comparisons(entries_by_method["spf"], visible, "mailfrom_domain")
    dkim = _comparisons(entries_by_method["dkim"], visible, "signing_domain")
    dmarc = _comparisons(entries_by_method["dmarc"], visible, "header_from_domain")
    spf_aligned, dkim_aligned = _passing_alignment(spf), _passing_alignment(dkim)
    supported = spf_aligned is True or dkim_aligned is True
    reported_from_mismatch = any(c["strict"] is False for c in dmarc)
    for method, comparisons in (("spf", spf), ("dkim", dkim)):
        if comparisons and all(c["status"] == "unaligned" for c in comparisons):
            finding(f"FROM_{method.upper()}_MISMATCH", "LOW", f"The reported {method.upper()} identity is not organizationally aligned with visible From. This can also occur with legitimate forwarding or sending services.")
    if reported_from_mismatch:
        finding("DMARC_FROM_MISMATCH", "MEDIUM", "The DMARC header.from identity differs from the visible From domain; the reported result may refer to another author identity.")
    results["alignment"] = {
        "from_domain": visible,
        "comparison_mode": "exact_and_offline_psl_relaxed_heuristic",
        "historical_policy_mode": "unknown",
        "spf": spf, "dkim": dkim,
        "dmarc": {
            "reported_result": results["dmarc"], "header_from_comparisons": dmarc,
            "spf_pass_aligned": spf_aligned, "dkim_pass_aligned": dkim_aligned,
            "aligned_pass_observed": supported,
            "assessment": "supporting_evidence" if supported and not reported_from_mismatch else "insufficient_or_inconsistent_evidence",
            "independently_verified": False,
        },
        "declared_dkim_domains": _declared_signing_domains(email_data),
        "declared_dkim_domains_verified": False,
        "limitations": "PSL comparisons include private suffixes and do not reproduce historical strict/relaxed policy or a DNS tree walk. HELO and bare signature declarations do not establish a DMARC-aligned PASS.",
    }
    unsupported_dmarc_pass = results["dmarc"] == "pass" and (reported_from_mismatch or
            (not supported and (spf_aligned is False or dkim_aligned is False)))
    if unsupported_dmarc_pass:
        finding("DMARC_ALIGNMENT_UNSUPPORTED", "LOW", "DMARC PASS was reported, but the available identities do not supply matching alignment evidence; the reported result is preserved.")
    inconclusive = (
        any(results[m] not in ("pass", "fail", "softfail") for m in KNOWN_RESULTS)
        or any(r["malformed"] for r in selected) or visible is None
        or reported_from_mismatch or unsupported_dmarc_pass
        or results["evidence_confidence"]["level"] in ("none", "low")
    )
    results["evidence_state"] = "inconclusive" if inconclusive else "reported_results"
    results["risk_score"] = min(results["risk_score"], 100)
    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m backend.analyzers.auth_analyzer <email.eml>")
        sys.exit(1)
    print(json.dumps(analyze_authentication(parse_email(sys.argv[1])), indent=4))
