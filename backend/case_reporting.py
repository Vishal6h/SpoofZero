"""Offline analysis comparison and privacy-aware forensic reports."""
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime, timezone
from email.utils import getaddresses
from hashlib import sha256
from html import escape
import json
import math
import re
import unicodedata

from backend.fusion_policy import snapshot_policy_version
from ml.model_policy import describe_ai_output

REPORT_SCHEMA = "spoofzero.forensic-report"
REPORT_VERSION = 2
GEOLOCATION_LIMITATION = (
    "IP geolocation represents approximate infrastructure location and does not "
    "identify a person's physical location."
)
AI_LIMITATION = (
    "Experimental/unvalidated AI signals are supporting evidence and do not "
    "contribute numerically under the current fusion policy."
)
CORRELATION_LIMITATION = (
    "Shared indicators and infrastructure are investigation evidence and do not "
    "prove a common attacker or authorship."
)
SECRET_KEY = re.compile(
    r"(?:^|[_-])(?:api[_-]?keys?|secrets?|passwords?|credentials?|authorization|"
    r"access[_-]?tokens?|refresh[_-]?tokens?|private[_-]?keys?|tokens?)(?:$|[_-])", re.I
)
SHA256 = re.compile(r"[a-f0-9]{64}")
SECRET_VALUE = re.compile(
    r"(?i)\b(VT_API_KEY|API_KEY|ACCESS_TOKEN|REFRESH_TOKEN|TOKEN|SECRET|PASSWORD)"
    r"\s*[:=]\s*([^\s,;]+)"
)
BEARER_VALUE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}")
SYSTEM_PATH = re.compile(
    r"(?i)(?:[A-Z]:\\|/(?:home|users|etc|var|tmp)/)[^\s<>'\"]+"
)


def _redact_text(value):
    value = SECRET_VALUE.sub(lambda match: match.group(1) + "=[REDACTED]", value)
    value = BEARER_VALUE.sub("Bearer [REDACTED]", value)
    return SYSTEM_PATH.sub("[REDACTED SYSTEM PATH]", value)


def _utc(value=None):
    value = value or datetime.now(timezone.utc)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("Generated timestamp must include a timezone")
        return value.astimezone(timezone.utc).isoformat()
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError):
        raise ValueError("Generated timestamp must include a timezone") from None


def sanitize_export_filename(case_name, case_id, extension):
    """Return a plain filename; user text is never interpreted as a path."""
    extension = extension.lower().lstrip(".")
    if extension not in {"json", "html"}:
        raise ValueError("Unsupported report extension")
    label = unicodedata.normalize("NFKD", str(case_name)).encode(
        "ascii", "ignore").decode().lower()
    label = re.sub(r"[^a-z0-9]+", "-", label).strip("-")[:60] or "case"
    if label in {"con", "prn", "aux", "nul"} or re.fullmatch(r"(?:com|lpt)[1-9]", label):
        label = "case-" + label
    identity = re.sub(r"[^a-f0-9]", "", str(case_id).lower())[:8] or "unknown"
    return f"spoofzero-{label}-{identity}.{extension}"


def _safe_copy(value):
    if isinstance(value, Mapping):
        return {
            str(key): _safe_copy(item)
            for key, item in value.items()
            if not SECRET_KEY.search(str(key)) and str(key).lower() not in {
                "body", "raw_email", "raw_eml", "eml_content", "environment",
                ".env", "env", "env_contents", "html_parts", "html_body",
                "text_body", "payload", "attachment_payload",
            }
        }
    if isinstance(value, (list, tuple)):
        return [_safe_copy(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, float) and not math.isfinite(value):
            return None
        return _redact_text(value) if isinstance(value, str) else value
    return str(value)


def _analysis(record):
    return record.get("analysis", record) if isinstance(record, Mapping) else {}


def _analysis_identity(record):
    analysis = _analysis(record)
    email_hash = str((analysis.get("email") or {}).get("sha256") or record.get("email_id") or "")
    if not SHA256.fullmatch(email_hash):
        email_hash = "UNKNOWN"
    basis = "|".join((
        str(record.get("case_id") or ""), email_hash,
        str(record.get("analyzed_at") or ""), str(record.get("version") or ""),
    ))
    return str(record.get("analysis_id") or sha256(basis.encode()).hexdigest()[:32]), email_hash


def _values(items):
    return {
        json.dumps(_safe_copy(item), sort_keys=True, ensure_ascii=False)
        for item in items or []
    }


def _change(label, before, after):
    return None if before == after else {"field": label, "before": before, "after": after}


def _sender(value):
    addresses = getaddresses([str(value or "")])
    if len(addresses) != 1 or "@" not in addresses[0][1]:
        return None, None
    mailbox = addresses[0][1].strip().casefold()
    return mailbox, mailbox.rsplit("@", 1)[-1]


def compare_analyses(left_record, right_record):
    """Compare two immutable records without inferring attribution."""
    left, right = _analysis(left_record), _analysis(right_record)
    la, ra = left.get("final_assessment") or {}, right.get("final_assessment") or {}
    li, ri = left.get("iocs") or {}, right.get("iocs") or {}
    lattach = (left.get("attachments") or {}).get("attachments") or []
    rattach = (right.get("attachments") or {}).get("attachments") or []

    def finding_set(analysis, section):
        value = analysis.get(section) or {}
        return _values(value.get("findings") if isinstance(value, Mapping) else [])

    changes = [
        _change("Forensic risk score", la.get("risk_score"), ra.get("risk_score")),
        _change("Verdict", la.get("verdict"), ra.get("verdict")),
        _change("Fusion policy", snapshot_policy_version(la), snapshot_policy_version(ra)),
        _change("Visible sender", (left.get("email") or {}).get("from"),
                (right.get("email") or {}).get("from")),
    ]
    for method in ("spf", "dkim", "dmarc"):
        changes.append(_change(method.upper(),
                               (left.get("authentication") or {}).get(method),
                               (right.get("authentication") or {}).get(method)))
    changes.extend((
        _change("AI signal", (left.get("ai_analysis") or {}).get("phishing_probability"),
                (right.get("ai_analysis") or {}).get("phishing_probability")),
        _change("AI validation", describe_ai_output(left.get("ai_analysis"))["validation_status"],
                describe_ai_output(right.get("ai_analysis"))["validation_status"]),
    ))
    for key, label in (("urls", "URLs"), ("domains", "Domains"), ("ips", "IP addresses")):
        changes.append(_change(label, sorted(set(map(str, li.get(key, [])))),
                              sorted(set(map(str, ri.get(key, []))))))
    changes.extend((
        _change("Attachment hashes", sorted({str(x.get("sha256")) for x in lattach if x.get("sha256")}),
                sorted({str(x.get("sha256")) for x in rattach if x.get("sha256")})),
        _change("Sender findings", sorted(finding_set(left, "sender_identity")),
                sorted(finding_set(right, "sender_identity"))),
        _change("Relay reconstruction", _safe_copy(left.get("relay_trace") or {}),
                _safe_copy(right.get("relay_trace") or {})),
        _change("Domain/IP reputation", _safe_copy(left.get("reputation") or {}),
                _safe_copy(right.get("reputation") or {})),
        _change("Attachment reputation", _safe_copy(left.get("attachment_reputation") or []),
                _safe_copy(right.get("attachment_reputation") or [])),
    ))
    left_mailbox, left_domain = _sender((left.get("email") or {}).get("from"))
    right_mailbox, right_domain = _sender((right.get("email") or {}).get("from"))
    shared = {
        "sender_mailboxes": [left_mailbox] if left_mailbox and left_mailbox == right_mailbox else [],
        "sender_domains": [left_domain] if left_domain and left_domain == right_domain else [],
        "urls": sorted(set(map(str, li.get("urls", []))) & set(map(str, ri.get("urls", [])))),
        "domains": sorted(set(map(str, li.get("domains", []))) & set(map(str, ri.get("domains", [])))),
        "ips": sorted(set(map(str, li.get("ips", []))) & set(map(str, ri.get("ips", [])))),
        "attachment_sha256": sorted(
            {str(x.get("sha256")) for x in lattach if x.get("sha256")}
            & {str(x.get("sha256")) for x in rattach if x.get("sha256")}
        ),
    }
    left_id, _ = _analysis_identity(left_record)
    right_id, _ = _analysis_identity(right_record)
    return {
        "schema_version": 1,
        "left_analysis_id": left_id,
        "right_analysis_id": right_id,
        "same_raw_email": (
            bool(SHA256.fullmatch(str((left.get("email") or {}).get("sha256") or "")))
            and (left.get("email") or {}).get("sha256") ==
            (right.get("email") or {}).get("sha256")
        ),
        "changes": [item for item in changes if item],
        "shared_indicators": shared,
        "note": CORRELATION_LIMITATION,
    }


def _record_for_report(record, include_sensitive, sensitive_bodies):
    analysis = _analysis(record)
    assessment = analysis.get("final_assessment") or {}
    ai = analysis.get("ai_analysis") or {}
    metadata = describe_ai_output(ai)
    analysis_id, email_hash = _analysis_identity(record)
    version = int(record.get("version") or 1)
    reasons = assessment.get("reasons") or []
    verdict = str(assessment.get("verdict") or "UNKNOWN")
    score = assessment.get("risk_score")
    summary = (
        f"Analysis #{version} recorded forensic risk score {score}/100 with verdict "
        f"{verdict} under {snapshot_policy_version(assessment)}. "
        f"{len(reasons)} documented reason(s) require investigator interpretation."
    )
    result = {
        "analysis_id": analysis_id,
        "analysis_version": version,
        "latest": bool(record.get("is_latest", True)),
        "analyzed_at": str(record.get("analyzed_at") or ""),
        "original_analysis_at": str(record.get("first_analyzed_at") or
                                    record.get("analyzed_at") or ""),
        "filename": re.split(r"[\\/]", str(record.get("filename") or "email.eml"))[-1],
        "raw_email_sha256": email_hash,
        "email": _safe_copy(analysis.get("email") or {}),
        "executive_summary": summary,
        "risk_assessment": {
            "score": score,
            "verdict": verdict,
            "fusion_policy_version": snapshot_policy_version(assessment),
            "contribution_ledger": _safe_copy(assessment.get("contributions") or {}),
            "reasons": _safe_copy(reasons),
        },
        "sender_identity": _safe_copy(analysis.get("sender_identity") or {}),
        "authentication": _safe_copy(analysis.get("authentication") or {}),
        "iocs": _safe_copy(analysis.get("iocs") or {}),
        "relay_reconstruction": _safe_copy(analysis.get("relay_trace") or {}),
        "origin_infrastructure_and_geolocation": _safe_copy(
            analysis.get("geo_analysis") or {}),
        "dns_rdap_threat_intelligence": _safe_copy(
            analysis.get("threat_intelligence") or {}),
        "domain_ip_reputation": _safe_copy(analysis.get("reputation") or {}),
        "attachments": _safe_copy(analysis.get("attachments") or {}),
        "attachment_reputation": _safe_copy(
            analysis.get("attachment_reputation") or []),
        "ai_signal": {
            "phishing_score": ai.get("phishing_probability"),
            "verdict": ai.get("verdict"),
            **metadata,
            "numeric_contribution": assessment.get("ai_numeric_contribution"),
        },
        "sensitive_content": {"included": False, "handling": "summary_only"},
    }
    body = (sensitive_bodies or {}).get(analysis_id)
    if include_sensitive and isinstance(body, str) and body:
        result["sensitive_content"] = {
            "included": True,
            "handling": "explicit_readable_body_only",
            "readable_body": _redact_text(body[:100000]),
            "note": "Explicitly supplied for this export; no raw EML or attachment payload included.",
        }
    return result


def _integrity(record):
    canonical = json.dumps(record, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":"), allow_nan=False).encode()
    return {
        "algorithm": "SHA-256",
        "scope": "canonical forensic record excluding this integrity object",
        "sha256": sha256(canonical).hexdigest(),
        "legal_digital_signature": False,
    }


def build_forensic_report(case, records, correlation=None, *, generated_at=None,
                          include_sensitive=False, sensitive_bodies=None):
    if not isinstance(case, Mapping) or not case.get("case_id"):
        raise ValueError("Case metadata is required")
    analyses = [
        _record_for_report(record, include_sensitive, sensitive_bodies)
        for record in records
    ]
    report = {
        "report_schema": REPORT_SCHEMA,
        "report_version": REPORT_VERSION,
        "generated_at": _utc(generated_at),
        "case": {
            "case_id": str(case["case_id"]),
            "name": _redact_text(str(case.get("name") or "")),
            "description": _redact_text(str(case.get("description") or "")),
            "created_at": str(case.get("created_at") or ""),
            "updated_at": str(case.get("updated_at") or ""),
            "archived": bool(case.get("archived", False)),
        },
        "analysis_count": len(analyses),
        "analyses": analyses,
        "campaign_correlation": _safe_copy(correlation or {
            "campaigns": [], "pairs": [], "shared_indicators": [],
            "note": CORRELATION_LIMITATION,
        }),
        "limitations_and_confidence": [
            GEOLOCATION_LIMITATION,
            AI_LIMITATION,
            CORRELATION_LIMITATION,
            "Authentication results are parsed reported evidence and are not independent cryptographic verification.",
            "Threat-intelligence and geolocation entries describe the stored lookup snapshot and may change over time.",
            "This report is an investigative aid and requires human interpretation.",
        ],
    }
    report["integrity"] = _integrity(report)
    return report


def verify_report_integrity(report):
    candidate = deepcopy(report)
    supplied = candidate.pop("integrity", None)
    return (
        isinstance(supplied, Mapping)
        and supplied.get("algorithm") == "SHA-256"
        and supplied.get("sha256") == _integrity(candidate)["sha256"]
    )


def report_json(report):
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False,
                      allow_nan=False) + "\n"


def _json_block(value):
    return escape(json.dumps(value, indent=2, sort_keys=True,
                             ensure_ascii=False, allow_nan=False))


def report_html(report):
    if not verify_report_integrity(report):
        raise ValueError("Report integrity metadata does not match its content")
    case = report["case"]
    analyses = []
    for item in report["analyses"]:
        risk = item["risk_assessment"]
        ledger = risk["contribution_ledger"]
        rows = "".join(
            f"<tr><th>{escape(str(key).replace('_', ' ').title())}</th>"
            f"<td>{escape(str(value))}</td></tr>"
            for key, value in ledger.items()
        ) or "<tr><td colspan='2'>No contribution ledger recorded in this snapshot.</td></tr>"
        reason_items = "".join(
            f"<li>{escape(str(reason))}</li>" for reason in risk.get("reasons", [])
        ) or "<li>No reasons were recorded in this snapshot.</li>"
        sections = []
        for key, title in (
            ("sender_identity", "Sender identity findings"),
            ("authentication", "SPF / DKIM / DMARC evidence"),
            ("iocs", "Indicators of compromise"),
            ("relay_reconstruction", "SMTP relay reconstruction"),
            ("origin_infrastructure_and_geolocation", "Origin infrastructure / geolocation"),
            ("dns_rdap_threat_intelligence", "DNS / RDAP / threat intelligence"),
            ("domain_ip_reputation", "Domain / IP reputation"),
            ("attachments", "Attachment hashes"),
            ("attachment_reputation", "Attachment reputation"),
            ("ai_signal", "AI signal and validation status"),
            ("sensitive_content", "Sensitive content handling"),
        ):
            sections.append(
                f"<details open><summary>{escape(title)}</summary><pre>{_json_block(item[key])}</pre></details>"
            )
        email_rows = "".join(
            f"<tr><th>{escape(label)}</th><td>{escape(str(item['email'].get(key) or 'Not recorded'))}</td></tr>"
            for key, label in (("subject", "Subject"), ("from", "From"),
                               ("to", "To"), ("date", "Reported email date"))
        )
        ai = item["ai_signal"]
        analyses.append(f"""<section class="analysis">
          <h2>Analysis #{item['analysis_version']} {"(latest)" if item['latest'] else "(historical)"}</h2>
          <p class="meta">ID {escape(item['analysis_id'])} |
          Evidence file {escape(item['filename'])} | Recorded {escape(item['analyzed_at'])}
          | Raw EML SHA-256 {escape(item['raw_email_sha256'])}</p>
          <div class="risk"><strong>{escape(str(risk['score']))}/100</strong>
          <span>{escape(risk['verdict'])}</span></div>
          <h3>Executive summary</h3><p>{escape(item['executive_summary'])}</p>
          <table>{email_rows}</table>
          <p class="ai-note">AI signal: {escape(str(ai['phishing_score']))} |
          Model: {escape(ai['model_status'])} | Validation: {escape(ai['validation_status'])}
          | Supporting evidence only</p>
          <h3>Contribution ledger</h3><table>{rows}</table>
          <h3>Assessment reasons</h3><ul>{reason_items}</ul>
          {''.join(sections)}
        </section>""")
    limits = "".join(f"<li>{escape(item)}</li>" for item in report["limitations_and_confidence"])
    correlation = _json_block(report["campaign_correlation"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>SpoofZero Forensic Report</title>
<style>
body{{font:14px/1.5 Arial,sans-serif;color:#17212b;max-width:1050px;margin:32px auto;padding:0 24px}}
header{{border-bottom:3px solid #2676ad;margin-bottom:24px}} h1{{margin-bottom:4px}}
.meta{{color:#546575;overflow-wrap:anywhere}} .risk{{display:flex;gap:24px;align-items:center;
background:#edf5fa;border-left:5px solid #2676ad;padding:12px 16px;margin:12px 0}}
.risk strong{{font-size:28px}} section.analysis{{margin-top:32px}}
section.analysis + section.analysis{{page-break-before:always}}
.ai-note{{background:#fff5da;padding:10px;border-left:4px solid #bc9130}}
table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #ccd8e0;padding:7px;text-align:left;overflow-wrap:anywhere}}
details{{border:1px solid #d7e0e7;padding:9px;margin:8px 0}} summary{{font-weight:bold}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f6f8fa;padding:10px}}
@media print{{body{{margin:0;max-width:none}} details{{break-inside:auto}}}}
</style></head><body>
<header><h1>SpoofZero Forensic Investigation Report</h1>
<p>Case: <strong>{escape(case['name'])}</strong> | ID {escape(case['case_id'])}</p>
<p class="meta">Generated {escape(report['generated_at'])} | Report schema v{report['report_version']}
| Integrity SHA-256 {escape(report['integrity']['sha256'])}</p></header>
<p>{escape(case['description'])}</p>
{''.join(analyses)}
<section><h2>Campaign / correlation findings</h2>
<p>{escape(CORRELATION_LIMITATION)}</p><pre>{correlation}</pre>
<h2>Limitations and confidence notes</h2><ul>{limits}</ul>
<p><strong>Integrity note:</strong> The SHA-256 is a content-integrity checksum,
not a legal digital signature.</p></section></body></html>"""
