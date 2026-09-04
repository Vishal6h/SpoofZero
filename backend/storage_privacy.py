"""Privacy projection for new case snapshots; historical rows are never rewritten."""
from copy import deepcopy
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SECRET_KEY = re.compile(
    r"(?:^|[_-])(?:api[_-]?keys?|secrets?|passwords?|credentials?|authorization|"
    r"access[_-]?tokens?|refresh[_-]?tokens?|private[_-]?keys?|tokens?)(?:$|[_-])", re.I)
_ALWAYS_DROP = {
    "body", "raw_email", "raw_eml", "eml_content", "html_parts", "html_body",
    "text_body", "payload", "attachment_payload", "environment", "env_contents",
}
_SECRET_QUERY = re.compile(r"^(?:key|api[_-]?key|token|access[_-]?token|password|secret)$", re.I)
_ASSIGNMENT = re.compile(
    r"(?i)\b(VT_API_KEY|API_KEY|ACCESS_TOKEN|REFRESH_TOKEN|TOKEN|SECRET|PASSWORD)"
    r"\s*[:=]\s*([^\s,;]+)")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}")

def _redact_text(value):
    value = _ASSIGNMENT.sub(lambda match: match.group(1) + "=[REDACTED]", value)
    return _BEARER.sub("Bearer [REDACTED]", value)

def _copy(value):
    if isinstance(value, dict):
        return {
            str(k): _copy(v) for k, v in value.items()
            if str(k).lower() not in _ALWAYS_DROP
            and (str(k) == "ai_scoring_authorization" or not _SECRET_KEY.search(str(k)))
        }
    if isinstance(value, list):
        return [_copy(item) for item in value]
    if isinstance(value, tuple):
        return [_copy(item) for item in value]
    return _redact_text(value) if isinstance(value, str) else deepcopy(value)

def _redact_url(value):
    try:
        parsed = urlsplit(value)
        query = [(key, "[REDACTED]" if _SECRET_QUERY.fullmatch(key) else val)
                 for key, val in parse_qsl(parsed.query, keep_blank_values=True)]
        host = parsed.hostname or ""
        authority = ("[" + host + "]") if ":" in host else host
        if parsed.port:
            authority += ":" + str(parsed.port)
        return urlunsplit((parsed.scheme, authority, parsed.path, urlencode(query), parsed.fragment))
    except (TypeError, ValueError):
        return "[REDACTED MALFORMED URL]"

def prepare_analysis_for_storage(analysis, *, privacy_safe=False):
    """Never persist raw bodies/payloads/secrets; optionally minimize personal metadata."""
    result = _copy(analysis)
    iocs = result.get("iocs") if isinstance(result, dict) else None
    if isinstance(iocs, dict):
        iocs["urls"] = [_redact_url(item) for item in iocs.get("urls", [])]
    if not privacy_safe:
        return result
    email = result.get("email") if isinstance(result, dict) else None
    if isinstance(email, dict):
        for key in ("subject", "from", "to", "reply_to", "return_path", "message_id"):
            email.pop(key, None)
    if isinstance(iocs, dict):
        iocs["emails"] = []
    attachments = result.get("attachments", {}).get("attachments", [])
    for item in attachments if isinstance(attachments, list) else []:
        if isinstance(item, dict):
            digest = str(item.get("sha256") or "")
            item["filename"] = "attachment-" + (digest[:12] or "unhashed")
    result["storage_privacy"] = {
        "mode": "MINIMIZED",
        "raw_body_retained": False,
        "attachment_payloads_retained": False,
        "personal_headers_retained": False,
        "note": "Sender domains, hashes, infrastructure, authentication and reputation evidence remain.",
    }
    return result
