"""Allowlisted operational events which never accept message/credential data."""
import json
import logging
import math
import re

LOGGER = logging.getLogger("spoofzero")
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}")

def _safe_identifier(value):
    value = str(value or "")
    return value if _IDENTIFIER.fullmatch(value) else "unavailable"

def log_event(event, *, analyzer, analysis_id=None, case_id=None,
              duration_ms=None, service_status=None, cache_hit=None,
              attempts=None, level=logging.INFO, logger=None):
    record = {"event": _safe_identifier(event), "analyzer": _safe_identifier(analyzer)}
    for key, value in (("analysis_id", analysis_id), ("case_id", case_id)):
        if value is not None:
            record[key] = _safe_identifier(value)
    if duration_ms is not None:
        try:
            numeric = float(duration_ms)
            if math.isfinite(numeric):
                record["duration_ms"] = round(max(0.0, numeric), 3)
        except (TypeError, ValueError, OverflowError):
            pass
    if service_status is not None:
        record["service_status"] = _safe_identifier(service_status)
    if type(cache_hit) is bool:
        record["cache_hit"] = cache_hit
    if type(attempts) is int and 0 <= attempts <= 10:
        record["attempts"] = attempts
    (logger or LOGGER).log(level, json.dumps(record, sort_keys=True))
    return record
