"""Validated environment configuration with conservative defaults."""
from dataclasses import asdict, dataclass
from os import environ
from typing import Mapping

TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
FALSE_VALUES = frozenset({"0", "false", "no", "off"})


@dataclass(frozen=True)
class RuntimeConfig:
    mode: str = "local"
    external_services_enabled: bool = True
    virus_total_enabled: bool = True
    dns_enabled: bool = True
    rdap_enabled: bool = True
    geolocation_enabled: bool = True
    privacy_safe_default: bool = False
    vt_timeout_seconds: float = 15.0
    rdap_timeout_seconds: float = 8.0
    geolocation_timeout_seconds: float = 10.0
    dns_timeout_seconds: float = 3.0
    vt_cache_ttl_seconds: int = 300
    dns_cache_ttl_seconds: int = 300
    rdap_cache_ttl_seconds: int = 900
    geolocation_cache_ttl_seconds: int = 900
    failure_cache_ttl_seconds: int = 20
    warnings: tuple = ()

    def public_summary(self):
        result = asdict(self)
        result.pop("warnings", None)
        return result


def _boolean(values, key, default, warnings):
    raw = values.get(key)
    if raw is None or not str(raw).strip():
        return default
    normalized = str(raw).strip().lower()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    warnings.append(f"{key} is invalid; the conservative default was used.")
    return default


def _number(values, key, default, minimum, maximum, warnings, integer=False):
    raw = values.get(key)
    if raw is None or not str(raw).strip():
        return default
    try:
        value = int(raw) if integer else float(raw)
    except (TypeError, ValueError):
        warnings.append(f"{key} is invalid; the conservative default was used.")
        return default
    if not minimum <= value <= maximum:
        warnings.append(f"{key} is outside its safe range; the conservative default was used.")
        return default
    return value


def get_runtime_config(values: Mapping | None = None):
    values = environ if values is None else values
    warnings = []
    mode = str(values.get("SPOOFZERO_MODE", "local")).strip().lower()
    if mode not in {"local", "demo"}:
        warnings.append("SPOOFZERO_MODE is invalid; local mode was used.")
        mode = "local"
    external = _boolean(values, "SPOOFZERO_EXTERNAL_SERVICES_ENABLED", True, warnings)
    if mode == "demo":
        external = False
    return RuntimeConfig(
        mode=mode,
        external_services_enabled=external,
        virus_total_enabled=external and _boolean(
            values, "SPOOFZERO_VIRUSTOTAL_ENABLED", True, warnings),
        dns_enabled=external and _boolean(values, "SPOOFZERO_DNS_ENABLED", True, warnings),
        rdap_enabled=external and _boolean(values, "SPOOFZERO_RDAP_ENABLED", True, warnings),
        geolocation_enabled=external and _boolean(
            values, "SPOOFZERO_GEOLOCATION_ENABLED", True, warnings),
        privacy_safe_default=_boolean(
            values, "SPOOFZERO_PRIVACY_SAFE_DEFAULT", False, warnings),
        vt_timeout_seconds=_number(
            values, "SPOOFZERO_VT_TIMEOUT_SECONDS", 15.0, 1.0, 60.0, warnings),
        rdap_timeout_seconds=_number(
            values, "SPOOFZERO_RDAP_TIMEOUT_SECONDS", 8.0, 1.0, 60.0, warnings),
        geolocation_timeout_seconds=_number(
            values, "SPOOFZERO_GEOLOCATION_TIMEOUT_SECONDS", 10.0, 1.0, 60.0, warnings),
        dns_timeout_seconds=_number(
            values, "SPOOFZERO_DNS_TIMEOUT_SECONDS", 3.0, 1.0, 30.0, warnings),
        vt_cache_ttl_seconds=_number(
            values, "SPOOFZERO_VT_CACHE_TTL_SECONDS", 300, 30, 3600, warnings, True),
        dns_cache_ttl_seconds=_number(
            values, "SPOOFZERO_DNS_CACHE_TTL_SECONDS", 300, 30, 3600, warnings, True),
        rdap_cache_ttl_seconds=_number(
            values, "SPOOFZERO_RDAP_CACHE_TTL_SECONDS", 900, 30, 86400, warnings, True),
        geolocation_cache_ttl_seconds=_number(
            values, "SPOOFZERO_GEOLOCATION_CACHE_TTL_SECONDS", 900, 30, 86400, warnings, True),
        failure_cache_ttl_seconds=_number(
            values, "SPOOFZERO_FAILURE_CACHE_TTL_SECONDS", 20, 5, 300, warnings, True),
        warnings=tuple(warnings),
    )
