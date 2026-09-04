"""Approximate infrastructure geolocation with bounded failure handling."""
import ipaddress
import json
import math
import sys
import urllib.parse
from backend.external_services import ERROR, SKIPPED, SUCCESS, UNAVAILABLE, TTLCache, request_json, service_result
from backend.runtime_config import get_runtime_config

GEO_CACHE = TTLCache(256)
GEO_TTL_SECONDS, GEO_FAILURE_TTL_SECONDS = 900, 20

def clear_geo_cache():
    GEO_CACHE.clear()

def geolocate_ip(ip_string):
    try:
        ip = ipaddress.ip_address(ip_string)
    except ValueError:
        return {"ip": str(ip_string), **service_result(ERROR, "Invalid IP address.")}
    value = str(ip)
    config = get_runtime_config()
    if not config.geolocation_enabled:
        return {"ip": value, **service_result(UNAVAILABLE, "Geolocation is disabled.")}
    if not ip.is_global:
        return {
            "status": "not_public", "service_status": SKIPPED, "ip": value,
            "message": "Private, reserved, documentation, or non-public IP.",
        }
    response = request_json(
        "geolocation", "https://ipwho.is/" + urllib.parse.quote(value, safe=""),
        headers={"User-Agent": "SpoofZero/1.0"}, timeout=config.geolocation_timeout_seconds,
        cache=GEO_CACHE, cache_key=value,
        ttl_seconds=config.geolocation_cache_ttl_seconds,
        failure_ttl_seconds=config.failure_cache_ttl_seconds,
    )
    if response.get("service_status") != SUCCESS:
        return {"ip": value, **response}
    data = response.get("data")
    if not isinstance(data, dict):
        return {"ip": value, **service_result(
            ERROR, "Geolocation service returned an incomplete response.",
            error_type="MALFORMED_RESPONSE")}
    if data.get("success") is False:
        return {"ip": value, **service_result(
            ERROR, "Geolocation service could not locate this infrastructure IP.")}
    connection = data.get("connection") if isinstance(data.get("connection"), dict) else {}
    latitude, longitude = data.get("latitude"), data.get("longitude")
    if not (
        type(latitude) in (int, float) and type(longitude) in (int, float)
        and math.isfinite(latitude) and math.isfinite(longitude)
        and -90 <= latitude <= 90 and -180 <= longitude <= 180
    ):
        latitude = longitude = None
    return {
        "status": "success", "service_status": SUCCESS, "ip": value,
        "country": data.get("country"), "country_code": data.get("country_code"),
        "region": data.get("region"), "city": data.get("city"),
        "latitude": latitude, "longitude": longitude,
        "asn": connection.get("asn"), "isp": connection.get("isp"),
        "organization": connection.get("org"),
        "cache_hit": response.get("cache_hit", False), "attempts": response.get("attempts", 1),
        "confidence_note": (
            "IP geolocation represents approximate infrastructure location and does not "
            "identify a person's physical location."
        ),
    }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m backend.analyzers.geo_analyzer <IP>")
        sys.exit(1)
    print(json.dumps(geolocate_ip(sys.argv[1]), indent=4))
