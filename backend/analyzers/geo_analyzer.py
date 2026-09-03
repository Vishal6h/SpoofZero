import sys
import json
import ipaddress
import urllib.request


def geolocate_ip(ip_string):
    try:
        ip = ipaddress.ip_address(ip_string)
    except ValueError:
        return {
            "status": "error",
            "ip": ip_string,
            "message": "Invalid IP address"
        }

    if not ip.is_global:
        return {
            "status": "not_public",
            "ip": ip_string,
            "message": "Private, reserved, documentation, or non-public IP"
        }

    url = f"https://ipwho.is/{ip_string}"

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "SpoofZero/1.0"}
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))

    except Exception as error:
        return {
            "status": "error",
            "ip": ip_string,
            "message": str(error)
        }

    if data.get("success") is False:
        return {
            "status": "error",
            "ip": ip_string,
            "message": data.get("message", "Lookup failed")
        }

    connection = data.get("connection") or {}

    return {
        "status": "success",
        "ip": ip_string,
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "region": data.get("region"),
        "city": data.get("city"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "asn": connection.get("asn"),
        "isp": connection.get("isp"),
        "organization": connection.get("org"),
        "confidence_note": (
            "This is the approximate location of the IP infrastructure, "
            "not confirmed physical location of the human sender."
        )
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m backend.analyzers.geo_analyzer <IP>")
        sys.exit(1)

    print(json.dumps(geolocate_ip(sys.argv[1]), indent=4))
