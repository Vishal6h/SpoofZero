import re
import sys
import json
import hashlib
from pathlib import Path

from .email_parser import parse_email


URL_PATTERN = re.compile(
    r'https?://[^\s<>"\']+',
    re.IGNORECASE
)

IP_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)

EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
)

DOMAIN_PATTERN = re.compile(
    r'\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b'
)


def sha256_file(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def extract_iocs(email_data):
    text_parts = [
        email_data.get("subject") or "",
        email_data.get("body") or "",
        email_data.get("from") or "",
        email_data.get("reply_to") or "",
        email_data.get("return_path") or "",
        " ".join(email_data.get("received", []))
    ]

    combined_text = "\n".join(text_parts)

    urls = sorted(set(URL_PATTERN.findall(combined_text)))
    ips = sorted(set(IP_PATTERN.findall(combined_text)))
    emails = sorted(set(EMAIL_PATTERN.findall(combined_text)))
    domains = sorted(set(DOMAIN_PATTERN.findall(combined_text)))

    return {
        "urls": urls,
        "ips": ips,
        "emails": emails,
        "domains": domains
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "Usage: python -m backend.analyzers.ioc_extractor "
            "<email.eml>"
        )
        sys.exit(1)

    email_data = parse_email(sys.argv[1])

    result = extract_iocs(email_data)

    print(json.dumps(result, indent=4))
