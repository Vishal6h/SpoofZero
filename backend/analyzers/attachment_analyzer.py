import hashlib
import json
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path


def analyze_attachments(file_path):
    file_path = Path(file_path)

    with open(file_path, "rb") as f:
        msg = BytesParser(
            policy=policy.default
        ).parse(f)

    attachments = []

    for part in msg.walk():
        filename = part.get_filename()
        disposition = part.get_content_disposition()

        if disposition != "attachment" and not filename:
            continue

        payload = part.get_payload(decode=True)

        if payload is None:
            payload = b""

        sha256 = hashlib.sha256(
            payload
        ).hexdigest()

        attachments.append({
            "filename": filename or "unnamed_attachment",
            "content_type": part.get_content_type(),
            "size_bytes": len(payload),
            "sha256": sha256
        })

    return {
        "attachment_count": len(attachments),
        "attachments": attachments
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "Usage: python -m "
            "backend.analyzers.attachment_analyzer "
            "<email.eml>"
        )
        sys.exit(1)

    result = analyze_attachments(
        sys.argv[1]
    )

    print(
        json.dumps(
            result,
            indent=4
        )
    )
