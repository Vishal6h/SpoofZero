"""Inert attachment metadata and complete-payload hashes within explicit limits."""
import hashlib
import json
import sys
from backend.input_safety import (
    DEFAULT_EMAIL_LIMITS, estimated_decoded_size, load_email_message, safe_evidence_filename,
)

def analyze_attachments(file_path, *, limits=None):
    limits = limits or DEFAULT_EMAIL_LIMITS
    msg, _ = load_email_message(file_path, limits)
    attachments, warnings = [], []
    total_bytes = discovered = skipped = 0
    for part in msg.walk():
        filename = part.get_filename()
        if part.get_content_disposition() != "attachment" and not filename:
            continue
        discovered += 1
        if len(attachments) >= limits.max_attachments:
            skipped += 1
            continue
        item = {
            "filename": safe_evidence_filename(filename),
            "content_type": part.get_content_type(),
            "size_bytes": None,
            "sha256": None,
        }
        estimate = estimated_decoded_size(part)
        available = min(limits.max_attachment_bytes, limits.max_total_attachment_bytes - total_bytes)
        if estimate > available:
            item.update(status="skipped_limit", message="Attachment exceeded an individual or total decoded-byte limit; no partial hash was generated.")
            attachments.append(item)
            skipped += 1
            continue
        try:
            payload = part.get_payload(decode=True)
            payload = payload if isinstance(payload, bytes) else b""
        except (LookupError, UnicodeError, ValueError, TypeError):
            item.update(status="error", message="Attachment encoding could not be decoded safely.")
            attachments.append(item)
            skipped += 1
            continue
        if len(payload) > available:
            item.update(status="skipped_limit", message="Attachment exceeded the decoded-byte limit; no partial hash was generated.")
            skipped += 1
        else:
            item.update(size_bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())
            total_bytes += len(payload)
        attachments.append(item)
    if skipped:
        warnings.append(f"{skipped} attachment(s) were not fully processed because of resource limits or malformed encoding.")
    return {
        "attachment_count": discovered,
        "attachments": attachments,
        "processing": {
            "status": "PARTIAL" if skipped else "COMPLETE",
            "processed_count": discovered - skipped,
            "skipped_count": skipped,
            "total_decoded_bytes": total_bytes,
            "warnings": warnings,
        },
    }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m backend.analyzers.attachment_analyzer <email.eml>")
        sys.exit(1)
    print(json.dumps(analyze_attachments(sys.argv[1]), indent=4))
