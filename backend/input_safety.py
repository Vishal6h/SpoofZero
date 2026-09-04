"""Conservative resource and display boundaries for untrusted email input."""
from dataclasses import asdict, dataclass
from email import errors, policy
from email.parser import BytesParser
from pathlib import Path
import re
import unicodedata

MIB = 1024 * 1024

@dataclass(frozen=True)
class EmailLimits:
    max_eml_bytes: int = 10 * MIB
    max_mime_parts: int = 200
    max_mime_depth: int = 20
    max_attachments: int = 50
    max_attachment_bytes: int = 5 * MIB
    max_total_attachment_bytes: int = 8 * MIB
    max_body_text_bytes: int = 1 * MIB
    max_header_chars: int = 32768

    def public_summary(self):
        return asdict(self)

DEFAULT_EMAIL_LIMITS = EmailLimits()

class EmailInputError(ValueError):
    """Safe, user-facing rejection for malformed or excessive email input."""

class EmailTooLargeError(EmailInputError):
    pass

class EmailStructureError(EmailInputError):
    pass

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

def safe_display_text(value, maximum=32768):
    if value is None:
        return None
    text = unicodedata.normalize("NFKC", str(value))
    text = _CONTROL.sub(" ", text).replace("\r", " ").replace("\n", " ")
    return " ".join(text.split())[:maximum]

def safe_evidence_filename(value, maximum=180):
    """Return a display-only basename, never an email-controlled path."""
    text = safe_display_text(value or "unnamed_attachment", maximum * 4) or "unnamed_attachment"
    text = re.split(r"[/\\]+", text)[-1].strip(" .")
    text = re.sub(r"[^\w.()\[\] @+-]", "_", text, flags=re.UNICODE)
    return text[:maximum].strip(" .") or "unnamed_attachment"

def truncate_utf8(value, maximum):
    text = value if isinstance(value, str) else str(value or "")
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= maximum:
        return text, False
    marker = "\n[TRUNCATED BY SPOOFZERO INPUT LIMIT]"
    if maximum < len(marker.encode()):
        return encoded[:maximum].decode("utf-8", errors="ignore"), True
    budget = maximum - len(marker.encode())
    return encoded[:budget].decode("utf-8", errors="ignore") + marker, True

def _structure(message, limits):
    count = deepest = 0
    pending = [(message, 1)]
    while pending:
        part, depth = pending.pop()
        count += 1
        deepest = max(deepest, depth)
        if count > limits.max_mime_parts:
            raise EmailStructureError(
                f"Email contains more than {limits.max_mime_parts} MIME parts and was rejected.")
        if depth > limits.max_mime_depth:
            raise EmailStructureError(
                f"Email MIME nesting exceeds {limits.max_mime_depth} levels and was rejected.")
        payload = part.get_payload()
        if isinstance(payload, list):
            pending.extend((child, depth + 1) for child in reversed(payload))
    return {"mime_part_count": count, "mime_depth": deepest}

def load_email_message(file_path, limits=None):
    """Read at most the configured bytes, parse inertly, and validate structure."""
    limits = limits or DEFAULT_EMAIL_LIMITS
    path = Path(file_path)
    try:
        if not path.is_file():
            raise EmailInputError("The EML file is missing or unreadable.")
        with path.open("rb") as stream:
            raw = stream.read(limits.max_eml_bytes + 1)
    except EmailInputError:
        raise
    except OSError as error:
        raise EmailInputError("The EML file could not be read.") from error
    if len(raw) > limits.max_eml_bytes:
        raise EmailTooLargeError(
            f"Email exceeds the {limits.max_eml_bytes / MIB:g} MiB upload limit.")
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
        structure = _structure(message, limits)
    except EmailInputError:
        raise
    except (errors.MessageError, RecursionError, TypeError, ValueError) as error:
        raise EmailStructureError(
            "Email MIME structure is malformed and could not be processed safely.") from error
    return message, {
        "input_bytes": len(raw), **structure, "limits": limits.public_summary(),
    }

def estimated_decoded_size(part):
    """Conservative pre-decode bound, including malformed transfer encodings."""
    payload = part.get_payload()
    if isinstance(payload, list):
        return 0
    raw = payload if isinstance(payload, bytes) else str(payload or "").encode("utf-8", errors="replace")
    encoding = str(part.get("Content-Transfer-Encoding") or "").lower().strip()
    if encoding == "base64":
        return (len(raw) * 3 + 3) // 4
    # Quoted-printable can shrink. Refusing a large encoded part is conservative.
    return len(raw)


def normalized_domain(value):
    if not isinstance(value, str):
        return None
    try:
        domain = value.strip().rstrip(".").lower().encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or labels[-1].isdigit():
        return None
    if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        return None
    return domain
