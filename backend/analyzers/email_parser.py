from email.utils import collapse_rfc2231_value
from html.parser import HTMLParser
import re

from backend.input_safety import (
    DEFAULT_EMAIL_LIMITS, load_email_message, safe_display_text, truncate_utf8,
)


class _EmailHTMLParser(HTMLParser):
    """Read text and reference attributes without rendering or fetching HTML."""

    BLOCK_TAGS = frozenset({
        "address", "article", "blockquote", "br", "div", "dl", "dt", "dd",
        "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2",
        "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "ol", "p",
        "pre", "section", "table", "tr", "ul",
    })
    IGNORED_TAGS = frozenset({"head", "title", "script", "style", "template"})
    REFERENCE_ATTRIBUTES = frozenset({
        "href", "src", "action", "formaction", "poster", "background", "data",
    })

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.chunks = []
        self.references = []
        self.url_texts = []
        self.base_url = None
        self.ignored = []
        self.preformatted = 0

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "pre":
            self.preformatted += 1
        for name, value in attrs:
            if name in self.REFERENCE_ATTRIBUTES and value:
                self.references.append(value.strip())
            elif name in {"style", "srcset"} and value:
                self.url_texts.append(value)
        if tag == "meta" and (attributes.get("http-equiv") or "").lower() == "refresh":
            self.url_texts.append(attributes.get("content") or "")
        if tag == "base" and self.base_url is None:
            self.base_url = attributes.get("href")
        # Tolerate a missing closing head tag in otherwise readable HTML.
        if tag == "body":
            self.ignored = [name for name in self.ignored if name not in {"head", "title"}]
        if tag in self.IGNORED_TAGS:
            self.ignored.append(tag)
        if self.ignored:
            return
        if tag in self.BLOCK_TAGS:
            self.chunks.append("\n")
        elif tag in {"td", "th"}:
            self.chunks.append(" ")
        elif tag == "img" and attributes.get("alt"):
            self.chunks.append(" " + attributes["alt"] + " ")

    def handle_endtag(self, tag):
        if tag == "pre":
            self.preformatted = max(0, self.preformatted - 1)
        if tag in self.ignored:
            index = len(self.ignored) - 1 - self.ignored[::-1].index(tag)
            del self.ignored[index:]
        if not self.ignored and tag in self.BLOCK_TAGS:
            self.chunks.append("\n")
        elif not self.ignored and tag in {"td", "th"}:
            self.chunks.append(" ")

    def handle_data(self, data):
        if any(tag in {"script", "style"} for tag in self.ignored):
            self.url_texts.append(data)
        if not self.ignored:
            self.chunks.append(data if self.preformatted else re.sub(r"\s+", " ", data))


def extract_html_content(html):
    """Return readable text and inert references, including entity decoding."""
    parser = _EmailHTMLParser()
    try:
        parser.feed(html)
        parser.close()
    except (ValueError, AssertionError):
        # Keep text already recovered from malformed markup; never render it.
        pass
    lines = [" ".join(line.split()) for line in "".join(parser.chunks).splitlines()]
    return {
        "text": "\n".join(line for line in lines if line),
        "references": list(dict.fromkeys(parser.references)),
        "base_url": parser.base_url,
        "url_texts": parser.url_texts,
    }


def _decode_text(part):
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
    except (LookupError, UnicodeError, ValueError, TypeError):
        pass
    # Unknown charset labels and malformed transfer encodings must not discard
    # the other body parts. Replacement decoding is deterministic and inert.
    try:
        payload = part.get_payload(decode=True)
    except (LookupError, UnicodeError, ValueError, TypeError):
        payload = None
    if isinstance(payload, bytes):
        return payload.decode("utf-8", errors="replace")
    payload = part.get_payload()
    return payload if isinstance(payload, str) else ""


def _body_parts(message):
    pending = [message]
    while pending:
        part = pending.pop()
        if part.get_content_disposition() == "attachment" or part.get_filename():
            continue
        # An encapsulated message belongs to attachment evidence, not this body.
        if part.get_content_maintype() == "message":
            continue
        if part.is_multipart():
            children = list(part.iter_parts())
            if part.get_content_subtype() == "related" and children:
                start = part.get_param("start")
                root = children[0]
                if start:
                    start = collapse_rfc2231_value(start).strip("<>")
                    root = next(
                        (child for child in children
                         if str(child.get("Content-ID", "")).strip("<>") == start),
                        root,
                    )
                children = [root]
            elif part.get_content_subtype() == "alternative":
                # Prefer plain-text formatting for identical alternatives, while
                # still retaining distinct HTML text and every HTML link target.
                children.sort(key=lambda child: child.get_content_type() != "text/plain")
            pending.extend(reversed(children))
        elif part.get_content_type() in {"text/plain", "text/html"}:
            yield part


def _merge_body_texts(texts):
    accepted = []
    seen_texts = []
    for text in texts:
        key = " ".join(text.split())
        if not key or key in seen_texts:
            continue
        # Deduplicate repeated lines across MIME representations, not repetition
        # inside one body. Whole-text matching above also tolerates line wrapping.
        lines = text.splitlines(keepends=True)
        unique = []
        for line in lines:
            line_key = " ".join(line.split())
            if line_key and any(" " + line_key + " " in " " + previous + " "
                                for previous in seen_texts):
                continue
            unique.append(line)
        retained = "".join(unique)
        if retained.strip():
            accepted.append(retained)
        seen_texts.append(key)
    if len(accepted) == 1:
        return accepted[0]
    return "\n\n".join(text.strip() for text in accepted)


def parse_email(file_path, *, limits=None):
    limits = limits or DEFAULT_EMAIL_LIMITS
    msg, processing = load_email_message(file_path, limits)

    email_data = {
        "subject": msg.get("Subject"),
        "from": msg.get("From"),
        "to": msg.get("To"),
        "reply_to": msg.get("Reply-To"),
        "return_path": msg.get("Return-Path"),
        "message_id": msg.get("Message-ID"),
        "date": msg.get("Date"),
        "received": msg.get_all("Received", []),
        "authentication_results": msg.get_all("Authentication-Results", []),
        "dkim_signatures": msg.get_all("DKIM-Signature", []),
        "from_headers": msg.get_all("From", []),
        "body": "",
        # Transient parser evidence for IOC extraction, never rendered in the UI.
        "html_parts": [],
    }
    for field in ("subject", "from", "to", "reply_to", "return_path", "message_id", "date"):
        email_data[field] = safe_display_text(email_data[field], limits.max_header_chars)
    for field in ("received", "authentication_results", "dkim_signatures", "from_headers"):
        email_data[field] = [
            safe_display_text(value, limits.max_header_chars) for value in email_data[field]
        ]
    texts = []
    remaining = limits.max_body_text_bytes
    truncated = False
    for part in _body_parts(msg):
        if remaining <= 0:
            truncated = True
            break
        text, was_truncated = truncate_utf8(_decode_text(part), remaining)
        remaining -= len(text.encode("utf-8", errors="replace"))
        truncated = truncated or was_truncated
        if part.get_content_type() == "text/html":
            if text not in email_data["html_parts"]:
                email_data["html_parts"].append(text)
            text = extract_html_content(text)["text"]
        texts.append(text)
    email_data["body"], merged_truncated = truncate_utf8(
        _merge_body_texts(texts), limits.max_body_text_bytes)
    truncated = truncated or merged_truncated
    processing["status"] = "PARTIAL" if truncated else "COMPLETE"
    processing["warnings"] = (
        ["Body/HTML extraction reached its byte limit; indicators beyond the retained text were not checked."]
        if truncated else []
    )
    email_data["processing"] = processing
    return email_data


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) != 2:
        print("Usage: python email_parser.py <email.eml>")
        sys.exit(1)

    result = parse_email(sys.argv[1])
    print(json.dumps(result, indent=4, default=str))
