"""Shared deterministic text preparation for candidate training and inference."""
from collections.abc import Mapping
import html
import re
import unicodedata

from backend.analyzers.email_parser import extract_html_content

VERSION = "readable_masked_v1"
MAX_CHARS = 40000


def safe_string(value):
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return ""


def readable(value):
    text = unicodedata.normalize("NFKC", safe_string(value)[:MAX_CHARS])
    if re.search(r"</?(?:html|body|div|p|a|br|table|span|script|style)\b", text, re.I):
        text = extract_html_content(text)["text"]
    text = html.unescape(text)
    text = "".join(c for c in text if not unicodedata.category(c).startswith("C") or c in "\n\t")
    return text.strip()


def message_parts(value):
    value = value if isinstance(value, Mapping) else {}
    return readable(value.get("subject")), readable(value.get("body"))


def normalized_content(subject, body):
    return re.sub(r"\s+", " ", f"{subject}\n{body}").strip().casefold()


def feature_text(value):
    subject, body = message_parts(value)
    # Drop transport/filter metadata wherever a corpus has embedded it in text.
    body = re.sub(r"(?im)^\s*(?:received|authentication-results|return-path|message-id|"
                  r"content-type|content-transfer-encoding|mime-version|x-[\w-]+|"
                  r"from|to|cc|bcc|date|sender|reply-to)\s*:.*(?:\n[ \t]+.*)*", " ", body)
    body = re.sub(r"(?m)^\s*>.*$", " ", body)
    text = f"{subject}\n{body}".casefold()
    text = re.sub(r"(?i)\bsubject\s*:", " ", text)
    text = re.sub(r"\[\s*(?:spam|ham|phish(?:ing)?)\s*\]|\*{2,}\s*spam\s*\*{2,}", " ", text)
    text = re.sub(r"https?\s*:\s*/\s*/\s*", "https://", text)
    text = re.sub(r"(?:https?://|www\.)\S+", " urltoken ", text)
    text = re.sub(r"\b[\w.+-]+\s*@\s*[\w.-]+\.[a-z]{2,}\b", " emailtoken ", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " iptoken ", text)
    text = re.sub(r"\b[a-f0-9]{16,}\b", " idtoken ", text)
    text = re.sub(r"\d+", " numtoken ", text)
    # Names/collector markers are not model features; topic bias may still remain.
    text = re.sub(r"\b(?:spamassassin|spamassasin|nazario|nigerian_fraud|linguist-list|enron)\b", " ", text)
    return " ".join(re.findall(r"(?u)\b\w+\b", text))


def verdict_for_probability(probability, thresholds):
    if not 0 <= probability <= 1:
        raise ValueError("Probability must be in [0, 1]")
    low, high = thresholds["suspicious"], thresholds["high"]
    if not 0 <= low <= high <= 1:
        raise ValueError("Thresholds must be ordered inside [0, 1]")
    if probability >= high:
        return "HIGH PHISHING LIKELIHOOD"
    if probability >= low:
        return "SUSPICIOUS"
    return "LOW PHISHING LIKELIHOOD"
