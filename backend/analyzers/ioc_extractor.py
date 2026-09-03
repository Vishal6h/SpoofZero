import hashlib
import ipaddress
import json
import re
import sys
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

from .email_parser import extract_html_content, parse_email


URL_PATTERN = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
IP_PATTERN = re.compile(r'(?<![\w.:])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?!\w|\.[\w.])')
IPV6_PATTERN = re.compile(
    r'(?<![\w:.])(?=[0-9a-f.]*:)[0-9a-f:.]+(?:%[\w.-]+)?(?![\w:.])',
    re.IGNORECASE,
)
EMAIL_PATTERN = re.compile(
    r"(?<![\w.+%-])([A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+)@([\w.-]+)"
)
DOMAIN_PATTERN = re.compile(r'(?<![\w@.-])(?:[\w-]+\.)+[\w-]+\.?(?![\w.-])')
HTML_BODY_PATTERN = re.compile(r'<(?:html|body|a|img|div|p|table|span|form)\b', re.IGNORECASE)
# Filter filename-like tokens only when found as unstructured prose. Explicit
# URL/mailbox hosts are retained even if their suffix appears here. Ambiguous
# suffixes such as .zip, .mov, and .com are deliberately not filtered.
FILE_SUFFIXES = frozenset({
    "pdf", "docx", "xlsx", "pptx", "txt", "csv", "eml", "msg", "html", "htm",
    "js", "css", "json", "xml", "png", "jpg", "jpeg", "gif", "svg", "ico",
    "exe", "dll", "py", "ipynb",
})


def sha256_file(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _ip(value):
    # Scope identifiers are local interface names, not portable IP identities.
    if not isinstance(value, str) or "%" in value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _domain(value):
    if not isinstance(value, str):
        return None
    value = value.strip().rstrip(".").lower()
    if _ip(value):
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or labels[-1].isdigit():
        return None
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels):
        return None
    return value


def _url(value):
    if not isinstance(value, str) or re.search(r'\s|[\x00-\x1f\x7f]', value):
        return None
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        host = _ip(parsed.hostname) or _domain(parsed.hostname)
        if (
            not host and parsed.hostname and not parsed.hostname.isdigit()
            and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', parsed.hostname, re.I)
        ):
            host = parsed.hostname.lower()
        if scheme not in {"http", "https"} or not host:
            return None
        authority = f"[{host}]" if ":" in host else host
        port = parsed.port
        if port is not None and (scheme, port) not in {("http", 80), ("https", 443)}:
            authority += f":{port}"
        if "@" in parsed.netloc:
            authority = parsed.netloc.rsplit("@", 1)[0] + "@" + authority
        return urlunsplit((scheme, authority, parsed.path or "/", parsed.query, parsed.fragment))
    except ValueError:
        return None


def _prose_url(value):
    # Attribute boundaries are exact; use this cleanup only for URLs in prose.
    value = value.rstrip(".,;!")
    pairs = {')': '(', ']': '[', '}': '{'}
    while value and value[-1] in pairs:
        closing = value[-1]
        if value.count(closing) <= value.count(pairs[closing]):
            break
        value = value[:-1].rstrip(".,;!")
    return value


def extract_iocs(email_data):
    """Extract normalized evidence without DNS lookups or HTML execution.

    The return shape is unchanged: sorted lists of urls, ips, emails, domains.
    html_parts is optional so older parser dictionaries remain compatible.
    """
    urls, ips, emails, domains = set(), set(), set(), set()

    def add_host(host):
        address = _ip(host)
        domain = _domain(host)
        if address:
            ips.add(address)
        elif domain:
            domains.add(domain)

    def add_url(value):
        url = _url(value)
        if url:
            urls.add(url)
            add_host(urlsplit(url).hostname)
        return url

    text_parts = [str(email_data.get(field) or "") for field in
                  ("subject", "body", "from", "reply_to", "return_path")]
    text_parts.extend(str(header) for header in email_data.get("received") or [])
    html_parts = email_data.get("html_parts") or []
    if isinstance(html_parts, str):
        html_parts = [html_parts]
    # Compatibility with older callers that supplied raw HTML as body text.
    if "html_parts" not in email_data and HTML_BODY_PATTERN.search(text_parts[1]):
        html_parts = [text_parts[1]]
        text_parts[1] = ""

    for html in html_parts:
        if not isinstance(html, str):
            continue
        evidence = extract_html_content(html)
        text_parts.append(evidence["text"])
        # Recover literal web URLs in CSS, srcset, scripts, and refresh targets;
        # never evaluate these snippets or promote CSS selectors to domains.
        for snippet in evidence["url_texts"]:
            for match in URL_PATTERN.finditer(snippet):
                add_url(_prose_url(match.group()))
        base_url = _url((evidence["base_url"] or "").strip())
        for reference in evidence["references"]:
            try:
                parsed = urlsplit(reference)
                if parsed.scheme.lower() == "mailto":
                    text_parts.append(unquote(parsed.path))
                elif parsed.scheme.lower() in {"http", "https"}:
                    add_url(reference)
                elif not parsed.scheme:
                    if base_url:
                        add_url(urljoin(base_url, reference))
                    elif parsed.netloc:
                        # A scheme-relative link exposes a host, but has no
                        # justified http/https URL without an absolute base.
                        parsed.port  # Validate port syntax before keeping host.
                        add_host(parsed.hostname)
            except ValueError:
                continue

    combined_text = "\n".join(text_parts)
    for match in URL_PATTERN.finditer(combined_text):
        add_url(_prose_url(match.group()))

    # Mask URL tokens before free-text extraction. Their real hosts were added
    # above; path filenames, credentials, and query values are not extra hosts.
    plain_text = URL_PATTERN.sub(" ", combined_text)
    for local, host in EMAIL_PATTERN.findall(plain_text):
        domain = _domain(host)
        if domain and not local.startswith(".") and not local.endswith(".") and ".." not in local:
            emails.add(local.lower() + "@" + domain)
            domains.add(domain)
    for value in DOMAIN_PATTERN.findall(EMAIL_PATTERN.sub(" ", plain_text)):
        domain = _domain(value)
        if domain and domain.rsplit(".", 1)[-1] not in FILE_SUFFIXES:
            domains.add(domain)

    ip_text = re.sub(r'\bIPv6:', ' ', plain_text, flags=re.IGNORECASE)
    for pattern in (IPV6_PATTERN, IP_PATTERN):
        for match in pattern.finditer(ip_text):
            address = _ip(match.group().rstrip("."))
            if address:
                ips.add(address)

    return {
        "urls": sorted(urls),
        "ips": sorted(ips),
        "emails": sorted(emails),
        "domains": sorted(domains),
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m backend.analyzers.ioc_extractor <email.eml>")
        sys.exit(1)
    print(json.dumps(extract_iocs(parse_email(sys.argv[1])), indent=4))
