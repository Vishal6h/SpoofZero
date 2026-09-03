"""Offline domain comparisons; these are evidence, not DMARC verification."""
from email.utils import getaddresses
from functools import lru_cache
import ipaddress
import re

import tldextract


# Use only the packaged PSL snapshot, including private tenant boundaries.
# No HTTP refresh and no user cache (which could vary between machines).
_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, fallback_to_snapshot=True,
    include_psl_private_domains=True,
)


def normalize_domain(value):
    if not isinstance(value, str):
        return None
    value = value.strip().rstrip(".").lower()
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(value) > 253 or "." not in value:
        return None
    if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
               for label in value.split(".")):
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    if value.replace(".", "").isdigit():
        return None
    return value


def address_domain(value):
    """Require one unambiguous mailbox; do not guess across multiple authors."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        addresses = getaddresses([value])
    except (ValueError, IndexError):
        return None
    if len(addresses) != 1 or "@" not in addresses[0][1]:
        return None
    local, domain = addresses[0][1].rsplit("@", 1)
    return normalize_domain(domain) if local else None


def identity_domain(value):
    """Authentication properties can contain either a mailbox or a domain."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if "@" in value:
        return address_domain(value)
    return normalize_domain(value)


@lru_cache(maxsize=4096)
def organizational_domain(domain):
    domain = normalize_domain(domain)
    if not domain:
        return None
    extracted = _EXTRACT(domain)
    # Unknown suffixes remain unknown; do not assume that the last two labels
    # are an organization. Exact matches can still be compared separately.
    return extracted.top_domain_under_public_suffix or None


def compare_domains(visible_domain, identity):
    left, right = normalize_domain(visible_domain), normalize_domain(identity)
    left_org = organizational_domain(left)
    right_org = organizational_domain(right)
    exact = bool(left and right and left == right)
    if not left or not right:
        status = "unknown"
    elif exact and _EXTRACT(left).suffix == left:
        status = "unknown"  # A public/private suffix alone is not an organization.
    elif exact:
        status = "aligned"
    elif left_org and right_org:
        status = "aligned" if left_org == right_org else "unaligned"
    else:
        status = "unknown"
    return {
        "from_domain": left, "identity_domain": right,
        "from_organizational_domain": left_org,
        "identity_organizational_domain": right_org,
        "strict": exact if left and right else None,
        "relaxed": status == "aligned" if status != "unknown" else None,
        "status": status,
        "basis": "exact" if exact else "offline_psl_including_private",
    }
