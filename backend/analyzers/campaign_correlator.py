"""Offline, explainable correlation over existing SpoofZero analysis results."""

from collections import defaultdict
from email.utils import getaddresses
from hashlib import sha256
from ipaddress import ip_address, ip_network
from itertools import combinations
import re
from urllib.parse import urlsplit, urlunsplit


# Shared provider domains provide context, not campaign evidence.
COMMON_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "google.com", "outlook.com", "hotmail.com",
    "live.com", "yahoo.com", "yahoo.co.uk", "icloud.com", "aol.com",
    "office365.com", "microsoft.com", "protection.outlook.com",
    "amazonses.com", "sendgrid.net", "mailgun.org", "cloudflare.com",
})
EMPTY_SHA256 = sha256(b"").hexdigest()
POLICY_VERSION = "1.0"


def normalize_domain(value):
    if not isinstance(value, str):
        return None
    value = value.strip().rstrip(".").lower()
    try:
        ip_address(value)
        return None
    except ValueError:
        pass
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or labels[-1].isdigit():
        return None
    if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
        return None
    return value


def normalize_ip(value):
    try:
        # Interface scope IDs are local, not Internet identities.
        if not isinstance(value, str) or "%" in value:
            return None
        return str(ip_address(value.strip().strip("[]")))
    except ValueError:
        return None


def normalize_url(value):
    if not isinstance(value, str) or re.search(r"\s|[\x00-\x1f\x7f]", value):
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in ("http", "https"):
            return None
        host = normalize_ip(parsed.hostname) or normalize_domain(parsed.hostname)
        if not host:
            return None
        if ":" in host:
            host = f"[{host}]"
        port = parsed.port
        if port is not None and (parsed.scheme.lower(), port) not in (("http", 80), ("https", 443)):
            host += f":{port}"
        if "@" in parsed.netloc:
            host = parsed.netloc.rsplit("@", 1)[0] + "@" + host
        return urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", parsed.query, parsed.fragment))
    except ValueError:
        return None


def is_common_domain(domain):
    return any(domain == item or domain.endswith("." + item) for item in COMMON_DOMAINS)


def extract_indicators(analysis):
    """Normalize without mutating original evidence; retain every contributing source.

    Weights are evidence strengths, not probabilities. A family contributes only
    its strongest shared indicator, preventing repeated evidence from inflating
    the score. Public IPs include DNS-to-email matches; non-public IPs are context.
    """
    indicators = {}

    def add(kind, value, family, weight, source):
        if not value:
            return
        key = (kind, value)
        entry = indicators.setdefault(key, {
            "kind": kind, "value": value, "family": family,
            "weight": weight, "sources": set(),
        })
        entry["weight"] = max(entry["weight"], weight)
        entry["sources"].add(source)

    def add_ip(value, source, weight=15):
        value = normalize_ip(value)
        if value:
            add("ip", value, "infrastructure", weight if ip_address(value).is_global else 0, source)

    def add_domain(value, source, weight=10):
        value = normalize_domain(value)
        if value:
            add("domain", value, "identity", 0 if is_common_domain(value) else weight, source)

    def add_host(kind, value, source):
        value = normalize_domain(value)
        if value:
            add(kind, value, "infrastructure", 0 if is_common_domain(value) else 3, source)

    email = analysis.get("email") or {}
    relay = analysis.get("relay_trace") or {}
    iocs = analysis.get("iocs") or {}
    sender_domains = set()
    url_hosts = set()
    relay_hosts = set()

    for field in ("from", "reply_to", "return_path"):
        for _, address in getaddresses([str(email.get(field) or "")]):
            local, sep, domain = address.rpartition("@")
            domain = normalize_domain(domain)
            if sep and local and domain:
                # Mailbox comparison is case-insensitive; display names are ignored.
                add("sender", local.lower() + "@" + domain, "identity", 30, "email." + field)
                add_domain(domain, "email." + field)
                sender_domains.add(domain)

    for field in ("from_domain", "reply_to_domain", "return_path_domain"):
        domain = normalize_domain((analysis.get("sender_identity") or {}).get(field))
        if domain:
            sender_domains.add(domain)
            add_domain(domain, "sender_identity." + field)

    for raw_url in iocs.get("urls") or []:
        url = normalize_url(raw_url)
        if url:
            host = urlsplit(url).hostname
            url_hosts.add(host)
            # A shared provider landing page is too generic to link a campaign.
            weight = 10 if is_common_domain(host) else 50
            add("url", url, "content", weight, "iocs.urls")
            add_domain(host, "iocs.urls.host")
            add_ip(host, "iocs.urls.host")

    for hop in relay.get("hops") or []:
        for field in ("from_host", "by_host"):
            host = normalize_domain(hop.get(field))
            if host:
                relay_hosts.add(host)
                add_host("relay_host", host, "relay_trace.hops." + field)
        for item in hop.get("ips") or []:
            add_ip(item.get("ip"), "relay_trace.hops.ips", 10)
    add_ip(relay.get("candidate_origin_ip"), "relay_trace.candidate_origin_ip", 20)

    for value in iocs.get("ips") or []:
        add_ip(value, "iocs.ips")
    for value in iocs.get("domains") or []:
        domain = normalize_domain(value)
        relay_only = domain in relay_hosts and domain not in sender_domains | url_hosts
        add_domain(value, "iocs.domains", 0 if relay_only else 10)

    for item in (analysis.get("attachments") or {}).get("attachments") or []:
        value = str(item.get("sha256") or "").strip().lower()
        if re.fullmatch(r"[a-f0-9]{64}", value):
            weight = 0 if value == EMPTY_SHA256 or item.get("size_bytes") == 0 else 60
            add("attachment_sha256", value, "attachment", weight, "attachments.sha256")

    for domain_data in analysis.get("threat_intelligence") or []:
        domain = domain_data.get("domain") or "unknown"
        dns = domain_data.get("dns") or {}
        for kind in ("A", "AAAA"):
            for value in dns.get(kind) or []:
                add_ip(value, f"dns.{kind}:{domain}", 10)
        for value in dns.get("MX") or []:
            fields = str(value).split()
            if fields:
                add_host("mail_server", fields[-1], f"dns.MX:{domain}")
        for value in dns.get("NS") or []:
            add_host("nameserver", value, f"dns.NS:{domain}")
        for value in (domain_data.get("rdap") or {}).get("nameservers") or []:
            add_host("nameserver", value, f"rdap.nameservers:{domain}")

    network_items = list((analysis.get("reputation") or {}).get("ips") or [])
    network_items.append(analysis.get("geo_analysis") or {})
    for item in network_items:
        if item.get("status") != "success":
            continue
        value = str(item.get("asn") or "").strip().upper().removeprefix("AS")
        if value.isdigit() and 0 < int(value) <= 4294967295:
            add("asn", str(int(value)), "infrastructure", 1, "enrichment.asn")
        try:
            network = ip_network(item.get("network"), strict=False)
            add("network", str(network), "infrastructure", 2 if network.is_global else 0, "reputation.ips.network")
        except (ValueError, TypeError):
            pass

    return [dict(entry, sources=sorted(entry["sources"])) for _, entry in sorted(indicators.items())]


def correlate_emails(records, minimum_score=50):
    """Return all shared evidence and candidate connected components for one case.

    Each record has email_id (raw EML SHA-256), filename, and analysis. Duplicate
    raw emails cannot inflate evidence or create a campaign. No external calls.
    """
    if not 1 <= minimum_score <= 100:
        raise ValueError("Correlation threshold must be between 1 and 100")
    documents = {r["email_id"]: r for r in records}
    index = defaultdict(dict)
    for email_id, record in sorted(documents.items()):
        for indicator in extract_indicators(record["analysis"]):
            index[(indicator["kind"], indicator["value"])][email_id] = indicator

    pair_evidence = defaultdict(list)
    shared = []
    for (kind, value), members in sorted(index.items()):
        if len(members) < 2:
            continue
        shared.append({
            "kind": kind, "value": value, "email_ids": sorted(members),
            "sources": {key: item["sources"] for key, item in sorted(members.items())},
        })
        for left, right in combinations(sorted(members), 2):
            a, b = members[left], members[right]
            pair_evidence[(left, right)].append({
                "kind": kind, "value": value, "family": a["family"],
                "weight": min(a["weight"], b["weight"]),
                "left_sources": a["sources"], "right_sources": b["sources"],
            })

    pairs = []
    adjacency = defaultdict(set)
    for (left, right), evidence in sorted(pair_evidence.items()):
        families = defaultdict(int)
        for item in evidence:
            families[item["family"]] = max(families[item["family"]], item["weight"])
        score = min(100, sum(families.values()))
        has_specific_evidence = any(item["weight"] >= 10 and item["family"] != "infrastructure" for item in evidence)
        linked = score >= minimum_score and has_specific_evidence
        if linked:
            adjacency[left].add(right)
            adjacency[right].add(left)
        pairs.append({
            "left_id": left, "right_id": right, "score": score,
            "linked": linked, "family_scores": dict(families), "evidence": evidence,
        })

    campaigns = []
    visited = set()
    for start in sorted(adjacency):
        if start in visited:
            continue
        pending = [start]
        members = set()
        while pending:
            current = pending.pop()
            if current in members:
                continue
            members.add(current)
            pending.extend(adjacency[current] - members)
        visited.update(members)
        ids = sorted(members)
        edges = [p for p in pairs if p["linked"] and p["left_id"] in members and p["right_id"] in members]
        campaigns.append({
            "campaign_id": "CMP-" + sha256("|".join(ids).encode()).hexdigest()[:12],
            "email_ids": ids, "link_count": len(edges),
            "strongest_link_score": max(p["score"] for p in edges),
        })

    return {
        "policy_version": POLICY_VERSION, "minimum_score": minimum_score,
        "email_count": len(documents), "shared_indicators": shared,
        "pairs": sorted(pairs, key=lambda p: (-p["score"], p["left_id"], p["right_id"])),
        "campaigns": campaigns,
        "unlinked_email_ids": sorted(set(documents) - visited),
        "note": "Candidate groups use transitive links. Correlation is not a maliciousness verdict or proof of a common actor.",
    }
