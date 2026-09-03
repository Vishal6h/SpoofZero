"""Parse reported Authentication-Results without evaluating authentication."""
import re

from .domain_alignment import identity_domain, normalize_domain


KNOWN_RESULTS = {
    "spf": {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy"},
    "dkim": {"pass", "fail", "none", "temperror", "permerror", "neutral", "policy"},
    "dmarc": {"pass", "fail", "bestguesspass", "none", "temperror", "permerror"},
}
_VALUE = r'"(?:\\.|[^"\\])*"|[^\s";]+'
_PROPERTY = re.compile(
    rf'([a-z][a-z0-9_-]*(?:\s*\.\s*[a-z][a-z0-9_-]*)?)\s*=\s*({_VALUE})', re.I
)
_METHOD = re.compile(
    r'^([a-z][a-z0-9_-]*)(?:\s*/\s*(\d+))?\s*=\s*([a-z][a-z0-9_-]*)(?=\s|$)', re.I
)


def split_clauses(value):
    """Split semicolons outside quotes/comments and remove nested comments.

    Malformed tails are discarded as syntax, but remain in the raw evidence.
    This prevents text in a reason/comment being promoted to a PASS result.
    """
    clauses, current, issues = [], [], []
    depth, quoted, escaped = 0, False, False
    for char in str(value):
        if escaped:
            if depth == 0:
                current.append(char)
            escaped = False
        elif char == "\\" and (depth or quoted):
            if not depth:
                current.append(char)
            escaped = True
        elif depth:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
        elif char == '"':
            quoted = not quoted
            current.append(char)
        elif quoted:
            current.append(char)
        elif char == "(":
            depth = 1
            current.append(" ")
        elif char == ")":
            issues.append("Unmatched closing comment")
            current.append(" ")
        elif char == ";":
            clauses.append("".join(current).strip())
            current = []
        elif char in "\r\n\t":
            current.append(" ")
        elif ord(char) < 32 or ord(char) == 127:
            issues.append("Invalid control character")
            current.append(" ")
        else:
            current.append(char)
    if depth or quoted or escaped:
        issues.append("Unterminated comment, quote, or escape")
    else:
        clauses.append("".join(current).strip())
    return clauses, list(dict.fromkeys(issues))


def _unquote(value):
    if value.startswith('"') and value.endswith('"'):
        return re.sub(r"\\(.)", r"\1", value[1:-1])
    return value


def _properties(text):
    properties, issues, end = {}, [], 0
    for match in _PROPERTY.finditer(text):
        if text[end:match.start()].strip():
            issues.append("Unparsed authentication property text")
        key = re.sub(r"\s", "", match[1]).lower()
        properties.setdefault(key, []).append(_unquote(match[2]))
        end = match.end()
    if text[end:].strip():
        issues.append("Unparsed authentication property text")
    if any(len(values) > 1 for values in properties.values()):
        issues.append("Duplicate authentication property")
    return properties, issues


def _one(properties, *names):
    values = [value for name in names for value in properties.get(name, [])]
    return values[0] if len(values) == 1 else None


def _identities(method, properties):
    if method == "spf":
        mailfrom = _one(properties, "smtp.mailfrom", "smtp.envelope-from", "envelope-from")
        helo = _one(properties, "smtp.helo", "helo")
        return {"mailfrom": mailfrom, "mailfrom_domain": identity_domain(mailfrom),
                "helo": helo, "helo_domain": normalize_domain(helo)}
    if method == "dkim":
        signing = _one(properties, "header.d", "d")
        return {"signing_domain": normalize_domain(signing)}
    if method == "dmarc":
        return {"header_from_domain": identity_domain(_one(properties, "header.from"))}
    return {}


def parse_authentication_results(value, index=0):
    raw = str(value)
    clauses, issues = split_clauses(raw)
    authserv_id, version = None, "1"
    if clauses:
        prefix = re.fullmatch(rf'({_VALUE})(?:\s+(\d+))?', clauses[0])
        if prefix and "=" not in prefix[1]:
            authserv_id = _unquote(prefix[1]).lower().rstrip(".")
            version = prefix[2] or "1"
            clauses = clauses[1:]
        else:
            issues.append("Missing or malformed authserv-id")
    else:
        issues.append("Empty or malformed header")
    if version != "1":
        issues.append("Unsupported Authentication-Results version")
    methods = []
    no_result = [clause.lower() for clause in clauses] == ["none"]
    for clause in clauses:
        if clause.lower() == "none" and no_result:
            continue
        match = _METHOD.match(clause)
        if not match:
            issues.append("Malformed authentication result clause")
            continue
        method, method_version, result = match[1].lower(), match[2] or "1", match[3].lower()
        properties, property_issues = _properties(clause[match.end():])
        method_issues = list(property_issues)
        if method_version != "1":
            method_issues.append("Unsupported authentication method version")
        methods.append({
            "method": method, "result": result, "version": method_version,
            "known_result": result in KNOWN_RESULTS.get(method, set()),
            "usable": version == "1" and method_version == "1" and not property_issues,
            "properties": properties, "identities": _identities(method, properties),
            "issues": method_issues,
        })
        issues.extend(method_issues)
    if not clauses:
        issues.append("No authentication result clauses")
    return {
        "header_index": index, "raw": raw, "authserv_id": authserv_id,
        "version": version, "no_result": no_result, "methods": methods,
        "issues": list(dict.fromkeys(issues)), "malformed": bool(issues),
    }
