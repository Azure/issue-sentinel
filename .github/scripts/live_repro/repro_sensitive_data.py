# GENERATED FILE - DO NOT EDIT.
# Vendored from x-engineering-agent `src/security/sensitive_data.py` by
# `scripts/sync_issue_sentinel_repro.py`; edit the source and re-run it.
"""Local, fail closed sensitive information detection for untrusted input."""

import hashlib
import re

SENSITIVE_INFO_REQUEST_MARKER = (
    "<!-- agent-assist:sensitive-information-request -->"
)
BLOCKED_TITLE = "[blocked: sensitive information detected]"
BLOCKED_BODY = (
    "Issue content was withheld because the local sensitive-information "
    "scanner found data that must be removed before automated processing."
)

_PATTERNS = (
    ("private_key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", re.I)),
    ("github_token", re.compile(
        r"\b(?:github_pat_[A-Za-z0-9_]{20,255}|"
        r"gh[pousr]_[A-Za-z0-9][A-Za-z0-9_.-]{29,2047})\b")),
    ("azure_storage_key", re.compile(
        r"(?i)\bAccountKey\s*=\s*[A-Za-z0-9+/]{40,}={0,2}")),
    ("azure_sas_token", re.compile(
        r"(?i)(?:[?&]sig=|SharedAccessSignature\s+sr=)[^\s&;]{16,}")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("jwt", re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\."
        r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{10,}\b")),
    ("bearer_token", re.compile(
        r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*\b")),
    ("database_credential", re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|"
        r"mssql)://[^/\s:@]+:[^@\s/]+@")),
    ("credential", re.compile(
        r"""(?ix)
        \b(?:api[_ -]?key|access[_ -]?key|client[_ -]?secret|
        password|passwd|pwd|secret|token|pat)\b
        \s*(?:=|:)\s*
        ["']?(?!<|\{|\[|\$|\*|x{4,}\b|redacted\b|example\b)
        (?=[^\s"',;()[\]{}]{8,})
        (?=[^\s"',;()[\]{}]*[0-9./+~=:-])
        [^\s"',;()[\]{}]{8,}(?![\w(])
        """)),
    ("cloud_identifier", re.compile(
        r"""(?ix)
        \b(?:subscription|tenant|client|object)[_ -]?id\b
        \s*(?:=|:)\s*
        ["']?[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-
        [89ab][0-9a-f]{3}-[0-9a-f]{12}\b
        """)),
    ("email_address", re.compile(
        r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@"
        r"(?!(?:[A-Za-z0-9-]+\.)*example\.(?:com|org|net)\b)"
        r"(?![A-Za-z0-9.-]+\.(?:example|invalid|localhost|test)\b)"
        r"[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b", re.I)),
    ("phone_number", re.compile(
        r"(?<!\w)\+[0-9][0-9 .()-]{7,}[0-9](?!\w)")),
)

_CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_SPECIFIC_CREDENTIAL_CATEGORIES = {
    "private_key",
    "github_token",
    "azure_storage_key",
    "azure_sas_token",
    "aws_access_key",
    "jwt",
    "bearer_token",
    "database_credential",
}
SOURCE_PATCH_SENSITIVE_CATEGORIES = frozenset(
    _SPECIFIC_CREDENTIAL_CATEGORIES | {"credential"}
)


def _is_luhn_valid(value):
    digits = [int(ch) for ch in value if ch.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def scan_sensitive_content(fields, allowed_categories=None):
    """Return only categories and locations and matched values never leave here."""
    allowed = set(allowed_categories) if allowed_categories is not None else None
    findings = []
    seen = set()
    for field in fields:
        location = str(field.get("location") or "unknown")
        text = str(field.get("text") or "")
        for category, pattern in _PATTERNS:
            if allowed is not None and category not in allowed:
                continue
            if category == "credential" and any(
                existing_location == location
                and existing_category in _SPECIFIC_CREDENTIAL_CATEGORIES
                for existing_category, existing_location in seen
            ):
                continue
            if pattern.search(text) and (category, location) not in seen:
                finding = {"category": category, "location": location}
                for key in ("file", "line", "url"):
                    if field.get(key) is not None:
                        finding[key] = field[key]
                findings.append(finding)
                seen.add((category, location))
        if (
            (allowed is None or "payment_card" in allowed)
            and any(
                _is_luhn_valid(match.group(0))
                for match in _CARD_CANDIDATE.finditer(text)
            )
        ):
            key = ("payment_card", location)
            if key not in seen:
                findings.append({
                    "category": "payment_card",
                    "location": location,
                })
                seen.add(key)
    digest = hashlib.sha256()
    for finding in sorted(
        findings, key=lambda item: (item["location"], item["category"])
    ):
        digest.update(finding["location"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(finding["category"].encode("utf-8"))
        digest.update(b"\0")
    return {
        "status": "blocked" if findings else "safe",
        "blocked": bool(findings),
        "finding_count": len(findings),
        "findings": findings,
        "scan_id": digest.hexdigest()[:20],
    }


def redact_sensitive_text(text):
    """Replace detected values locally without returning the matched values."""
    redacted = str(text or "")
    for category, pattern in _PATTERNS:
        redacted = pattern.sub(f"[REDACTED:{category}]", redacted)

    def redact_card(match):
        return (
            "[REDACTED:payment_card]"
            if _is_luhn_valid(match.group(0))
            else match.group(0)
        )

    redacted = _CARD_CANDIDATE.sub(redact_card, redacted)
    return redacted


def finding_summary(scan):
    """Build a safe, value free summary suitable for a public comment."""
    findings = scan.get("findings") or []
    return {
        "categories": sorted({item["category"] for item in findings}),
        "locations": sorted({item["location"] for item in findings}),
    }
