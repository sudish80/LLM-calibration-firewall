import ipaddress
import logging
import re
import time
from typing import Optional

logger = logging.getLogger(__name__)

_IP_ALLOWLIST: list[str] = []
_IP_BLOCKLIST: list[str] = []
_IP_ALLOWLIST_ENABLED = False
_IP_BLOCKLIST_ENABLED = False

SQL_INJECTION_PATTERNS = [
    r"(?i)'\s*OR\s*'[^']*'\s*=\s*'",
    r"(?i)'\s*OR\s*1\s*=\s*1",
    r"(?i)UNION\s+ALL\s+SELECT",
    r"(?i)UNION\s+SELECT",
    r"(?i)DROP\s+TABLE",
    r"(?i)DELETE\s+FROM",
    r"(?i)INSERT\s+INTO",
    r"(?i)SELECT\s+.*\s+FROM\s+.*\s+WHERE",
    r"(?i)EXEC\s*\(",
    r"(?i)xp_cmdshell",
    r"(?i)pg_sleep\s*\(",
    r"(?i)BENCHMARK\s*\(",
    r"(?i)LOAD_FILE\s*\(",
    r"--\s*$",
    r"/\*.*\*/",
]

SSRF_PATTERNS = [
    r"(?i)https?://169\.254\.\d{1,3}\.\d{1,3}",
    r"(?i)https?://127\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"(?i)https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"(?i)https?://172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}",
    r"(?i)https?://192\.168\.\d{1,3}\.\d{1,3}",
    r"(?i)https?://0\.0\.0\.0",
    r"(?i)https?://localhost",
    r"(?i)https?://metadata\.google\.internal",
    r"(?i)https?://169\.254\.169\.254",
    r"(?i)file://",
    r"(?i)dict://",
    r"(?i)gopher://",
]


def configure_ip_lists(allowlist: Optional[list[str]] = None, blocklist: Optional[list[str]] = None) -> None:
    global _IP_ALLOWLIST, _IP_BLOCKLIST, _IP_ALLOWLIST_ENABLED, _IP_BLOCKLIST_ENABLED
    if allowlist is not None:
        _IP_ALLOWLIST = allowlist
        _IP_ALLOWLIST_ENABLED = len(allowlist) > 0
    if blocklist is not None:
        _IP_BLOCKLIST = blocklist
        _IP_BLOCKLIST_ENABLED = len(blocklist) > 0
    logger.info("IP lists configured: allow=%d, block=%d", len(_IP_ALLOWLIST), len(_IP_BLOCKLIST))


def check_ip(ip_str: str) -> tuple[bool, Optional[str]]:
    if not _IP_ALLOWLIST_ENABLED and not _IP_BLOCKLIST_ENABLED:
        return True, None
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, "Invalid IP address"

    if _IP_BLOCKLIST_ENABLED:
        for cidr in _IP_BLOCKLIST:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return False, f"IP blocked by rule: {cidr}"

    if _IP_ALLOWLIST_ENABLED:
        for cidr in _IP_ALLOWLIST:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True, None
        return False, "IP not in allowlist"

    return True, None


def sql_injection_scan(text: str) -> list[str]:
    findings: list[str] = []
    for i, pattern in enumerate(SQL_INJECTION_PATTERNS):
        if re.search(pattern, text):
            findings.append(f"SQLi pattern #{i + 1} matched")
            if len(findings) >= 3:
                break
    return findings


def ssrf_scan(text: str) -> list[str]:
    findings: list[str] = []
    for pattern in SSRF_PATTERNS:
        if re.search(pattern, text):
            findings.append("SSRF pattern detected")
            break
    return findings


def scan_text(text: str) -> list[str]:
    reasons: list[str] = []
    reasons.extend(sql_injection_scan(text))
    reasons.extend(ssrf_scan(text))
    return reasons
