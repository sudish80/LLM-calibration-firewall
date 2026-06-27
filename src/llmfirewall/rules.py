import fnmatch
import logging
import re
from typing import Any, Callable, Optional

from llmfirewall.schemas import ModerationResult

logger = logging.getLogger(__name__)

RuleAction = Callable[[str, dict], Optional[list[str]]]

_BUILTIN_RULES: dict[str, str] = {
    "block_corporate_secrets": r"(?i)(password|secret|token|api[_-]?key)\s*[=:]\s*\S{16,}",
    "block_credit_card_strict": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "block_ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "block_email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "block_ip_address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    "block_phone_us": r"\b\d{3}[-.)]\s?\d{3}[-.]\d{4}\b",
    "flag_base64_like": r"(?:[A-Za-z0-9+/]{40,}={0,2})",
    "flag_hex_string": r"\b(?:0x)?[0-9a-fA-F]{16,}\b",
}

_ALLOWLIST: list[str] = []
_DENYLIST: list[str] = []


def get_builtin_rules() -> dict[str, str]:
    return dict(_BUILTIN_RULES)


def add_custom_rule(name: str, pattern: str) -> None:
    _BUILTIN_RULES[name] = pattern
    logger.info("Added custom rule '%s'", name)


def remove_custom_rule(name: str) -> bool:
    if name in _BUILTIN_RULES:
        del _BUILTIN_RULES[name]
        logger.info("Removed rule '%s'", name)
        return True
    return False


def list_rules() -> list[dict]:
    return [{"name": k, "pattern": v, "builtin": True} for k, v in _BUILTIN_RULES.items()]


def test_rule(pattern: str, text: str) -> dict:
    try:
        compiled = re.compile(pattern)
        matches = compiled.findall(text)
        return {"valid": True, "matches": len(matches), "samples": matches[:5]}
    except re.error as e:
        return {"valid": False, "error": str(e)}


def add_allowlist(word: str) -> None:
    w = word.strip().lower()
    if w and w not in _ALLOWLIST:
        _ALLOWLIST.append(w)


def remove_allowlist(word: str) -> bool:
    w = word.strip().lower()
    if w in _ALLOWLIST:
        _ALLOWLIST.remove(w)
        return True
    return False


def list_allowlist() -> list[str]:
    return list(_ALLOWLIST)


def add_denylist(word: str) -> None:
    w = word.strip().lower()
    if w and w not in _DENYLIST:
        _DENYLIST.append(w)


def remove_denylist(word: str) -> bool:
    w = word.strip().lower()
    if w in _DENYLIST:
        _DENYLIST.remove(w)
        return True
    return False


def list_denylist() -> list[str]:
    return list(_DENYLIST)


def apply_allowlist(text: str) -> str:
    if not _ALLOWLIST:
        return text
    result = text
    for word in _ALLOWLIST:
        result = result.replace(word, "")
    return result


def apply_denylist(text: str, reasons: list[str]) -> bool:
    if not _DENYLIST:
        return False
    text_lower = text.lower()
    blocked = False
    for word in _DENYLIST:
        if word in text_lower:
            reasons.append(f"Denylist match: '{word}'")
            blocked = True
    return blocked


def scan_custom_rules(text: str, reasons: list[str]) -> bool:
    blocked = False
    for name, pattern in _BUILTIN_RULES.items():
        try:
            if re.search(pattern, text):
                reasons.append(f"Rule '{name}' matched")
                blocked = True
        except re.error:
            continue
    return blocked
