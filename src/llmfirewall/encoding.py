import base64
import binascii
import logging
import re
import urllib.parse
from typing import Optional

logger = logging.getLogger(__name__)

HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "і": "i", "ӏ": "l", "ӧ": "o", "ӓ": "a", "ӱ": "u",
    "Ａ": "A", "Ｂ": "B", "Ｃ": "C", "Ｄ": "D", "Ｅ": "E",
    "０": "0", "１": "1", "２": "2", "３": "3", "４": "4",
    "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
}


def deobfuscate(text: str) -> str:
    result = text
    for obf_char, replacement in HOMOGLYPH_MAP.items():
        result = result.replace(obf_char, replacement)
    return result


def has_homoglyphs(text: str) -> bool:
    for char in text:
        if char in HOMOGLYPH_MAP:
            return True
    return False


def detect_base64(text: str) -> Optional[str]:
    potential = re.findall(r"(?:[A-Za-z0-9+/]{20,}={0,2})", text)
    for candidate in potential:
        try:
            decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
            if any(c.isalpha() for c in decoded) and len(decoded) > 5:
                return decoded[:500]
        except (binascii.Error, ValueError):
            continue
    return None


def detect_hex_encoding(text: str) -> Optional[str]:
    hex_strings = re.findall(r"\b(?:0x)?[0-9a-fA-F]{8,}\b", text)
    for candidate in hex_strings:
        candidate = candidate.replace("0x", "")
        try:
            decoded = bytes.fromhex(candidate).decode("utf-8", errors="ignore")
            if any(c.isalpha() for c in decoded) and len(decoded) > 2:
                return decoded[:500]
        except (ValueError, binascii.Error):
            continue
    return None


def detect_url_encoded(text: str) -> Optional[str]:
    if re.search(r"%[0-9a-fA-F]{2}", text):
        try:
            decoded = urllib.parse.unquote(text)
            if decoded != text:
                return decoded[:500]
        except Exception:
            pass
    return None


def has_unicode_obfuscation(text: str) -> bool:
    unicode_blocks = 0
    for char in text:
        cp = ord(char)
        if 0x0400 <= cp <= 0x04FF:
            unicode_blocks += 1
        if 0x0600 <= cp <= 0x06FF:
            unicode_blocks += 1
        if 0x4E00 <= cp <= 0x9FFF:
            unicode_blocks += 1
    return unicode_blocks > len(text) * 0.3


def analyze_encoding(text: str) -> dict:
    results: dict = {
        "has_homoglyphs": has_homoglyphs(text),
        "has_unicode_obfuscation": has_unicode_obfuscation(text),
        "base64_decoded": detect_base64(text),
        "hex_decoded": detect_hex_encoding(text),
        "url_decoded": detect_url_encoded(text),
    }
    results["decoded_count"] = sum(1 for v in results.values() if isinstance(v, str) and v is not None)
    return results
