import hashlib
import logging
import secrets
import time
from typing import Optional

logger = logging.getLogger(__name__)

API_KEYS: dict[str, dict] = {}
KEY_USAGE: dict[str, list[float]] = {}
QUOTA_LIMITS: dict[str, int] = {}
TIER_RATE_LIMITS: dict[str, int] = {}


def generate_api_key(label: str = "") -> str:
    key = f"llmfw_{secrets.token_hex(24)}"
    key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
    API_KEYS[key_hash] = {
        "key_prefix": key[:16],
        "label": label or f"key_{len(API_KEYS) + 1}",
        "created_at": time.time(),
        "enabled": True,
        "tier": "default",
    }
    return key


def revoke_api_key(key_hash: str) -> bool:
    if key_hash in API_KEYS:
        API_KEYS[key_hash]["enabled"] = False
        logger.info("Revoked API key: %s", key_hash[:8])
        return True
    return False


def list_api_keys() -> list[dict]:
    return [
        {"key_hash": kh, **details}
        for kh, details in API_KEYS.items()
    ]


def verify_api_key(key: str) -> Optional[dict]:
    if not key:
        return None
    key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
    info = API_KEYS.get(key_hash)
    if info and info.get("enabled"):
        _track_usage(key_hash)
        return {**info, "key_hash": key_hash}
    return None


def set_quota(key_hash: str, max_requests: int) -> None:
    QUOTA_LIMITS[key_hash] = max_requests


def get_quota(key_hash: str) -> Optional[int]:
    return QUOTA_LIMITS.get(key_hash)


def set_tier_rate_limit(tier: str, max_per_minute: int) -> None:
    TIER_RATE_LIMITS[tier] = max_per_minute


def get_tier_rate_limit(tier: str) -> int:
    return TIER_RATE_LIMITS.get(tier, 60)


def _track_usage(key_hash: str) -> None:
    KEY_USAGE.setdefault(key_hash, [])
    KEY_USAGE[key_hash] = [t for t in KEY_USAGE[key_hash] if time.time() - t < 3600]
    KEY_USAGE[key_hash].append(time.time())


def check_quota(key_hash: str) -> bool:
    quota = QUOTA_LIMITS.get(key_hash)
    if quota is None:
        return True
    usage = len(KEY_USAGE.get(key_hash, []))
    if usage >= quota:
        logger.warning("API key %s exceeded quota (%d/%d)", key_hash[:8], usage, quota)
        return False
    return True


def get_usage_stats(key_hash: str) -> dict:
    usage = KEY_USAGE.get(key_hash, [])
    now = time.time()
    return {
        "last_hour": len([t for t in usage if now - t < 3600]),
        "last_day": len([t for t in usage if now - t < 86400]),
        "total": len(usage),
    }
