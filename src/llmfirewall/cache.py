import logging
import time
from collections import OrderedDict
from typing import Optional

from llmfirewall.schemas import ModerationResult

logger = logging.getLogger(__name__)


class ModerationCache:
    def __init__(self, maxsize: int = 10_000, ttl: float = 300.0):
        self._maxsize = maxsize
        self._ttl = ttl
        self._cache: OrderedDict[str, tuple[float, ModerationResult]] = OrderedDict()
        self._hits = 0
        self._misses = 0

    def _make_key(self, text: str) -> str:
        return text.strip().lower()

    def get(self, text: str) -> Optional[ModerationResult]:
        key = self._make_key(text)
        entry = self._cache.get(key)
        if entry is None:
            self._misses += 1
            return None
        timestamp, result = entry
        if time.monotonic() - timestamp > self._ttl:
            del self._cache[key]
            self._misses += 1
            return None
        self._cache.move_to_end(key)
        self._hits += 1
        return result

    def set(self, text: str, result: ModerationResult) -> None:
        key = self._make_key(text)
        while len(self._cache) >= self._maxsize:
            self._cache.popitem(last=False)
        self._cache[key] = (time.monotonic(), result)

    def clear(self) -> None:
        self._cache.clear()
        self._hits = 0
        self._misses = 0
        logger.info("Cache cleared")

    @property
    def stats(self) -> dict:
        total = self._hits + self._misses
        return {
            "size": len(self._cache),
            "maxsize": self._maxsize,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / total, 4) if total else 0.0,
            "ttl_seconds": self._ttl,
        }
