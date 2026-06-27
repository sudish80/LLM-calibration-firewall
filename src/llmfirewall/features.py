import logging
import re
import time
from typing import Optional

from llmfirewall.firewall import LLMFirewall

logger = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self, max_requests: int = 10, time_window: float = 60.0):
        self.max_requests = max_requests
        self.time_window = time_window
        self._buckets: dict[str, dict] = {}

    def check(self, user_id: str) -> bool:
        now = time.time()
        bucket = self._buckets.get(user_id)

        if bucket is None:
            self._buckets[user_id] = {"count": 1, "start": now}
            return True

        if now - bucket["start"] > self.time_window:
            self._buckets[user_id] = {"count": 1, "start": now}
            return True

        if bucket["count"] >= self.max_requests:
            return False

        bucket["count"] += 1
        return True


class AdvancedFirewallFeatures:
    def __init__(self, firewall: LLMFirewall):
        self.firewall = firewall
        self.rate_limiter = RateLimiter()

    def add_rate_limiting(
        self,
        user_id: str,
        max_requests: Optional[int] = None,
        time_window: Optional[float] = None,
    ) -> bool:
        if max_requests is not None or time_window is not None:
            self.rate_limiter = RateLimiter(
                max_requests=max_requests or self.rate_limiter.max_requests,
                time_window=time_window or self.rate_limiter.time_window,
            )
        return self.rate_limiter.check(user_id)

    @staticmethod
    def detect_anomalies(text: str) -> list[str]:
        anomalies: list[str] = []
        if re.search(r"([!?]){3,}", text):
            anomalies.append("Excessive punctuation")
        if len(text.split()) > 200:
            anomalies.append("Excessive length")
        return anomalies
