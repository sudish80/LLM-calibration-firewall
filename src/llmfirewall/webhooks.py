import json
import logging
import threading
import time
import urllib.request
from typing import Any, Optional

from llmfirewall.schemas import ModerationResult

logger = logging.getLogger(__name__)

_WEBHOOKS: list[dict] = []
_MAX_RETRIES = 3
_RETRY_DELAY = 2.0


def register_webhook(url: str, events: Optional[list[str]] = None, secret: str = "") -> dict:
    if events is None:
        events = ["block", "allow"]
    hook = {"url": url, "events": events, "secret": secret, "created_at": time.time()}
    _WEBHOOKS.append(hook)
    logger.info("Registered webhook: %s (events: %s)", url, events)
    return hook


def remove_webhook(url: str) -> bool:
    for i, h in enumerate(_WEBHOOKS):
        if h["url"] == url:
            _WEBHOOKS.pop(i)
            logger.info("Removed webhook: %s", url)
            return True
    return False


def list_webhooks() -> list[dict]:
    return list(_WEBHOOKS)


def _deliver_payload(url: str, payload: dict, secret: str = "") -> bool:
    data = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if secret:
        import hashlib
        sig = hashlib.sha256((secret + data.decode()).encode()).hexdigest()
        headers["X-Webhook-Signature"] = sig
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception as e:
        logger.warning("Webhook delivery failed to %s: %s", url, e)
        return False


def dispatch(event: str, result: ModerationResult, elapsed: float) -> None:
    for hook in _WEBHOOKS:
        if event not in hook["events"]:
            continue
        payload = {
            "event": event,
            "timestamp": time.time(),
            "elapsed_seconds": round(elapsed, 4),
            "input": result.input,
            "allowed": result.allowed,
            "reasons": result.reasons,
            "toxicity_score": round(result.toxicity.score, 4) if result.toxicity else None,
            "neural_risk": round(result.neural_risk_score, 4) if result.neural_risk_score is not None else None,
        }

        def _deliver(hook: dict, payload: dict) -> None:
            for attempt in range(_MAX_RETRIES):
                if _deliver_payload(hook["url"], payload, hook.get("secret", "")):
                    return
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_DELAY * (attempt + 1))
            logger.error("Webhook %s failed after %d attempts", hook["url"], _MAX_RETRIES)

        threading.Thread(target=_deliver, args=(hook, payload), daemon=True).start()
