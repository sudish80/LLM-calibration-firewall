import json
import logging
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from llmfirewall.schemas import ModerationResult

logger = logging.getLogger(__name__)


class LLMFirewallClient:
    def __init__(self, base_url: str = "http://localhost:8000", api_key: Optional[str] = None, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def health(self) -> dict:
        resp = self._get("/health")
        return json.loads(resp)

    def moderate(self, text: str) -> ModerationResult:
        body = json.dumps({"text": text}).encode()
        req = Request(f"{self.base_url}/moderate", data=body, headers=self._headers(), method="POST")
        try:
            resp = urlopen(req, timeout=self.timeout)
            data = json.loads(resp.read().decode())
            return ModerationResult(**data["result"])
        except HTTPError as e:
            detail = e.read().decode()
            raise RuntimeError(f"Moderation failed ({e.code}): {detail}") from e
        except URLError as e:
            raise RuntimeError(f"Connection failed: {e.reason}") from e

    def moderate_batch(self, texts: list[str]) -> list[ModerationResult]:
        body = json.dumps([{"text": t} for t in texts]).encode()
        req = Request(f"{self.base_url}/moderate/batch", data=body, headers=self._headers(), method="POST")
        try:
            resp = urlopen(req, timeout=self.timeout)
            data = json.loads(resp.read().decode())
            return [ModerationResult(**item["result"]) for item in data]
        except HTTPError as e:
            detail = e.read().decode()
            raise RuntimeError(f"Batch moderation failed ({e.code}): {detail}") from e
        except URLError as e:
            raise RuntimeError(f"Connection failed: {e.reason}") from e

    def _get(self, path: str) -> str:
        req = Request(f"{self.base_url}{path}", headers=self._headers(), method="GET")
        try:
            resp = urlopen(req, timeout=self.timeout)
            return resp.read().decode()
        except HTTPError as e:
            raise RuntimeError(f"GET {path} failed ({e.code})") from e
        except URLError as e:
            raise RuntimeError(f"Connection failed: {e.reason}") from e
