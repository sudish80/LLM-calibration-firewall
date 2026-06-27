import json
import logging
import time
from pathlib import Path
from typing import Optional

from llmfirewall.schemas import ModerationResult

logger = logging.getLogger(__name__)


class AuditLogger:
    def __init__(self, path: str = "./data/audit.jsonl", buffer_size: int = 10):
        self._path = Path(path)
        self._buffer_size = buffer_size
        self._buffer: list[str] = []
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, result: ModerationResult, elapsed: float, client_ip: str = "", api_key_hash: str = "") -> None:
        record = {
            "timestamp": time.time(),
            "elapsed_seconds": round(elapsed, 4),
            "input": result.input,
            "allowed": result.allowed,
            "reasons": result.reasons,
            "toxicity_score": round(result.toxicity.score, 4) if result.toxicity else None,
            "toxicity_label": result.toxicity.label if result.toxicity else None,
            "semantic_similarity": round(result.semantic_similarity, 4) if result.semantic_similarity is not None else None,
            "neural_risk": round(result.neural_risk_score, 4) if result.neural_risk_score is not None else None,
            "client_ip": client_ip,
            "api_key_hash": api_key_hash,
        }
        self._buffer.append(json.dumps(record))
        if len(self._buffer) >= self._buffer_size:
            self.flush()

    def flush(self) -> None:
        if not self._buffer:
            return
        with open(self._path, "a", encoding="utf-8") as f:
            f.write("\n".join(self._buffer) + "\n")
        count = len(self._buffer)
        self._buffer.clear()
        logger.debug("Flushed %d audit records to %s", count, self._path)

    @property
    def stats(self) -> dict:
        if not self._path.exists():
            return {"total_records": 0, "file_size_bytes": 0}
        total = sum(1 for _ in self._path.open() if _.strip())
        return {
            "total_records": total,
            "file_size_bytes": self._path.stat().st_size,
            "buffered": len(self._buffer),
            "path": str(self._path),
        }
