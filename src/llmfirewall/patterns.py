import logging
from typing import Optional

from llmfirewall.config import settings

logger = logging.getLogger(__name__)


class PatternManager:
    def __init__(self, firewall: "LLMFirewall") -> None:
        self._firewall = firewall

    def list_prompt_injection_patterns(self) -> list[str]:
        return list(self._firewall.patterns["prompt_injection"])

    def add_prompt_injection_pattern(self, pattern: str) -> None:
        if pattern not in self._firewall.patterns["prompt_injection"]:
            self._firewall.patterns["prompt_injection"].append(pattern)
            logger.info("Added prompt injection pattern: %s", pattern)

    def remove_prompt_injection_pattern(self, pattern: str) -> bool:
        try:
            self._firewall.patterns["prompt_injection"].remove(pattern)
            logger.info("Removed prompt injection pattern: %s", pattern)
            return True
        except ValueError:
            return False

    def list_sensitive_patterns(self) -> list[str]:
        return list(self._firewall.patterns["sensitive_patterns"])

    def add_sensitive_pattern(self, pattern: str) -> None:
        if pattern not in self._firewall.patterns["sensitive_patterns"]:
            self._firewall.patterns["sensitive_patterns"].append(pattern)
            logger.info("Added sensitive pattern: %s", pattern)

    def remove_sensitive_pattern(self, pattern: str) -> bool:
        try:
            self._firewall.patterns["sensitive_patterns"].remove(pattern)
            logger.info("Removed sensitive pattern: %s", pattern)
            return True
        except ValueError:
            return False


class SeedManager:
    def __init__(self, firewall: "EnhancedVectorFirewall") -> None:
        self._firewall = firewall

    def list_seeds(self) -> list[str]:
        if self._firewall.collection.count() == 0:
            return []
        return self._firewall.collection.get()["documents"]

    def add_seed(self, text: str) -> None:
        existing = self._firewall.collection.get()
        ids = existing["ids"] if existing else []
        next_id = max((int(i.split("_")[1]) for i in ids), default=-1) + 1
        self._firewall.collection.add(
            documents=[text],
            ids=[f"id_{next_id}"],
        )
        logger.info("Added malicious seed: %s", text[:60])

    def remove_seed(self, text: str) -> bool:
        existing = self._firewall.collection.get()
        if not existing or not existing["documents"]:
            return False
        for doc, doc_id in zip(existing["documents"], existing["ids"]):
            if doc == text:
                self._firewall.collection.delete(ids=[doc_id])
                logger.info("Removed malicious seed: %s", text[:60])
                return True
        return False

    def reset_to_defaults(self) -> None:
        from llmfirewall.vector_firewall import MALICIOUS_SEEDS
        existing = self._firewall.collection.get()
        if existing and existing["ids"]:
            self._firewall.collection.delete(ids=existing["ids"])
        self._firewall.collection.add(
            documents=MALICIOUS_SEEDS,
            ids=[f"id_{i}" for i in range(len(MALICIOUS_SEEDS))],
        )
        logger.info("Reset malicious seeds to %d defaults", len(MALICIOUS_SEEDS))
