import logging
import re
from typing import Optional

import torch
from transformers import pipeline

from llmfirewall.config import settings
from llmfirewall.schemas import ModerationResult, ToxicityResult, SentimentResult, IntentResult
from llmfirewall.exceptions import ModelLoadError

logger = logging.getLogger(__name__)


class LLMFirewall:
    def __init__(
        self,
        toxicity_threshold: Optional[float] = None,
        sentiment_threshold: Optional[float] = None,
    ):
        self.toxicity_threshold = toxicity_threshold if toxicity_threshold is not None else settings.toxicity_threshold
        self.sentiment_threshold = sentiment_threshold if sentiment_threshold is not None else settings.sentiment_threshold
        self._load_models()
        self._setup_patterns()

    def _resolve_device(self) -> int:
        if settings.device == "auto":
            return 0 if torch.cuda.is_available() else -1
        if settings.device == "cpu":
            return -1
        return 0

    def _load_models(self):
        logger.info("Loading models...")
        device = self._resolve_device()
        model_kwargs = {"device": device}
        if settings.model_cache_dir:
            model_kwargs["cache_dir"] = settings.model_cache_dir

        try:
            self.toxicity_model = pipeline(
                "text-classification",
                model=settings.model_toxicity,
                **model_kwargs,
            )
        except Exception as e:
            raise ModelLoadError(f"Failed to load toxicity model: {e}") from e

        try:
            self.intent_model = pipeline(
                "zero-shot-classification",
                model=settings.model_intent,
                **model_kwargs,
            )
        except Exception as e:
            raise ModelLoadError(f"Failed to load intent model: {e}") from e

        try:
            self.sentiment_model = pipeline(
                "sentiment-analysis",
                model=settings.model_sentiment,
                **model_kwargs,
            )
        except Exception as e:
            raise ModelLoadError(f"Failed to load sentiment model: {e}") from e

        logger.info("Models loaded successfully.")

    def _setup_patterns(self):
        self.patterns = {
            "prompt_injection": [
                r"ignore.*previous.*instructions",
                r"forget.*training.*data",
                r"jailbreak.*bypass",
            ],
            "sensitive_patterns": [
                r"\b\d{3}-\d{2}-\d{4}\b",
                r"\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b",
            ],
        }

    def detect_prompt_injection(self, text: str) -> bool:
        return any(re.search(p, text.lower()) for p in self.patterns["prompt_injection"])

    def detect_pii(self, text: str) -> bool:
        return any(re.search(p, text) for p in self.patterns["sensitive_patterns"])

    def moderate(self, text: str) -> ModerationResult:
        reasons: list[str] = []
        allowed = True

        if self.detect_pii(text):
            allowed = False
            reasons.append("PII detected")

        if self.detect_prompt_injection(text):
            allowed = False
            reasons.append("Prompt injection detected")

        intent_raw = self.intent_model(
            text,
            ["educational", "informative", "malicious", "dangerous", "benign"],
        )
        intent = IntentResult(labels=intent_raw["labels"], scores=intent_raw["scores"])
        top_intent = intent.labels[0]

        edu_score = max(
            intent.scores[intent.labels.index("educational")],
            intent.scores[intent.labels.index("informative")],
        )
        is_educational = edu_score > settings.edu_override_score or top_intent in ["educational", "informative"]

        tox_raw = self.toxicity_model(text)[0]
        toxicity = ToxicityResult(label=tox_raw["label"], score=tox_raw["score"])

        sent_raw = self.sentiment_model(text)[0]
        sentiment = SentimentResult(label=sent_raw["label"], score=sent_raw["score"])

        if toxicity.score > self.toxicity_threshold:
            allowed = False
            reasons.append("Toxic content detected")

        if not is_educational:
            if sentiment.label == "NEGATIVE" and sentiment.score > self.sentiment_threshold:
                allowed = False
                reasons.append("Extreme negative sentiment detected")
            if top_intent in ["malicious", "dangerous"]:
                allowed = False
                reasons.append(f"Malicious intent detected ({top_intent})")

        return ModerationResult(
            input=text,
            allowed=allowed,
            reasons=reasons,
            toxicity=toxicity,
            sentiment=sentiment,
            intent=intent,
        )
