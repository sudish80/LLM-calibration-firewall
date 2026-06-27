import logging
import re
import time
from typing import Optional

import torch
from transformers import pipeline

from llmfirewall.config import settings
from llmfirewall.schemas import (
    ModerationResult,
    ToxicityResult,
    SentimentResult,
    IntentResult,
    LayerContribution,
)
from llmfirewall.exceptions import ModelLoadError
from llmfirewall.encoding import analyze_encoding, deobfuscate
from llmfirewall.security_layer import scan_text as security_scan_text
from llmfirewall.rules import apply_denylist, scan_custom_rules
from llmfirewall.metrics import encoding_blocks, sql_injection_blocks

logger = logging.getLogger(__name__)


def sanitize_input(text: str) -> str:
    cleaned = text.replace("\x00", "")
    cleaned = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", cleaned)
    cleaned = cleaned.replace("\r\n", "\n").replace("\r", "\n")
    return cleaned.strip()


class LLMFirewall:
    def __init__(
        self,
        toxicity_threshold: Optional[float] = None,
        sentiment_threshold: Optional[float] = None,
    ):
        self.toxicity_threshold = toxicity_threshold if toxicity_threshold is not None else settings.toxicity_threshold
        self.sentiment_threshold = sentiment_threshold if sentiment_threshold is not None else settings.sentiment_threshold
        self._models_loaded: dict[str, bool] = {}
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

        for name, model_id, task in [
            ("toxicity", settings.model_toxicity, "text-classification"),
            ("sentiment", settings.model_sentiment, "sentiment-analysis"),
        ]:
            try:
                setattr(self, f"{name}_model", pipeline(task, model=model_id, **model_kwargs))
                self._models_loaded[name] = True
                logger.info("Loaded %s model: %s", name, model_id)
            except Exception as e:
                logger.warning("Failed to load %s model (%s): %s", name, model_id, e)
                setattr(self, f"{name}_model", None)
                self._models_loaded[name] = False

        try:
            self.intent_model = pipeline(
                "zero-shot-classification",
                model=settings.model_intent,
                **model_kwargs,
            )
            self._models_loaded["intent"] = True
            logger.info("Loaded intent model: %s", settings.model_intent)
        except Exception as e:
            logger.warning("Failed to load intent model (%s): %s", settings.model_intent, e)
            self.intent_model = None
            self._models_loaded["intent"] = False

        loaded = sum(1 for v in self._models_loaded.values() if v)
        total = len(self._models_loaded)
        logger.info("Models loaded: %d/%d", loaded, total)

    def is_model_healthy(self, name: str) -> bool:
        return self._models_loaded.get(name, False)

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
        raw_text = text
        text = sanitize_input(text)
        contributions: list[LayerContribution] = []
        reasons: list[str] = []
        allowed = True

        encoding_info = analyze_encoding(text)
        if encoding_info["has_homoglyphs"] or encoding_info["has_unicode_obfuscation"]:
            text = deobfuscate(text)
            reasons.append("Encoding obfuscation detected")
            allowed = False
            contributions.append(LayerContribution(layer="encoding", score=1.0, detail="Unicode/homoglyph obfuscation"))
            encoding_blocks.inc()
        else:
            contributions.append(LayerContribution(layer="encoding", score=0.0, detail="No encoding issues"))

        security_reasons = security_scan_text(text)
        for sr in security_reasons:
            reasons.append(sr)
            allowed = False
            if "SQLi" in sr:
                sql_injection_blocks.inc()
        if security_reasons:
            contributions.append(LayerContribution(layer="security", score=1.0, detail="; ".join(security_reasons)))
        else:
            contributions.append(LayerContribution(layer="security", score=0.0, detail="No security issues"))

        if apply_denylist(text, reasons):
            allowed = False
            contributions.append(LayerContribution(layer="denylist", score=1.0, detail="Denylist match"))

        if scan_custom_rules(text, reasons):
            allowed = False
            contributions.append(LayerContribution(layer="rules", score=1.0, detail="Custom rule matched"))

        if self.detect_pii(text):
            allowed = False
            reasons.append("PII detected")
            contributions.append(LayerContribution(layer="structural", score=1.0, detail="PII matched regex"))
        else:
            contributions.append(LayerContribution(layer="structural", score=0.0, detail="No PII detected"))

        if self.detect_prompt_injection(text):
            allowed = False
            reasons.append("Prompt injection detected")
            contributions.append(LayerContribution(layer="structural_pi", score=1.0, detail="Prompt injection matched regex"))
        else:
            contributions.append(LayerContribution(layer="structural_pi", score=0.0, detail="No injection detected"))

        intent: Optional[IntentResult] = None
        toxicity: Optional[ToxicityResult] = None
        sentiment: Optional[SentimentResult] = None

        if self._models_loaded.get("intent") and self.intent_model:
            try:
                intent_raw = self.intent_model(
                    text,
                    ["educational", "informative", "malicious", "dangerous", "benign"],
                )
                intent = IntentResult(labels=intent_raw["labels"], scores=intent_raw["scores"])
            except Exception as e:
                logger.error("Intent model error: %s", e)

        if self._models_loaded.get("toxicity") and self.toxicity_model:
            try:
                tox_raw = self.toxicity_model(text)[0]
                toxicity = ToxicityResult(label=tox_raw["label"], score=tox_raw["score"])
                if toxicity.score > self.toxicity_threshold:
                    allowed = False
                    reasons.append("Toxic content detected")
                    contributions.append(LayerContribution(layer="toxicity", score=toxicity.score, detail=f"Toxicity > {self.toxicity_threshold}"))
                else:
                    contributions.append(LayerContribution(layer="toxicity", score=toxicity.score, detail="Below threshold"))
            except Exception as e:
                logger.error("Toxicity model error: %s", e)
        else:
            contributions.append(LayerContribution(layer="toxicity", score=0.0, detail="Model unavailable"))

        if self._models_loaded.get("sentiment") and self.sentiment_model:
            try:
                sent_raw = self.sentiment_model(text)[0]
                sentiment = SentimentResult(label=sent_raw["label"], score=sent_raw["score"])
            except Exception as e:
                logger.error("Sentiment model error: %s", e)

        edu_score: float = 0.0
        top_intent: str = "benign"
        if intent and intent.labels:
            top_intent = intent.labels[0]
            if "educational" in intent.labels:
                edu_score = intent.scores[intent.labels.index("educational")]
            elif "informative" in intent.labels:
                edu_score = intent.scores[intent.labels.index("informative")]

        is_educational = edu_score > settings.edu_override_score or top_intent in ["educational", "informative"]

        if not is_educational and sentiment and sentiment.label == "NEGATIVE" and sentiment.score > self.sentiment_threshold:
            allowed = False
            reasons.append("Extreme negative sentiment detected")
            contributions.append(LayerContribution(layer="sentiment", score=sentiment.score, detail="Extreme negative sentiment"))
        elif sentiment:
            contributions.append(LayerContribution(layer="sentiment", score=sentiment.score, detail="OK"))

        if not is_educational and top_intent in ["malicious", "dangerous"]:
            allowed = False
            reasons.append(f"Malicious intent detected ({top_intent})")
            contributions.append(LayerContribution(layer="intent", score=1.0, detail=f"Top intent: {top_intent}"))
        elif intent:
            contributions.append(LayerContribution(layer="intent", score=0.0, detail=f"Top intent: {top_intent}"))

        return ModerationResult(
            input=raw_text,
            sanitized_input=text if text != raw_text else None,
            allowed=allowed,
            reasons=reasons,
            toxicity=toxicity,
            sentiment=sentiment,
            intent=intent,
            layer_contributions=contributions,
        )

    async def moderate_async(self, text: str) -> ModerationResult:
        return self.moderate(text)
