from typing import Optional

from pydantic import BaseModel, Field


class IntentResult(BaseModel):
    labels: list[str]
    scores: list[float]


class ToxicityResult(BaseModel):
    label: str
    score: float


class SentimentResult(BaseModel):
    label: str
    score: float


class ModerationResult(BaseModel):
    input: str
    allowed: bool
    reasons: list[str] = Field(default_factory=list)
    toxicity: Optional[ToxicityResult] = None
    sentiment: Optional[SentimentResult] = None
    intent: Optional[IntentResult] = None
    semantic_similarity: Optional[float] = None
    closest_malicious_match: Optional[str] = None
    neural_risk_score: Optional[float] = None


class FirewallConfig(BaseModel):
    toxicity_threshold: float = 0.5
    sentiment_threshold: float = 0.9
    semantic_threshold: float = 0.8


class HealthResponse(BaseModel):
    status: str
    version: str
    layers: list[str]


class ModerateRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10_000)


class ModerateResponse(BaseModel):
    result: ModerationResult
