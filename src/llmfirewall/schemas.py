from typing import Optional

from pydantic import BaseModel, Field


class LayerContribution(BaseModel):
    layer: str
    score: float = 0.0
    detail: str = ""


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
    sanitized_input: Optional[str] = None
    allowed: bool
    reasons: list[str] = Field(default_factory=list)
    toxicity: Optional[ToxicityResult] = None
    sentiment: Optional[SentimentResult] = None
    intent: Optional[IntentResult] = None
    semantic_similarity: Optional[float] = None
    closest_malicious_match: Optional[str] = None
    neural_risk_score: Optional[float] = None
    layer_contributions: list[LayerContribution] = Field(default_factory=list)


class FirewallConfig(BaseModel):
    toxicity_threshold: float = 0.5
    sentiment_threshold: float = 0.9
    semantic_threshold: float = 0.8
    neural_hard_block_threshold: float = 0.75


class HealthResponse(BaseModel):
    status: str
    version: str
    layers: list[str]
    models: Optional[dict[str, bool]] = None
    uptime_seconds: Optional[float] = None


class HealthDetailedResponse(HealthResponse):
    cache_size: Optional[int] = None
    cache_hit_rate: Optional[float] = None
    audit_records: Optional[int] = None
    seed_count: Optional[int] = None


class ModerateRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10_000)


class ModerateResponse(BaseModel):
    result: ModerationResult


class VersionInfo(BaseModel):
    api_version: str = "v1"
    package_version: str = "1.0.0"
    models: dict[str, str]
