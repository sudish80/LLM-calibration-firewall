import logging
import re
from pathlib import Path
from typing import Optional

import yaml
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    pass


class FirewallSettings(BaseSettings):
    toxicity_threshold: float = 0.5
    sentiment_threshold: float = 0.9
    semantic_threshold: float = 0.8
    neural_hard_block_threshold: float = 0.75
    neural_moderate_block_threshold: float = 0.60
    neural_edu_override_threshold: float = 0.60
    edu_override_score: float = 0.35

    device: str = "auto"

    chromadb_persist_directory: Optional[str] = "./data/chromadb"
    model_cache_dir: Optional[str] = "./data/models"

    model_toxicity: str = "unitary/toxic-bert"
    model_intent: str = "facebook/bart-large-mnli"
    model_sentiment: str = "distilbert-base-uncased-finetuned-sst-2-english"

    server_host: str = "0.0.0.0"
    server_port: int = 8000
    server_log_level: str = "info"
    server_log_format: str = "text"
    server_workers: int = 1
    server_rate_limit_max: int = 60
    server_rate_limit_window: float = 60.0
    cors_origins: list[str] = ["*"]
    max_input_length: int = 10_000

    api_key: Optional[str] = None
    jwt_secret: Optional[str] = None

    cache_maxsize: int = 10_000
    cache_ttl: float = 300.0

    audit_log_path: str = "./data/audit.jsonl"

    model_config = SettingsConfigDict(
        env_prefix="LLMFW_",
        env_file=".env",
        env_file_encoding="utf-8",
    )

    def validate(self) -> None:
        errors: list[str] = []

        if not 0.0 <= self.toxicity_threshold <= 1.0:
            errors.append("toxicity_threshold must be between 0.0 and 1.0")
        if not 0.0 <= self.semantic_threshold <= 1.0:
            errors.append("semantic_threshold must be between 0.0 and 1.0")
        if not 0.0 <= self.neural_hard_block_threshold <= 1.0:
            errors.append("neural_hard_block_threshold must be between 0.0 and 1.0")
        if self.neural_moderate_block_threshold >= self.neural_hard_block_threshold:
            errors.append("neural_moderate_block_threshold must be less than neural_hard_block_threshold")

        if self.device not in ("auto", "cpu", "cuda"):
            errors.append(f"device must be 'auto', 'cpu', or 'cuda', got '{self.device}'")

        if self.server_workers < 1:
            errors.append("server_workers must be >= 1")
        if self.server_rate_limit_max < 1:
            errors.append("server_rate_limit_max must be >= 1")
        if self.server_rate_limit_window <= 0:
            errors.append("server_rate_limit_window must be > 0")
        if self.max_input_length < 1:
            errors.append("max_input_length must be >= 1")
        if self.cache_maxsize < 1:
            errors.append("cache_maxsize must be >= 1")
        if self.cache_ttl <= 0:
            errors.append("cache_ttl must be > 0")

        model_pattern = re.compile(r"^[\w\-]+/[\w\-\.]+$")
        for name, val in [
            ("model_toxicity", self.model_toxicity),
            ("model_intent", self.model_intent),
            ("model_sentiment", self.model_sentiment),
        ]:
            if val and not model_pattern.match(val):
                errors.append(f"{name} does not look like a valid HuggingFace model ID: '{val}'")

        if errors:
            raise ValidationError("\n".join(errors))

    @classmethod
    def from_yaml(cls, path: str = "firewall.yaml") -> "FirewallSettings":
        path_obj = Path(path)
        if not path_obj.exists():
            logger.info("No YAML config found at %s, using env defaults", path)
            return cls()
        with open(path_obj) as f:
            raw = yaml.safe_load(f)
        env_map = {}
        for key, value in (raw or {}).items():
            env_key = f"LLMFW_{key.upper()}"
            env_map[env_key] = value
        inst = cls(**env_map)
        try:
            inst.validate()
            logger.info("Configuration validated successfully")
        except ValidationError as e:
            logger.warning("Configuration validation warnings:\n%s", e)
        return inst


def load_settings(config_path: Optional[str] = None) -> FirewallSettings:
    if config_path:
        return FirewallSettings.from_yaml(config_path)
    yaml_paths = ["firewall.yaml", "firewall.yml", "config/firewall.yaml"]
    for yp in yaml_paths:
        if Path(yp).exists():
            logger.info("Loading config from %s", yp)
            return FirewallSettings.from_yaml(yp)
    inst = FirewallSettings()
    try:
        inst.validate()
    except ValidationError as e:
        logger.warning("Configuration validation warnings:\n%s", e)
    return inst


settings = load_settings()
