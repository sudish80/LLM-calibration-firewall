import json
import logging
from pathlib import Path
from typing import Optional

import yaml
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class FirewallSettings(BaseSettings):
    # Detection thresholds
    toxicity_threshold: float = 0.5
    sentiment_threshold: float = 0.9
    semantic_threshold: float = 0.8
    neural_hard_block_threshold: float = 0.75
    neural_moderate_block_threshold: float = 0.60
    neural_edu_override_threshold: float = 0.60
    edu_override_score: float = 0.35

    # Hardware
    device: str = "auto"

    # Paths
    chromadb_persist_directory: Optional[str] = "./data/chromadb"
    model_cache_dir: Optional[str] = "./data/models"

    # Model selection
    model_toxicity: str = "unitary/toxic-bert"
    model_intent: str = "facebook/bart-large-mnli"
    model_sentiment: str = "distilbert-base-uncased-finetuned-sst-2-english"

    # Server
    server_host: str = "0.0.0.0"
    server_port: int = 8000
    server_log_level: str = "info"
    server_log_format: str = "text"
    server_workers: int = 1
    server_rate_limit_max: int = 60
    server_rate_limit_window: float = 60.0
    cors_origins: list[str] = ["*"]
    max_input_length: int = 10_000

    # Auth
    api_key: Optional[str] = None
    jwt_secret: Optional[str] = None

    # Cache
    cache_maxsize: int = 10_000
    cache_ttl: float = 300.0

    # Audit
    audit_log_path: str = "./data/audit.jsonl"

    model_config = SettingsConfigDict(
        env_prefix="LLMFW_",
        env_file=".env",
        env_file_encoding="utf-8",
    )

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
        return cls(**env_map)


def load_settings(config_path: Optional[str] = None) -> FirewallSettings:
    if config_path:
        return FirewallSettings.from_yaml(config_path)
    yaml_paths = ["firewall.yaml", "firewall.yml", "config/firewall.yaml"]
    for yp in yaml_paths:
        if Path(yp).exists():
            logger.info("Loading config from %s", yp)
            return FirewallSettings.from_yaml(yp)
    return FirewallSettings()


settings = load_settings()
