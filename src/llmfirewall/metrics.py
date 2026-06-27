import time
from typing import Callable

from prometheus_client import Counter, Gauge, Histogram, generate_latest

moderation_total = Counter(
    "llmfirewall_moderation_total",
    "Total moderation requests",
    ["allowed"],
)

moderation_latency = Histogram(
    "llmfirewall_moderation_latency_seconds",
    "Moderation latency in seconds",
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

block_reasons_total = Counter(
    "llmfirewall_block_reasons_total",
    "Blocked requests by reason",
    ["reason"],
)

cache_hits_total = Counter(
    "llmfirewall_cache_hits_total",
    "Cache hit count",
)

cache_misses_total = Counter(
    "llmfirewall_cache_misses_total",
    "Cache miss count",
)

cache_size = Gauge(
    "llmfirewall_cache_size",
    "Current cache entry count",
)

models_loaded = Gauge(
    "llmfirewall_models_loaded",
    "Whether each model is loaded (1 = loaded, 0 = not)",
    ["model"],
)

rate_limit_blocks = Counter(
    "llmfirewall_rate_limit_blocks_total",
    "Requests blocked by rate limiter",
)

layer_latency = Histogram(
    "llmfirewall_layer_latency_seconds",
    "Per-layer latency in seconds",
    ["layer"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
)

total_api_keys = Gauge(
    "llmfirewall_total_api_keys",
    "Total number of active API keys",
)

sql_injection_blocks = Counter(
    "llmfirewall_sql_injection_blocks_total",
    "SQL injection attempts blocked",
)

encoding_blocks = Counter(
    "llmfirewall_encoding_blocks_total",
    "Requests blocked by encoded payload detection",
)


def track_moderation(allowed: bool, elapsed: float, reasons: list[str]) -> None:
    moderation_total.labels(allowed="true" if allowed else "false").inc()
    moderation_latency.observe(elapsed)
    if not allowed:
        for reason in reasons:
            block_reasons_total.labels(reason=reason).inc()


def track_layer(layer: str, elapsed: float) -> None:
    layer_latency.labels(layer=layer).observe(elapsed)


def metrics_endpoint() -> tuple[str, str]:
    return generate_latest().decode("utf-8"), "text/plain; charset=utf-8"
