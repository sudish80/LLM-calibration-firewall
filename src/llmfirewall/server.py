import json
import logging
import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Optional

import uvicorn
from fastapi import APIRouter, FastAPI, HTTPException, Request, Response, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from llmfirewall import HybridNeuralFirewall
from llmfirewall.audit import AuditLogger
from llmfirewall.cache import ModerationCache
from llmfirewall.config import settings
from llmfirewall.dashboard import render_dashboard
from llmfirewall.metrics import (
    metrics_endpoint,
    models_loaded,
    rate_limit_blocks,
    track_moderation,
)
from llmfirewall.patterns import PatternManager, SeedManager
from llmfirewall.schemas import (
    HealthDetailedResponse,
    HealthResponse,
    ModerateRequest,
    ModerateResponse,
    ModerationResult,
    VersionInfo,
)
from llmfirewall.vector_firewall import EnhancedVectorFirewall
from llmfirewall.auth import (
    generate_api_key, revoke_api_key, list_api_keys, verify_api_key,
    set_quota, get_quota, get_usage_stats, check_quota,
    set_tier_rate_limit, get_tier_rate_limit, KEY_USAGE,
)
from llmfirewall.rules import (
    list_rules, add_custom_rule, remove_custom_rule, test_rule,
    add_allowlist, remove_allowlist, list_allowlist,
    add_denylist, remove_denylist, list_denylist,
)
from llmfirewall.encoding import analyze_encoding, deobfuscate
from llmfirewall.security_layer import (
    configure_ip_lists, check_ip, sql_injection_scan, ssrf_scan,
    _IP_ALLOWLIST, _IP_BLOCKLIST,
)
from llmfirewall.webhooks import register_webhook, remove_webhook, list_webhooks
from llmfirewall.repl import run_batch

logger = logging.getLogger(__name__)

_start_time = time.monotonic()


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "request_id"):
            log_entry["request_id"] = record.request_id
        return json.dumps(log_entry)


def setup_logging() -> None:
    if settings.server_log_format == "json":
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        root = logging.getLogger()
        root.handlers = [handler]
        root.setLevel(getattr(logging, settings.server_log_level.upper(), logging.INFO))
    else:
        logging.basicConfig(
            level=getattr(logging, settings.server_log_level.upper(), logging.INFO),
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)

firewall: Optional[HybridNeuralFirewall] = None
cache: Optional[ModerationCache] = None
audit: Optional[AuditLogger] = None
pattern_manager: Optional[PatternManager] = None
seed_manager: Optional[SeedManager] = None

_rate_limiter: dict[str, list[float]] = {}


def _rate_limit_key(request: Request) -> str:
    api_key = request.headers.get("X-API-Key", "")
    if api_key and settings.api_key:
        return f"key:{api_key[:16]}"
    return f"ip:{request.client.host if request.client else 'unknown'}"


def _check_rate_limit(request: Request) -> None:
    key = _rate_limit_key(request)
    now = time.monotonic()
    bucket = _rate_limiter.get(key, [])
    bucket = [t for t in bucket if now - t < settings.server_rate_limit_window]
    if len(bucket) >= settings.server_rate_limit_max:
        rate_limit_blocks.inc()
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    bucket.append(now)
    _rate_limiter[key] = bucket


async def rate_limit_middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    if request.url.path not in ("/metrics", "/health", "/v1/health", "/dashboard"):
        _check_rate_limit(request)
    return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global firewall, cache, audit, pattern_manager, seed_manager
    logger.info("Initializing firewall engine...")
    t0 = time.monotonic()
    firewall = HybridNeuralFirewall()
    cache = ModerationCache(maxsize=settings.cache_maxsize, ttl=settings.cache_ttl)
    audit = AuditLogger(path=settings.audit_log_path)
    pattern_manager = PatternManager(firewall)
    if isinstance(firewall, EnhancedVectorFirewall):
        seed_manager = SeedManager(firewall)
    models_loaded.labels(model="toxicity").set(1)
    models_loaded.labels(model="intent").set(1)
    models_loaded.labels(model="sentiment").set(1)
    models_loaded.labels(model="chromadb").set(1)
    elapsed = time.monotonic() - t0
    logger.info("Firewall ready in %.2fs", elapsed)
    yield
    if audit:
        audit.flush()
    logger.info("Shutdown complete.")


app = FastAPI(
    title="LLM Firewall API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.middleware("http")(rate_limit_middleware)


def verify_auth(
    api_key: str = Security(api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> None:
    if not settings.api_key and not settings.jwt_secret:
        return
    if api_key and settings.api_key and api_key == settings.api_key:
        return
    if bearer and settings.jwt_secret:
        try:
            jwt.decode(bearer.credentials, settings.jwt_secret, algorithms=["HS256"])
            return
        except JWTError:
            pass
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing credentials")


def _validate_input(text: str) -> None:
    if not text or not text.strip():
        raise HTTPException(status_code=400, detail="Input text cannot be empty")
    if len(text) > settings.max_input_length:
        raise HTTPException(
            status_code=400,
            detail=f"Input text exceeds max length of {settings.max_input_length} characters",
        )


# ---------------------------------------------------------------------------
# Versioned API router  (/v1/*)
# ---------------------------------------------------------------------------
v1 = APIRouter(prefix="/v1")


@v1.get("/version", response_model=VersionInfo)
def get_version():
    return VersionInfo(
        models={
            "toxicity": settings.model_toxicity,
            "intent": settings.model_intent,
            "sentiment": settings.model_sentiment,
        }
    )


@v1.get("/health", response_model=HealthResponse)
def health_v1():
    uptime = time.monotonic() - _start_time
    model_status: dict[str, bool] = {}
    if firewall:
        model_status["toxicity"] = firewall.is_model_healthy("toxicity")
        model_status["intent"] = firewall.is_model_healthy("intent")
        model_status["sentiment"] = firewall.is_model_healthy("sentiment")
        model_status["chromadb"] = getattr(firewall, "_chromadb_healthy", False)
    return HealthResponse(
        status="ok" if all(model_status.values()) else "degraded",
        version="1.0.0",
        layers=["structural", "intent", "toxicity", "semantic", "neural"],
        models=model_status,
        uptime_seconds=round(uptime, 2),
    )


@v1.get("/health-detailed", response_model=HealthDetailedResponse)
def health_detailed_v1():
    base = health_v1()
    return HealthDetailedResponse(
        **base.model_dump(),
        cache_size=cache.stats["size"] if cache else None,
        cache_hit_rate=cache.stats["hit_rate"] if cache else None,
        audit_records=audit.stats["total_records"] if audit else None,
        seed_count=len(seed_manager.list_seeds()) if seed_manager else None,
    )


@v1.post("/moderate", response_model=ModerateResponse, dependencies=[Security(verify_auth)])
def moderate_v1(req: ModerateRequest, request: Request):
    _validate_input(req.text)
    if firewall is None:
        raise HTTPException(status_code=503, detail="Firewall not initialized")

    if cache:
        cached = cache.get(req.text)
        if cached is not None:
            return ModerateResponse(result=cached)

    t0 = time.monotonic()
    try:
        result: ModerationResult = firewall.moderate(req.text)
        elapsed = time.monotonic() - t0
        if cache:
            cache.set(req.text, result)
        if audit:
            audit.log(
                result,
                elapsed=elapsed,
                client_ip=request.client.host if request.client else "",
                api_key_hash=request.headers.get("X-API-Key", "")[:16] if settings.api_key else "",
            )
        track_moderation(result.allowed, elapsed, result.reasons)
        return ModerateResponse(result=result)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Moderation failed for input: %.50s", req.text)
        raise HTTPException(status_code=500, detail=f"Moderation error: {e}")


@v1.post("/moderate/batch", response_model=list[ModerateResponse], dependencies=[Security(verify_auth)])
def moderate_batch_v1(reqs: list[ModerateRequest], request: Request):
    if firewall is None:
        raise HTTPException(status_code=503, detail="Firewall not initialized")
    results: list[ModerateResponse] = []
    for req_item in reqs:
        _validate_input(req_item.text)
        if cache:
            cached = cache.get(req_item.text)
            if cached is not None:
                results.append(ModerateResponse(result=cached))
                continue
        t0 = time.monotonic()
        try:
            result = firewall.moderate(req_item.text)
            elapsed = time.monotonic() - t0
            if cache:
                cache.set(req_item.text, result)
            if audit:
                audit.log(result, elapsed=elapsed, client_ip=request.client.host if request.client else "")
            track_moderation(result.allowed, elapsed, result.reasons)
            results.append(ModerateResponse(result=result))
        except Exception as e:
            logger.exception("Batch moderation failed for input: %.50s", req_item.text)
            results.append(
                ModerateResponse(
                    result=ModerationResult(
                        input=req_item.text,
                        allowed=False,
                        reasons=[f"Internal error: {e}"],
                    )
                )
            )
    return results


# ---------------------------------------------------------------------------
# v1: Admin / Management endpoints
# ---------------------------------------------------------------------------


@v1.post("/admin/config/reload", dependencies=[Security(verify_auth)])
def admin_config_reload():
    from llmfirewall.config import load_settings
    global settings
    new_settings = load_settings()
    for key, val in new_settings.model_dump().items():
        setattr(settings, key, val)
    logger.info("Configuration reloaded")
    return {"status": "ok", "message": "Configuration reloaded"}


@v1.get("/admin/keys", dependencies=[Security(verify_auth)])
def admin_list_api_keys():
    return {"keys": list_api_keys()}


@v1.post("/admin/keys", dependencies=[Security(verify_auth)])
def admin_create_api_key(label: str = ""):
    key = generate_api_key(label)
    return {"api_key": key, "prefix": key[:16]}


@v1.post("/admin/keys/revoke", dependencies=[Security(verify_auth)])
def admin_revoke_api_key(body: dict):
    kh = body.get("key_hash", "")
    ok = revoke_api_key(kh)
    if not ok:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"status": "ok"}


@v1.post("/admin/keys/quota", dependencies=[Security(verify_auth)])
def admin_set_quota(body: dict):
    kh = body.get("key_hash", "")
    quota = body.get("max_requests", 0)
    if not kh or quota < 1:
        raise HTTPException(status_code=400, detail="Invalid key_hash or max_requests")
    set_quota(kh, quota)
    return {"status": "ok", "key_hash": kh, "max_requests": quota}


@v1.get("/admin/keys/usage/{key_hash}", dependencies=[Security(verify_auth)])
def admin_key_usage(key_hash: str):
    return get_usage_stats(key_hash)


@v1.post("/admin/rate-limit/tier", dependencies=[Security(verify_auth)])
def admin_set_tier_rate_limit(body: dict):
    tier = body.get("tier", "default")
    limit = body.get("max_per_minute", 60)
    set_tier_rate_limit(tier, limit)
    return {"status": "ok", "tier": tier, "max_per_minute": limit}


@v1.post("/admin/ip-lists", dependencies=[Security(verify_auth)])
def admin_configure_ip_lists(body: dict):
    configure_ip_lists(
        allowlist=body.get("allowlist"),
        blocklist=body.get("blocklist"),
    )
    return {"status": "ok", "allowlist": _IP_ALLOWLIST, "blocklist": _IP_BLOCKLIST}


@v1.get("/admin/rules", dependencies=[Security(verify_auth)])
def admin_list_rules():
    return {"rules": list_rules(), "allowlist": list_allowlist(), "denylist": list_denylist()}


@v1.post("/admin/rules", dependencies=[Security(verify_auth)])
def admin_add_rule(body: dict):
    name = body.get("name", "")
    pattern = body.get("pattern", "")
    if not name or not pattern:
        raise HTTPException(status_code=400, detail="Missing 'name' or 'pattern'")
    add_custom_rule(name, pattern)
    return {"status": "ok", "name": name}


@v1.delete("/admin/rules", dependencies=[Security(verify_auth)])
def admin_remove_rule(body: dict):
    name = body.get("name", "")
    ok = remove_custom_rule(name)
    if not ok:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "ok"}


@v1.post("/admin/rules/test", dependencies=[Security(verify_auth)])
def admin_test_rule(body: dict):
    pattern = body.get("pattern", "")
    text = body.get("text", "")
    return test_rule(pattern, text)


@v1.post("/admin/allowlist", dependencies=[Security(verify_auth)])
def admin_add_allowlist(body: dict):
    word = body.get("word", "")
    if not word:
        raise HTTPException(status_code=400, detail="Missing 'word'")
    add_allowlist(word)
    return {"status": "ok"}


@v1.delete("/admin/allowlist", dependencies=[Security(verify_auth)])
def admin_remove_allowlist(body: dict):
    word = body.get("word", "")
    ok = remove_allowlist(word)
    if not ok:
        raise HTTPException(status_code=404, detail="Word not in allowlist")
    return {"status": "ok"}


@v1.post("/admin/denylist", dependencies=[Security(verify_auth)])
def admin_add_denylist(body: dict):
    word = body.get("word", "")
    if not word:
        raise HTTPException(status_code=400, detail="Missing 'word'")
    add_denylist(word)
    return {"status": "ok"}


@v1.delete("/admin/denylist", dependencies=[Security(verify_auth)])
def admin_remove_denylist(body: dict):
    word = body.get("word", "")
    ok = remove_denylist(word)
    if not ok:
        raise HTTPException(status_code=404, detail="Word not in denylist")
    return {"status": "ok"}


@v1.post("/admin/encoding/analyze", dependencies=[Security(verify_auth)])
def admin_analyze_encoding(body: dict):
    text = body.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="Missing 'text'")
    return analyze_encoding(text)


@v1.post("/admin/security/scan", dependencies=[Security(verify_auth)])
def admin_security_scan(body: dict):
    text = body.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="Missing 'text'")
    return {"sql_injection": sql_injection_scan(text), "ssrf": ssrf_scan(text)}


@v1.get("/admin/webhooks", dependencies=[Security(verify_auth)])
def admin_list_webhooks():
    return {"webhooks": list_webhooks()}


@v1.post("/admin/webhooks", dependencies=[Security(verify_auth)])
def admin_register_webhook(body: dict):
    url = body.get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="Missing 'url'")
    events = body.get("events")
    secret = body.get("secret", "")
    hook = register_webhook(url, events, secret)
    return {"status": "ok", "webhook": hook}


@v1.delete("/admin/webhooks", dependencies=[Security(verify_auth)])
def admin_remove_webhook(body: dict):
    url = body.get("url", "")
    ok = remove_webhook(url)
    if not ok:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return {"status": "ok"}


@v1.get("/admin/audit", dependencies=[Security(verify_auth)])
def admin_audit_log(page: int = 1, per_page: int = 50):
    if audit is None:
        raise HTTPException(status_code=503, detail="Audit not available")
    stats = audit.stats
    return {
        "page": page,
        "per_page": per_page,
        "total_records": stats["total_records"],
        "stats": stats,
    }


@v1.get("/admin/rate-limits", dependencies=[Security(verify_auth)])
def admin_rate_limits():
    return {
        "rate_limiter_size": len(_rate_limiter),
        "tier_limits": {tier: get_tier_rate_limit(tier) for tier in ["default"]},
    }


app.include_router(v1)

# ---------------------------------------------------------------------------
# Legacy (backward-compatible) endpoints
# ---------------------------------------------------------------------------


@app.get("/health", response_model=HealthResponse)
def health_legacy():
    return health_v1()


@app.get("/metrics")
def metrics():
    body, content_type = metrics_endpoint()
    return Response(content=body, media_type=content_type)


@app.post("/moderate", response_model=ModerateResponse, dependencies=[Security(verify_auth)])
def moderate_legacy(req: ModerateRequest, request: Request):
    return moderate_v1(req, request)


@app.post("/moderate/batch", response_model=list[ModerateResponse], dependencies=[Security(verify_auth)])
def moderate_batch_legacy(reqs: list[ModerateRequest], request: Request):
    return moderate_batch_v1(reqs, request)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(content=render_dashboard())


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------


@app.get("/admin/cache", dependencies=[Security(verify_auth)])
def admin_cache_stats():
    if cache is None:
        raise HTTPException(status_code=503, detail="Cache not available")
    return cache.stats


@app.post("/admin/cache/clear", dependencies=[Security(verify_auth)])
def admin_cache_clear():
    if cache is None:
        raise HTTPException(status_code=503, detail="Cache not available")
    cache.clear()
    return {"status": "ok", "message": "Cache cleared"}


@app.get("/admin/audit/stats", dependencies=[Security(verify_auth)])
def admin_audit_stats():
    if audit is None:
        raise HTTPException(status_code=503, detail="Audit not available")
    return audit.stats


@app.get("/admin/patterns/prompt-injection", dependencies=[Security(verify_auth)])
def admin_list_prompt_injection():
    if pattern_manager is None:
        raise HTTPException(status_code=503, detail="Pattern manager not available")
    return {"patterns": pattern_manager.list_prompt_injection_patterns()}


@app.post("/admin/patterns/prompt-injection", dependencies=[Security(verify_auth)])
def admin_add_prompt_injection(body: dict):
    if pattern_manager is None:
        raise HTTPException(status_code=503, detail="Pattern manager not available")
    pattern = body.get("pattern")
    if not pattern:
        raise HTTPException(status_code=400, detail="Missing 'pattern' field")
    pattern_manager.add_prompt_injection_pattern(pattern)
    return {"status": "ok", "pattern": pattern}


@app.delete("/admin/patterns/prompt-injection", dependencies=[Security(verify_auth)])
def admin_remove_prompt_injection(body: dict):
    if pattern_manager is None:
        raise HTTPException(status_code=503, detail="Pattern manager not available")
    pattern = body.get("pattern")
    if not pattern:
        raise HTTPException(status_code=400, detail="Missing 'pattern' field")
    ok = pattern_manager.remove_prompt_injection_pattern(pattern)
    if not ok:
        raise HTTPException(status_code=404, detail="Pattern not found")
    return {"status": "ok", "pattern": pattern}


@app.get("/admin/seeds", dependencies=[Security(verify_auth)])
def admin_list_seeds():
    if seed_manager is None:
        raise HTTPException(status_code=503, detail="Seed manager not available")
    return {"seeds": seed_manager.list_seeds()}


@app.post("/admin/seeds", dependencies=[Security(verify_auth)])
def admin_add_seed(body: dict):
    if seed_manager is None:
        raise HTTPException(status_code=503, detail="Seed manager not available")
    text = body.get("text")
    if not text:
        raise HTTPException(status_code=400, detail="Missing 'text' field")
    seed_manager.add_seed(text)
    return {"status": "ok"}


@app.delete("/admin/seeds", dependencies=[Security(verify_auth)])
def admin_remove_seed(body: dict):
    if seed_manager is None:
        raise HTTPException(status_code=503, detail="Seed manager not available")
    text = body.get("text")
    if not text:
        raise HTTPException(status_code=400, detail="Missing 'text' field")
    ok = seed_manager.remove_seed(text)
    if not ok:
        raise HTTPException(status_code=404, detail="Seed not found")
    return {"status": "ok"}


@app.post("/admin/seeds/reset", dependencies=[Security(verify_auth)])
def admin_reset_seeds():
    if seed_manager is None:
        raise HTTPException(status_code=503, detail="Seed manager not available")
    seed_manager.reset_to_defaults()
    return {"status": "ok", "message": "Seeds reset to defaults"}


def main() -> None:
    setup_logging()
    uvicorn.run(
        "llmfirewall.server:app",
        host=settings.server_host,
        port=settings.server_port,
        log_level=settings.server_log_level,
        workers=settings.server_workers,
    )


if __name__ == "__main__":
    main()
