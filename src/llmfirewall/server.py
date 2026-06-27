import json
import logging
import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from llmfirewall import HybridNeuralFirewall
from llmfirewall.audit import AuditLogger
from llmfirewall.cache import ModerationCache
from llmfirewall.config import settings
from llmfirewall.metrics import (
    metrics_endpoint,
    models_loaded,
    rate_limit_blocks,
    track_moderation,
)
from llmfirewall.patterns import PatternManager, SeedManager
from llmfirewall.schemas import (
    HealthResponse,
    ModerateRequest,
    ModerateResponse,
    ModerationResult,
)
from llmfirewall.vector_firewall import EnhancedVectorFirewall

logger = logging.getLogger(__name__)


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
    if request.url.path not in ("/metrics", "/health"):
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
        logger.debug("Authenticated via API key")
        return
    if bearer and settings.jwt_secret:
        try:
            jwt.decode(bearer.credentials, settings.jwt_secret, algorithms=["HS256"])
            logger.debug("Authenticated via JWT")
            return
        except JWTError as e:
            logger.warning("JWT validation failed: %s", e)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing credentials")


def _validate_input(text: str) -> None:
    if not text or not text.strip():
        raise HTTPException(status_code=400, detail="Input text cannot be empty")
    if len(text) > settings.max_input_length:
        raise HTTPException(
            status_code=400,
            detail=f"Input text exceeds max length of {settings.max_input_length} characters",
        )


@app.get("/health", response_model=HealthResponse)
def health(request: Request):
    return HealthResponse(
        status="ok",
        version="1.0.0",
        layers=["structural", "intent", "toxicity", "semantic", "neural"],
    )


@app.get("/metrics")
def metrics(request: Request):
    body, content_type = metrics_endpoint()
    return Response(content=body, media_type=content_type)


@app.post("/moderate", response_model=ModerateResponse, dependencies=[Security(verify_auth)])
def moderate(req: ModerateRequest, request: Request):
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


@app.post("/moderate/batch", response_model=list[ModerateResponse], dependencies=[Security(verify_auth)])
def moderate_batch(reqs: list[ModerateRequest], request: Request):
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
