"""
backend.py -- Project Aegis Production REST API
================================================
FastAPI application with:
  - Redis-backed async job queue (ARQ)
  - Distributed rate limiting (Redis sliding window)
  - Result caching (Redis KV, configurable TTL)
  - Request deduplication (Redis SET NX)
  - Distributed concurrency guard (Redis atomic counter)
  - Bearer token authentication (AEGIS_API_KEY)
  - Structured health endpoint

Endpoints:
  POST /api/v1/run-audit          Enqueue audit job -> 202 {job_id}
  GET  /api/v1/audit-status/{id}  Poll job status
  GET  /api/v1/audit-result/{id}  Retrieve completed result
  GET  /health                    Redis + worker liveness
  GET  /                          API info
"""
from __future__ import annotations

import ipaddress
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import uvicorn
from arq import ArqRedis, create_pool
from arq.connections import RedisSettings
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

try:
    from aegis.core.redis import (
        RATE_LIMIT_RPM,
        active_audits_acquire,
        active_audits_count,
        cache_get,
        cache_key,
        close_redis,
        dedup_acquire,
        dedup_release,
        job_get,
        job_set,
        redis_ping,
        ratelimit_check,
    )
except ImportError:
    from redis_client import (
        RATE_LIMIT_RPM,
        active_audits_acquire,
        active_audits_count,
        cache_get,
        cache_key,
        close_redis,
        dedup_acquire,
        dedup_release,
        job_get,
        job_set,
        redis_ping,
        ratelimit_check,
    )

logger = logging.getLogger("aegis.backend")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s -- %(message)s",
)

# -- CONFIG ------------------------------------------------------------------
REDIS_URL    = os.getenv("REDIS_URL",    "redis://localhost:6379/0")
_API_KEY     = os.getenv("AEGIS_API_KEY", "").strip()
_CORS_ORIGINS_RAW = os.getenv("CORS_ALLOWED_ORIGINS", "")
_CORS_ORIGINS = (
    [o.strip() for o in _CORS_ORIGINS_RAW.split(",") if o.strip()]
    or ["http://localhost:3000"]
)

_BLOCKED_PATH_PREFIXES = (
    "/etc/", "/proc/", "/sys/", "/root/", "/bin/", "/sbin/", "/usr/",
    "C:\\Windows\\", "C:/Windows/",
)
_CLOUD_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "fd00:ec2::254"}


# -- ARQ POOL (shared across requests) ---------------------------------------
_arq_pool: Optional[ArqRedis] = None


def _parse_redis_settings(url: str) -> RedisSettings:
    from urllib.parse import urlparse
    p = urlparse(url)
    return RedisSettings(
        host=p.hostname or "localhost",
        port=p.port or 6379,
        database=int((p.path or "/0").lstrip("/") or 0),
        password=p.password or None,
        ssl=url.startswith("rediss://"),
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _arq_pool
    _arq_pool = await create_pool(_parse_redis_settings(REDIS_URL))
    logger.info("[Backend] ARQ pool ready.")
    yield
    if _arq_pool:
        await _arq_pool.aclose()
    await close_redis()
    logger.info("[Backend] Shutdown complete.")


app = FastAPI(
    title="Project Aegis -- Autonomous DevSecOps Engine",
    description="Multi-Agent Security Correlation, Exploitation & Remediation API",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


# -- AUTH --------------------------------------------------------------------
_bearer_scheme = HTTPBearer(auto_error=False)


def verify_api_key(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> Optional[str]:
    """
    Returns the API key string (used as rate-limit identity).
    If AEGIS_API_KEY is unset, auth is bypassed (dev mode).
    """
    if not _API_KEY:
        return "dev"
    if credentials is None or credentials.credentials != _API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials


# -- INPUT VALIDATION --------------------------------------------------------

def _validate_codebase_path(path: str) -> str:
    real = os.path.realpath(path)
    for prefix in _BLOCKED_PATH_PREFIXES:
        if real.startswith(prefix) or path.startswith(prefix):
            raise HTTPException(
                status_code=400,
                detail=f"codebase_path '{path}' points to a restricted system directory.",
            )
    return real


def _validate_target_url(url: str) -> str:
    try:
        parsed = urlparse(url.strip())
    except Exception:
        raise HTTPException(status_code=400, detail="target_url is malformed.")
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="target_url must use http or https scheme.")
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise HTTPException(status_code=400, detail="target_url has no resolvable hostname.")
    if hostname in _CLOUD_METADATA_HOSTS:
        raise HTTPException(status_code=400, detail="target_url points to a forbidden cloud metadata endpoint.")
    allow_local = os.getenv("ALLOW_LOCAL_TARGETS", "true").lower() in ("true", "1", "yes")
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_multicast or ip.is_reserved:
            raise HTTPException(status_code=400, detail="target_url IP is reserved/multicast.")
        if not allow_local and (ip.is_private or ip.is_loopback or ip.is_link_local):
            raise HTTPException(
                status_code=400,
                detail="target_url points to a private/loopback IP. Set ALLOW_LOCAL_TARGETS=true to permit.",
            )
    except ValueError:
        pass
    return url


# -- SCHEMAS -----------------------------------------------------------------

class AuditRequest(BaseModel):
    target_url: str
    codebase_path: str
    git_diff: Optional[str] = None


class JobEnqueuedResponse(BaseModel):
    job_id: str
    status: str
    queued_at: str
    poll_url: str
    message: str


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    queued_at: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None


class AuditResultResponse(BaseModel):
    job_id: str
    status: str
    verification_status: Optional[str] = None
    cleaned_errors_count: Optional[int] = None
    active_debugger_count: Optional[int] = None
    remediation_patches_count: Optional[int] = None
    deployment_status: Optional[str] = None
    deployment_url: Optional[str] = None
    summary: Optional[Dict[str, Any]] = None
    cached: bool = False


# Backward-compatible alias — existing tests and CI code import AuditResponse
AuditResponse = AuditResultResponse

# -- ENDPOINTS ---------------------------------------------------------------

@app.get("/")
async def root():
    return {
        "engine": "Project Aegis",
        "version": "2.0.0",
        "status": "Online",
        "architecture": "Async Job Queue (Redis + ARQ)",
        "interactive_docs": "/docs",
    }


@app.get("/health")
async def health():
    redis_ok = await redis_ping()
    active = await active_audits_count()
    return {
        "status": "healthy" if redis_ok else "degraded",
        "redis": "ok" if redis_ok else "unreachable",
        "active_audits": active,
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post(
    "/api/v1/run-audit",
    response_model=JobEnqueuedResponse,
    status_code=202,
    dependencies=[Depends(verify_api_key)],
)
async def run_security_audit(
    request: AuditRequest,
    api_key: Optional[str] = Depends(verify_api_key),
):
    """
    Enqueue an Aegis audit job. Returns immediately with job_id.
    Poll GET /api/v1/audit-status/{job_id} for progress.
    Fetch GET /api/v1/audit-result/{job_id} when status=DONE.

    Authentication: Bearer {AEGIS_API_KEY} (if env var is set).
    Rate limit:     AEGIS_RATE_LIMIT_RPM per minute per API key.
    """
    # -- 1. Rate limit ---------------------------------------------------
    allowed, remaining = await ratelimit_check(api_key or "dev")
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Max {RATE_LIMIT_RPM} requests/minute.",
            headers={"X-RateLimit-Remaining": "0"},
        )

    # -- 2. Input validation ---------------------------------------------
    _validate_target_url(request.target_url)
    if not os.path.exists(request.codebase_path):
        raise HTTPException(
            status_code=400,
            detail=f"codebase_path '{request.codebase_path}' does not exist.",
        )
    safe_codebase_path = _validate_codebase_path(request.codebase_path)

    safe_git_diff = request.git_diff
    if safe_git_diff and len(safe_git_diff) > 100_000:
        logger.warning("[Backend] git_diff truncated from %d to 100000 chars.", len(safe_git_diff))
        safe_git_diff = safe_git_diff[:100_000] + "\n... [TRUNCATED_BY_BACKEND_GUARD]"

    # -- 3. Cache check --------------------------------------------------
    ck = cache_key(request.target_url, safe_git_diff)
    cached = await cache_get(ck)
    if cached:
        logger.info("[Backend] Cache HIT for key %s -- returning cached result.", ck)
        job_id = "cached-" + ck[:8]
        return JobEnqueuedResponse(
            job_id=job_id,
            status="DONE",
            queued_at=datetime.utcnow().isoformat(),
            poll_url=f"/api/v1/audit-result/{job_id}",
            message="Result served from cache. Use /api/v1/audit-result/{job_id} to retrieve.",
        )

    # -- 4. Dedup check --------------------------------------------------
    job_id = str(uuid.uuid4())
    existing_job_id = await dedup_acquire(ck, job_id)
    if existing_job_id:
        logger.info("[Backend] Dedup HIT -- returning existing job %s.", existing_job_id)
        return JobEnqueuedResponse(
            job_id=existing_job_id,
            status="RUNNING",
            queued_at=datetime.utcnow().isoformat(),
            poll_url=f"/api/v1/audit-status/{existing_job_id}",
            message="Identical request already in progress. Tracking existing job.",
        )

    # -- 5. Concurrency cap ----------------------------------------------
    acquired = await active_audits_acquire()
    if not acquired:
        await dedup_release(ck)
        raise HTTPException(
            status_code=429,
            detail="Server at capacity. Retry shortly or increase AEGIS_MAX_CONCURRENT_AUDITS.",
        )

    # -- 6. Build initial pipeline state ---------------------------------
    initial_state = {
        "messages": [],
        "url": request.target_url,
        "frontend_analysis": [],
        "codebase_analysis": [],
        "active_debugger": [],
        "proposed_patch": [],
        "verification_status": "PENDING",
        "codebase_path": [safe_codebase_path],
        "git_diff": safe_git_diff,
        "cleaned_errors": [],
        "remediation_plan": [],
        "test_results": [],
        "verification_report": [],
        "deployment_status": None,
        "deployment_url": None,
        "next": "Recon_Team",
    }

    # -- 7. Persist job record + enqueue ---------------------------------
    queued_at = datetime.utcnow().isoformat()
    await job_set(job_id, {
        "status": "QUEUED",
        "queued_at": queued_at,
        "target_url": request.target_url,
        "codebase_path": safe_codebase_path,
    })

    await _arq_pool.enqueue_job(
        "run_audit_task",
        job_id,
        initial_state,
        _job_id=job_id,
    )

    logger.info("[Backend] Job %s enqueued for %s.", job_id, request.target_url)

    return JobEnqueuedResponse(
        job_id=job_id,
        status="QUEUED",
        queued_at=queued_at,
        poll_url=f"/api/v1/audit-status/{job_id}",
        message="Audit job queued. Poll /api/v1/audit-status/{job_id} for progress.",
    )


@app.get("/api/v1/audit-status/{job_id}", response_model=JobStatusResponse)
async def get_audit_status(job_id: str):
    """Poll the status of an enqueued audit job."""
    if job_id.startswith("cached-"):
        return JobStatusResponse(job_id=job_id, status="DONE")
    job = await job_get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
    return JobStatusResponse(
        job_id=job_id,
        status=job.get("status", "UNKNOWN"),
        queued_at=job.get("queued_at"),
        started_at=job.get("started_at"),
        completed_at=job.get("completed_at"),
        error=job.get("error"),
    )


@app.get("/api/v1/audit-result/{job_id}", response_model=AuditResultResponse)
async def get_audit_result(job_id: str):
    """Retrieve the completed result of an audit job."""
    # Handle cache-hit short-circuit job IDs
    if job_id.startswith("cached-"):
        ck = job_id[len("cached-"):]
        cached = await cache_get(ck)
        if cached:
            return AuditResultResponse(job_id=job_id, cached=True, **cached)
        raise HTTPException(status_code=404, detail="Cached result expired.")

    job = await job_get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")

    status = job.get("status", "UNKNOWN")
    if status == "FAILED":
        raise HTTPException(
            status_code=500,
            detail=f"Job failed: {job.get('error', 'unknown error')}",
        )
    if status not in ("DONE", "COMPLETED"):
        raise HTTPException(
            status_code=202,
            detail=f"Job not yet complete. Current status: {status}. Poll /api/v1/audit-status/{job_id}.",
        )

    result = job.get("result", {})
    if isinstance(result, str):
        import json
        result = json.loads(result)

    return AuditResultResponse(
        job_id=job_id,
        cached=False,
        **result,
    )


if __name__ == "__main__":
    uvicorn.run("aegis.api.app:app", host="0.0.0.0", port=8000, reload=False, workers=1)