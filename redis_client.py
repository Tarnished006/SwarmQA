"""
src/aegis/core/redis.py — Project Aegis Shared Redis Layer.
Provides a shared async Redis connection pool, rate limiting, caching, and dedup.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Optional, Tuple

import redis.asyncio as aioredis
from redis.asyncio import Redis
from redis.exceptions import RedisError

from aegis.core.config import settings

logger = logging.getLogger("aegis.redis")

REDIS_URL        = settings.REDIS_URL
JOB_TTL          = 3600
CACHE_TTL        = settings.AEGIS_CACHE_TTL
DEDUP_TTL        = 300
RATE_LIMIT_RPM   = settings.AEGIS_RATE_LIMIT_RPM
ACTIVE_AUDIT_CAP = settings.AEGIS_MAX_CONCURRENT_AUDITS

_KEY_JOB       = "aegis:job:{}"
_KEY_CACHE     = "aegis:cache:{}"
_KEY_DEDUP     = "aegis:dedup:{}"
_KEY_RATELIMIT = "aegis:ratelimit:{}:{}"
_KEY_ACTIVE    = "aegis:active_audits"

_redis_pool: Optional[Redis] = None


def get_redis() -> Redis:
    """Return (and lazily create) the shared async Redis connection pool."""
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = aioredis.from_url(
            REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            max_connections=20,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
        )
        logger.info("[Redis] Pool initialised -> %s", REDIS_URL.split("@")[-1])
    return _redis_pool


async def close_redis() -> None:
    """Gracefully close the connection pool."""
    global _redis_pool
    if _redis_pool:
        await _redis_pool.aclose()
        _redis_pool = None
        logger.info("[Redis] Pool closed.")


async def redis_ping() -> bool:
    """Health check -- returns True if Redis is reachable."""
    try:
        return await get_redis().ping()
    except RedisError:
        return False


# -- JOB STATE ---------------------------------------------------------------

async def job_set(job_id: str, data: dict, ttl: int = JOB_TTL) -> None:
    """Persist job metadata as a Redis hash with TTL."""
    r = get_redis()
    key = _KEY_JOB.format(job_id)
    pipe = r.pipeline()
    pipe.hset(key, mapping={
        k: json.dumps(v) if not isinstance(v, str) else v
        for k, v in data.items()
    })
    pipe.expire(key, ttl)
    await pipe.execute()


async def job_get(job_id: str) -> Optional[dict]:
    """Fetch job metadata dict, or None if not found."""
    r = get_redis()
    raw = await r.hgetall(_KEY_JOB.format(job_id))
    if not raw:
        return None
    result = {}
    for k, v in raw.items():
        try:
            result[k] = json.loads(v)
        except (json.JSONDecodeError, TypeError):
            result[k] = v
    return result


async def job_update(job_id: str, **fields) -> None:
    """Atomically update one or more fields on a job hash."""
    r = get_redis()
    key = _KEY_JOB.format(job_id)
    mapping = {
        k: json.dumps(v) if not isinstance(v, str) else v
        for k, v in fields.items()
    }
    await r.hset(key, mapping=mapping)


# -- RESULT CACHE ------------------------------------------------------------

def cache_key(target_url: str, git_diff: Optional[str]) -> str:
    """Stable SHA-256 cache key from target_url + git_diff sample."""
    diff_sample = (git_diff or "")[:1024]
    raw = target_url.strip().lower() + "||" + diff_sample
    return hashlib.sha256(raw.encode()).hexdigest()[:40]


async def cache_get(key: str) -> Optional[dict]:
    """Return cached result dict or None."""
    raw = await get_redis().get(_KEY_CACHE.format(key))
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


async def cache_set(key: str, value: dict, ttl: int = CACHE_TTL) -> None:
    """Store result dict in cache with TTL."""
    await get_redis().setex(_KEY_CACHE.format(key), ttl, json.dumps(value))


# -- REQUEST DEDUPLICATION ---------------------------------------------------

async def dedup_acquire(key: str, job_id: str, ttl: int = DEDUP_TTL) -> Optional[str]:
    """
    SET NX -- atomically claim the dedup slot.
    Returns None if this caller won. Returns existing job_id if duplicate.
    """
    r = get_redis()
    rkey = _KEY_DEDUP.format(key)
    set_result = await r.set(rkey, job_id, nx=True, ex=ttl)
    if set_result:
        return None
    return await r.get(rkey)


async def dedup_release(key: str) -> None:
    """Release a dedup slot on job completion or failure."""
    await get_redis().delete(_KEY_DEDUP.format(key))


# -- SLIDING WINDOW RATE LIMITER ---------------------------------------------

async def ratelimit_check(
    api_key: str,
    max_rpm: int = RATE_LIMIT_RPM,
) -> Tuple[bool, int]:
    """
    Per-API-key tumbling 1-minute window rate limiter.
    Returns: (allowed: bool, remaining: int)
    """
    r = get_redis()
    bucket = int(time.time() // 60)
    rkey = _KEY_RATELIMIT.format(api_key or "anonymous", bucket)
    pipe = r.pipeline()
    pipe.incr(rkey)
    pipe.expire(rkey, 60)
    results = await pipe.execute()
    current_count: int = results[0]
    remaining = max(0, max_rpm - current_count)
    return current_count <= max_rpm, remaining


# -- CONCURRENCY GUARD (Redis atomic counter) --------------------------------

async def active_audits_acquire() -> bool:
    """
    Atomically increment global active audit counter.
    Returns True if slot acquired, False if at capacity.
    """
    r = get_redis()
    new_count = await r.incr(_KEY_ACTIVE)
    if new_count > ACTIVE_AUDIT_CAP:
        await r.decr(_KEY_ACTIVE)
        return False
    await r.expire(_KEY_ACTIVE, 7200)
    return True


async def active_audits_release() -> None:
    """Decrement global active audit counter. Always call in finally."""
    r = get_redis()
    count = await r.decr(_KEY_ACTIVE)
    if count < 0:
        await r.set(_KEY_ACTIVE, 0)


async def active_audits_count() -> int:
    """Return current active audit count."""
    val = await get_redis().get(_KEY_ACTIVE)
    return int(val or 0)
