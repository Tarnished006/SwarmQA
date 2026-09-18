"""
worker.py -- Project Aegis ARQ Background Worker
=================================================
Runs the multi-agent LangGraph pipeline as background tasks dequeued from Redis.

Start with:
    python worker.py
or via Docker:
    command: python worker.py

Environment variables:
  REDIS_URL             -- Redis connection string
  AEGIS_JOB_TIMEOUT_S   -- Max seconds a single job may run (default: 1800)
  AEGIS_WORKER_CONCURRENCY -- Max parallel jobs per worker (default: 3)
"""
from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, Dict

from arq import cron
from arq.connections import RedisSettings
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("aegis.worker")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s -- %(message)s",
)

REDIS_URL          = os.getenv("REDIS_URL", "redis://localhost:6379/0")
JOB_TIMEOUT_S      = int(os.getenv("AEGIS_JOB_TIMEOUT_S",     "1800"))
WORKER_CONCURRENCY = int(os.getenv("AEGIS_WORKER_CONCURRENCY", "3"))


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


async def run_audit_task(ctx: dict, job_id: str, initial_state: dict) -> dict:
    """
    ARQ task -- executes the full LangGraph multi-agent pipeline.

    Steps:
      1. Mark job as RUNNING in Redis
      2. Invoke aegis_app.ainvoke(initial_state)
      3. Write result to Redis job hash (status=DONE)
      4. Write result to Redis cache
      5. On exception: mark FAILED
      6. Release concurrency slot
    """
    from redis_client import (
        active_audits_release,
        cache_key,
        cache_set,
        dedup_release,
        job_update,
    )
    from agent import aegis_app

    logger.info("[Worker] Starting job %s", job_id)

    await job_update(
        job_id,
        status="RUNNING",
        started_at=datetime.utcnow().isoformat(),
    )

    try:
        final_state = await aegis_app.ainvoke(initial_state)

        result = {
            "status": "COMPLETED",
            "verification_status": final_state.get("verification_status", "UNKNOWN"),
            "cleaned_errors_count": len(final_state.get("cleaned_errors", [])),
            "active_debugger_count": len(final_state.get("active_debugger", [])),
            "remediation_patches_count": len(final_state.get("remediation_plan", [])),
            "deployment_status": final_state.get("deployment_status"),
            "deployment_url": final_state.get("deployment_url"),
            "summary": {
                "verification_report": final_state.get("verification_report", []),
                "remediation_plan": final_state.get("remediation_plan", []),
                "active_debugger": final_state.get("active_debugger", []),
                "deployment_status": final_state.get("deployment_status"),
                "deployment_url": final_state.get("deployment_url"),
            },
        }

        await job_update(
            job_id,
            status="DONE",
            completed_at=datetime.utcnow().isoformat(),
            result=result,
        )

        ck = cache_key(initial_state.get("url", ""), initial_state.get("git_diff"))
        await cache_set(ck, result)
        logger.info("[Worker] Job %s DONE. Cached as %s.", job_id, ck)
        return result

    except Exception as exc:
        logger.error("[Worker] Job %s FAILED: %s", job_id, exc, exc_info=True)
        await job_update(
            job_id,
            status="FAILED",
            error=str(exc),
            completed_at=datetime.utcnow().isoformat(),
        )
        return {"status": "FAILED", "error": str(exc)}

    finally:
        await active_audits_release()
        ck = cache_key(initial_state.get("url", ""), initial_state.get("git_diff"))
        await dedup_release(ck)


async def cleanup_stale_jobs(ctx: dict) -> None:
    """Hourly cron: mark RUNNING jobs that exceeded JOB_TIMEOUT_S as FAILED."""
    from redis_client import get_redis, active_audits_release
    import time

    r = get_redis()
    async for key in r.scan_iter(match="aegis:job:*", count=100):
        try:
            job = await r.hgetall(key)
            if job.get("status") != "RUNNING":
                continue
            started_at = job.get("started_at", "")
            if not started_at:
                continue
            dt = datetime.fromisoformat(started_at)
            age_s = (datetime.utcnow() - dt).total_seconds()
            if age_s > JOB_TIMEOUT_S:
                job_id = key.split(":")[-1]
                logger.warning("[Worker:cron] Job %s stale (%.0fs) -- marking FAILED.", job_id, age_s)
                await r.hset(key, mapping={
                    "status": "FAILED",
                    "error": f"Job exceeded timeout of {JOB_TIMEOUT_S}s and was marked stale.",
                    "completed_at": datetime.utcnow().isoformat(),
                })
                await active_audits_release()
        except Exception as e:
            logger.debug("[Worker:cron] Error checking %s: %s", key, e)


async def startup(ctx: dict) -> None:
    logger.info("[Worker] Startup. Redis: %s", REDIS_URL.split("@")[-1])


async def shutdown(ctx: dict) -> None:
    from redis_client import close_redis
    await close_redis()
    logger.info("[Worker] Shutdown complete.")


class WorkerSettings:
    functions   = [run_audit_task]
    cron_jobs   = [cron(cleanup_stale_jobs, hour={*range(24)}, minute=0)]
    on_startup  = startup
    on_shutdown = shutdown
    redis_settings = _parse_redis_settings(REDIS_URL)
    max_jobs       = WORKER_CONCURRENCY
    job_timeout    = JOB_TIMEOUT_S
    keep_result    = 3600


if __name__ == "__main__":
    from arq import run_worker
    run_worker(WorkerSettings)