"""
deploy_agent.py -- Autonomous Cloud Deployment Agent for Project Aegis.

Final LangGraph node in the pipeline. Fires ONLY when the Gatekeeper
returns READY_FOR_DEPLOYMENT. Manages the full deploy lifecycle:

  Phase 1 -- Platform Detection  (reads AEGIS_DEPLOY_PLATFORM)
  Phase 2 -- Deploy Trigger      (Vercel / Render / Railway / AWS ECS)
  Phase 3 -- Liveness Poll       (HTTP poll until 200 or timeout)
  Phase 4 -- Post-Deploy Smoke   (deterministic HTTP probes on live URL)
  Rollback -- HITL alert + DEPLOYMENT_FAILED if smoke tests fail

Security:
  - All credentials read from env vars at call-time; never stored in state.
  - Deploy hook URLs never logged, printed, or included in audit reports.
  - AWS credentials passed directly to boto3; never surface in state.
"""
import os
import asyncio
import logging
import json
from datetime import datetime
from typing import Optional, Dict, Any, Annotated, List, TypedDict
import httpx
from dotenv import load_dotenv
from langgraph.graph.message import add_messages

try:
    from aegis.core.state import Selector
    from aegis.notifications.alerts import dispatch_hitl_alert
except ImportError:
    from alerts import dispatch_hitl_alert

load_dotenv()

logger = logging.getLogger("aegis.agents.deploy.deployer")
logging.basicConfig(level=logging.INFO)


# -- SHARED STATE ---------------------------------------------------------
class Selector(TypedDict):
    messages: Annotated[List, add_messages]
    url: str
    frontend_analysis: List[str]
    codebase_analysis: List[str]
    active_debugger: List[str]
    proposed_patch: List[str]
    verification_status: str
    codebase_path: List[str]
    git_diff: Optional[str]
    cleaned_errors: List[str]
    remediation_plan: List[str]
    test_results: List[str]
    verification_report: List[str]
    next: str
    # New fields added by this agent
    deployment_status: Optional[str]   # DEPLOYED_AND_LIVE | DEPLOYMENT_FAILED | SKIPPED
    deployment_url: Optional[str]


SUPPORTED_PLATFORMS = {"vercel", "render", "railway", "aws_ecs"}


# -- PHASE 2: PLATFORM-SPECIFIC DEPLOY TRIGGERS ---------------------------

async def _trigger_vercel() -> Dict[str, Any]:
    """Trigger Vercel deployment via Deploy Hook URL (URL is the auth secret)."""
    hook_url = os.getenv("VERCEL_DEPLOY_HOOK_URL", "").strip()
    if not hook_url:
        raise ValueError("VERCEL_DEPLOY_HOOK_URL is not set in environment.")
    async with httpx.AsyncClient(timeout=15.0) as client:
        res = await client.post(hook_url)
    if res.status_code not in (200, 201):
        raise RuntimeError(f"Vercel deploy hook returned HTTP {res.status_code}: {res.text[:200]}")
    logger.info("[Deploy Agent] Vercel deployment triggered successfully.")
    return {"platform": "vercel", "triggered_at": datetime.utcnow().isoformat()}


async def _trigger_render() -> Dict[str, Any]:
    """Trigger Render service redeploy via REST API (Bearer RENDER_API_KEY)."""
    api_key = os.getenv("RENDER_API_KEY", "").strip()
    service_id = os.getenv("RENDER_SERVICE_ID", "").strip()
    if not api_key or not service_id:
        raise ValueError("RENDER_API_KEY and RENDER_SERVICE_ID must be set.")
    url = f"https://api.render.com/v1/services/{service_id}/deploys"
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=15.0) as client:
        res = await client.post(url, headers=headers, json={"clearCache": "do_not_clear"})
    if res.status_code not in (200, 201):
        raise RuntimeError(f"Render API returned HTTP {res.status_code}: {res.text[:200]}")
    data = res.json()
    deploy_id = data.get("id", "unknown")
    logger.info("[Deploy Agent] Render deployment triggered. Deploy ID: %s", deploy_id)
    return {"platform": "render", "deploy_id": deploy_id, "triggered_at": datetime.utcnow().isoformat()}


async def _trigger_railway() -> Dict[str, Any]:
    """Trigger Railway redeployment via GraphQL API (Bearer RAILWAY_API_TOKEN)."""
    api_token = os.getenv("RAILWAY_API_TOKEN", "").strip()
    deployment_id = os.getenv("RAILWAY_DEPLOYMENT_ID", "").strip()
    if not api_token or not deployment_id:
        raise ValueError("RAILWAY_API_TOKEN and RAILWAY_DEPLOYMENT_ID must be set.")
    endpoint = "https://backboard.railway.app/graphql/v2"
    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
    mutation = {
        "query": "mutation deploymentRedeploy($id: String!) { deploymentRedeploy(id: $id) { id status } }",
        "variables": {"id": deployment_id},
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        res = await client.post(endpoint, headers=headers, json=mutation)
    if res.status_code != 200:
        raise RuntimeError(f"Railway GraphQL returned HTTP {res.status_code}: {res.text[:200]}")
    data = res.json()
    if "errors" in data:
        raise RuntimeError(f"Railway GraphQL error: {data['errors']}")
    new_deploy = data.get("data", {}).get("deploymentRedeploy", {})
    logger.info("[Deploy Agent] Railway redeployment triggered. Status: %s", new_deploy.get("status"))
    return {"platform": "railway", "deployment": new_deploy, "triggered_at": datetime.utcnow().isoformat()}


async def _trigger_aws_ecs() -> Dict[str, Any]:
    """Force a new ECS service deployment via boto3 (standard AWS credential chain)."""
    try:
        import boto3
    except ImportError:
        raise RuntimeError("boto3 is not installed. Run: pip install boto3")
    cluster = os.getenv("AWS_ECS_CLUSTER", "").strip()
    service = os.getenv("AWS_ECS_SERVICE", "").strip()
    region = os.getenv("AWS_DEFAULT_REGION", os.getenv("AWS_REGION", "us-east-1")).strip()
    if not cluster or not service:
        raise ValueError("AWS_ECS_CLUSTER and AWS_ECS_SERVICE must be set.")

    def _boto_update():
        client = boto3.client("ecs", region_name=region)
        return client.update_service(cluster=cluster, service=service, forceNewDeployment=True)

    response = await asyncio.to_thread(_boto_update)
    svc_status = response.get("service", {}).get("status", "unknown")
    deploy_count = len(response.get("service", {}).get("deployments", []))
    logger.info(
        "[Deploy Agent] AWS ECS forceNewDeployment triggered. Service: %s | Deployments: %d",
        service, deploy_count
    )
    return {
        "platform": "aws_ecs",
        "cluster": cluster,
        "service": service,
        "service_status": svc_status,
        "triggered_at": datetime.utcnow().isoformat(),
    }


# -- PHASE 3: LIVENESS POLL -----------------------------------------------

async def _poll_until_live(target_url: str, timeout_s: int = 300, interval_s: int = 10) -> bool:
    """Poll target_url until HTTP <500 or timeout. Exponential backoff, capped at 30s.

    Security: follow_redirects=False prevents a compromised deployment endpoint
    from redirecting liveness probes to cloud metadata IPs (e.g. 169.254.169.254).
    HTTP 3xx responses are treated as "alive" (< 500) without following the chain.
    """
    deadline = asyncio.get_event_loop().time() + timeout_s
    attempt = 0
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
        while asyncio.get_event_loop().time() < deadline:
            attempt += 1
            try:
                res = await client.get(target_url)
                if res.status_code < 500:
                    logger.info("[Deploy Agent] Liveness PASSED (HTTP %d) after %d attempt(s).", res.status_code, attempt)
                    return True
                logger.info("[Deploy Agent] Liveness attempt %d: HTTP %d -- still deploying...", attempt, res.status_code)
            except Exception as e:
                logger.info("[Deploy Agent] Liveness attempt %d: connection error -- %s", attempt, e)
            sleep_s = min(interval_s * (2 ** min(attempt - 1, 3)), 30)
            await asyncio.sleep(sleep_s)
    logger.warning("[Deploy Agent] Liveness poll timed out after %ds.", timeout_s)
    return False


# -- PHASE 4: POST-DEPLOY SMOKE TESTS -------------------------------------

async def _run_post_deploy_smoke(target_url: str) -> Dict[str, Any]:
    """Deterministic HTTP probes on live deployment. Fail if any return 5xx.

    Security: follow_redirects=False prevents redirect-based SSRF.
    HTTP 3xx is treated as passed (not a 5xx) and not followed further.
    """
    results = []
    probes = [
        (target_url, "Root endpoint reachable", 200),
        (f"{target_url.rstrip('/')}/health", "Health endpoint", None),
        (f"{target_url.rstrip('/')}/api/v1/", "API v1 prefix", None),
    ]
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        for url, label, expected_code in probes:
            try:
                res = await client.get(url)
                passed = res.status_code < 500
                if expected_code is not None:
                    passed = (res.status_code == expected_code)
                results.append({"label": label, "url": url, "http_status": res.status_code, "passed": passed})
                logger.info("[Smoke Test] %-40s HTTP %d  %s", label, res.status_code, "PASS" if passed else "FAIL")
            except Exception as e:
                results.append({"label": label, "url": url, "error": str(e), "passed": False})
                logger.warning("[Smoke Test] %s -- ERROR: %s", label, e)
    return {"passed": all(r["passed"] for r in results), "probes": results}


# -- MAIN DEPLOY AGENT NODE -----------------------------------------------

async def deploy_agent(state: Selector) -> dict:
    """
    LangGraph node: Deploy trigger + liveness poll + smoke test gate.
    Fires ONLY when verification_status == READY_FOR_DEPLOYMENT.
    Skips gracefully if AEGIS_DEPLOY_PLATFORM is not configured (backward compatible).
    """
    v_status = state.get("verification_status", "")
    target_url = state.get("url", "")
    codebase_paths = state.get("codebase_path", [])
    repo_path = codebase_paths[0] if codebase_paths else "."

    # Gate: Only fire on full security clearance
    if v_status != "READY_FOR_DEPLOYMENT":
        logger.info("[Deploy Agent] Skipping -- status is '%s', not READY_FOR_DEPLOYMENT.", v_status)
        return {
            "deployment_status": "SKIPPED",
            "deployment_url": None,
            "messages": [f"[Deploy Agent] Skipped -- pipeline status is '{v_status}'."],
        }

    platform = os.getenv("AEGIS_DEPLOY_PLATFORM", "").strip().lower()

    # Gate: No platform configured -- graceful skip (zero breakage for existing installs)
    if not platform:
        logger.info("[Deploy Agent] AEGIS_DEPLOY_PLATFORM not set. Deployment skipped.")
        return {
            "deployment_status": "SKIPPED",
            "deployment_url": None,
            "messages": [
                "[Deploy Agent] No deployment platform configured. "
                "Set AEGIS_DEPLOY_PLATFORM=vercel|render|railway|aws_ecs to enable."
            ],
        }

    if platform not in SUPPORTED_PLATFORMS:
        logger.warning("[Deploy Agent] Unknown platform '%s'. Supported: %s", platform, SUPPORTED_PLATFORMS)
        return {
            "deployment_status": "SKIPPED",
            "deployment_url": None,
            "messages": [f"[Deploy Agent] Unknown platform '{platform}'. Skipped."],
        }

    logger.info("[Deploy Agent] Security gate CLEARED. Triggering '%s' deploy for: %s", platform, target_url)

    # Phase 2: Trigger deployment
    trigger_info: Dict[str, Any] = {}
    try:
        if platform == "vercel":
            trigger_info = await _trigger_vercel()
        elif platform == "render":
            trigger_info = await _trigger_render()
        elif platform == "railway":
            trigger_info = await _trigger_railway()
        elif platform == "aws_ecs":
            trigger_info = await _trigger_aws_ecs()
    except Exception as e:
        logger.error("[Deploy Agent] Trigger FAILED: %s", e)
        await dispatch_hitl_alert(
            title=f"Deployment Trigger Failed [{platform.upper()}]",
            summary=f"Aegis attempted deployment on '{platform}' after security clearance, but trigger failed.",
            severity="CRITICAL",
            details={"platform": platform, "error": str(e), "target_url": target_url},
            codebase_path=repo_path,
        )
        return {
            "deployment_status": "DEPLOYMENT_FAILED",
            "deployment_url": None,
            "messages": [f"[Deploy Agent] Trigger failed on '{platform}': {e}"],
        }

    # Phase 3: Liveness poll
    if target_url:
        is_live = await _poll_until_live(target_url, timeout_s=300, interval_s=10)
        if not is_live:
            await dispatch_hitl_alert(
                title=f"Deployment Liveness Timeout [{platform.upper()}]",
                summary=f"Aegis triggered '{platform}' deployment but target URL did not respond within 5 minutes.",
                severity="HIGH",
                details={"platform": platform, "target_url": target_url, **trigger_info},
                codebase_path=repo_path,
            )
            return {
                "deployment_status": "DEPLOYMENT_FAILED",
                "deployment_url": target_url,
                "messages": [f"[Deploy Agent] Liveness timeout on '{platform}'. HITL alert dispatched."],
            }
    else:
        is_live = True

    # Phase 4: Post-deploy smoke tests
    smoke_result = {"passed": True, "probes": []}
    if target_url and is_live:
        smoke_result = await _run_post_deploy_smoke(target_url)

    if not smoke_result["passed"]:
        failed_probes = [p for p in smoke_result["probes"] if not p.get("passed")]
        await dispatch_hitl_alert(
            title=f"Post-Deploy Smoke Tests FAILED [{platform.upper()}]",
            summary=(
                f"Deployment on '{platform}' completed but {len(failed_probes)} smoke probe(s) failed. "
                "The live deployment may be broken -- manual rollback may be needed."
            ),
            severity="CRITICAL",
            details={
                "platform": platform,
                "target_url": target_url,
                "failed_probes": str([p.get("label") for p in failed_probes]),
            },
            codebase_path=repo_path,
        )
        return {
            "deployment_status": "DEPLOYMENT_FAILED",
            "deployment_url": target_url,
            "messages": [f"[Deploy Agent] Smoke tests FAILED on '{platform}'. HITL alert dispatched."],
        }

    # All phases passed
    logger.info("[Deploy Agent] Deployment COMPLETE and VERIFIED LIVE on '%s' at %s", platform, target_url)
    await dispatch_hitl_alert(
        title=f"Deployment Successful [{platform.upper()}]",
        summary=(
            f"Aegis autonomously deployed and verified the security-hardened build on '{platform}'. "
            f"All smoke tests passed. Live at: {target_url}"
        ),
        severity="LOW",
        details={
            "platform": platform,
            "target_url": target_url,
            "smoke_tests_passed": len(smoke_result["probes"]),
            "triggered_at": trigger_info.get("triggered_at", "N/A"),
        },
        codebase_path=repo_path,
    )
    return {
        "deployment_status": "DEPLOYED_AND_LIVE",
        "deployment_url": target_url,
        "messages": [f"[Deploy Agent] Deployed on '{platform}'. Live at: {target_url}. All smoke tests passed."],
    }
