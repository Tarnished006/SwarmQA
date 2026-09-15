import asyncio
import io
import json
import logging
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Dict, List, Literal, Optional, Annotated, TypedDict
from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field

from alerts import dispatch_hitl_alert

load_dotenv()

logger = logging.getLogger("aegis.checking_agent")
logging.basicConfig(level=logging.INFO)


# ── SHARED STATE ──────────────────────────────────────────────
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


# ── DOCKER UTILITY & CLEAN ROOM SANDBOX ───────────────────────
def is_docker_running() -> bool:
    try:
        import docker
        client = docker.from_env()
        client.ping()
        return True
    except Exception:
        return False


class CleanRoomSandbox:
    """Hardened Docker runner for regression testing."""
    IMAGE = os.getenv("SANDBOX_DOCKER_IMAGE", "swarm:latest")

    def __init__(self, network_name: str = "checking_agent_net"):
        import docker
        self.client = docker.from_env()
        self.network_name = network_name
        self.container = None
        self.network = None

    def start(self):
        networks = self.client.networks.list(names=[self.network_name])
        if networks:
            self.network = networks[0]
        else:
            self.network = self.client.networks.create(
                self.network_name, driver="bridge", internal=True
            )

        self.container = self.client.containers.run(
            image=self.IMAGE,
            command="tail -f /dev/null",
            detach=True,
            network=self.network_name,
            user="1000:1000",
            read_only=False,
            mem_limit="512m",
            memswap_limit="512m",
            nano_cpus=1_000_000_000,
            pids_limit=100,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            tmpfs={"/tmp": "size=100M,exec,uid=1000,gid=1000"},
        )

    def upload_workspace(self, workspace_dir: str):
        tarstream = io.BytesIO()
        with tarfile.open(fileobj=tarstream, mode="w") as tar:
            for root, _, files in os.walk(workspace_dir):
                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, workspace_dir)
                    tar.add(full_path, arcname=rel_path)
        tarstream.seek(0)
        self.container.exec_run(["mkdir", "-p", "/tmp/workspace"])
        self.container.put_archive("/tmp/workspace", tarstream)

    async def execute_test(self, test_filename: str, timeout_s: int = 20) -> Dict[str, Any]:
        def _exec():
            return self.container.exec_run(
                ["timeout", str(timeout_s), "pytest", f"/tmp/workspace/{test_filename}", "-v"],
                demux=True,
                workdir="/tmp/workspace"
            )

        try:
            exit_code, (stdout, stderr) = await asyncio.wait_for(
                asyncio.to_thread(_exec), timeout=timeout_s + 5
            )
            return {
                "exit_code": exit_code,
                "stdout": (stdout or b"").decode("utf-8", errors="ignore"),
                "stderr": (stderr or b"").decode("utf-8", errors="ignore")
            }
        except asyncio.TimeoutError:
            return {"exit_code": -1, "stdout": "", "stderr": "Error: Test timed out."}

    def stop(self):
        if self.container:
            try:
                self.container.stop(timeout=2)
                self.container.remove(force=True)
            except Exception:
                pass
            self.container = None


async def execute_local_test(workspace_dir: str, test_filename: str, timeout_s: int = 20) -> Dict[str, Any]:
    """Fallback local test runner when Docker is offline."""
    def _run():
        return subprocess.run(
            [sys.executable, "-m", "pytest", test_filename, "-v"],
            cwd=workspace_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
        )

    try:
        res = await asyncio.wait_for(asyncio.to_thread(_run), timeout=timeout_s + 3)
        return {
            "exit_code": res.returncode,
            "stdout": res.stdout,
            "stderr": res.stderr,
        }
    except (asyncio.TimeoutError, subprocess.TimeoutExpired):
        return {"exit_code": -1, "stdout": "", "stderr": "Error: Test timed out."}
    except Exception as e:
        return {"exit_code": -1, "stdout": "", "stderr": f"Execution Error: {str(e)}"}


# ── RESILIENT PATCH APPLICATION HELPER ────────────────────────
def apply_patch_to_file(target_file: str, original_code: str, patched_code: str) -> bool:
    """
    Applies a code patch with CRLF / LF line-ending resilience.
    Returns True if successfully replaced, False otherwise.
    """
    if not os.path.exists(target_file) or not original_code:
        return False

    with open(target_file, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    # 1. Direct match
    if original_code in content:
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(content.replace(original_code, patched_code, 1))
        return True

    # 2. Normalized line-ending match (CRLF <-> LF)
    norm_content = content.replace("\r\n", "\n")
    norm_original = original_code.replace("\r\n", "\n")
    norm_patched = patched_code.replace("\r\n", "\n")

    if norm_original in norm_content:
        updated = norm_content.replace(norm_original, norm_patched, 1)
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(updated)
        return True

    return False


# ── NODE 1: SANDBOX EXECUTION NODE ────────────────────────────
async def sandbox_execution_node(state: Selector) -> dict:
    raw_path = state.get("codebase_path", [])
    source_codebase = raw_path[0] if raw_path else ""
    remediation_raw = state.get("remediation_plan", [])

    if not source_codebase or not os.path.exists(source_codebase):
        return {"test_results": [json.dumps({"error": "Invalid codebase path provided."})]}

    if not remediation_raw:
        logger.info("[Sandbox_Execution] No remediation plan to test. Fast-pass exit ($0 tokens).")
        return {"test_results": []}

    logger.info("[Sandbox_Execution] Setting up clean-room workspace for %d patches ...", len(remediation_raw))
    execution_logs: List[str] = []

    patches = []
    for plan_str in remediation_raw:
        try:
            patches.append(json.loads(plan_str))
        except Exception:
            pass

    with tempfile.TemporaryDirectory(prefix="aegis_cleanroom_") as temp_workspace:
        # Copy codebase to isolated temp workspace
        if os.path.isdir(source_codebase):
            shutil.copytree(source_codebase, temp_workspace, dirs_exist_ok=True)
        else:
            shutil.copy2(source_codebase, temp_workspace)

        test_files_created = []
        for patch in patches:
            patch_id = patch.get("id", "UNKNOWN")
            file_rel_path = patch.get("file_path", "")
            original_code = patch.get("original_code_snippet", "")
            patched_code = patch.get("patched_code_snippet", "")
            regression_test = patch.get("regression_test", "")

            target_file_full = os.path.join(temp_workspace, file_rel_path)
            applied = apply_patch_to_file(target_file_full, original_code, patched_code)
            if not applied:
                logger.warning("[Sandbox_Execution] Patch %s could not be matched in %s", patch_id, file_rel_path)

            # Write regression test
            if regression_test:
                test_filename = f"test_aegis_{patch_id}.py"
                test_file_full = os.path.join(temp_workspace, test_filename)
                with open(test_file_full, "w", encoding="utf-8") as f:
                    f.write(regression_test)
                test_files_created.append((patch_id, test_filename))

        # Execute tests via Docker or local fallback
        use_docker = is_docker_running()
        if use_docker:
            logger.info("[Sandbox_Execution] Docker detected. Running in Docker CleanRoomSandbox.")
            sandbox = CleanRoomSandbox()
            try:
                sandbox.start()
                sandbox.upload_workspace(temp_workspace)
                for patch_id, test_filename in test_files_created:
                    res = await sandbox.execute_test(test_filename)
                    execution_logs.append(json.dumps({
                        "patch_id": patch_id,
                        "test_file": test_filename,
                        "exit_code": res["exit_code"],
                        "status": "PASSED" if res["exit_code"] == 0 else "FAILED",
                        "stdout": res["stdout"],
                        "stderr": res["stderr"]
                    }))
            finally:
                sandbox.stop()
        else:
            logger.info("[Sandbox_Execution] Docker unavailable. Running tests via local subprocess runner.")
            for patch_id, test_filename in test_files_created:
                res = await execute_local_test(temp_workspace, test_filename)
                execution_logs.append(json.dumps({
                    "patch_id": patch_id,
                    "test_file": test_filename,
                    "exit_code": res["exit_code"],
                    "status": "PASSED" if res["exit_code"] == 0 else "FAILED",
                    "stdout": res["stdout"],
                    "stderr": res["stderr"]
                }))

    return {"test_results": execution_logs}


# ── NODE 2: CHECKER / GATEKEEPER AGENT NODE ───────────────────
class VerificationSummaryCounts(BaseModel):
    total_evaluated: int
    success_secure: int
    failed_vulnerable: int
    failed_regression: int
    manual_review: int


class VerificationResult(BaseModel):
    id: str = Field(description="The ID of the exploit/patch being evaluated")
    verdict: Literal[
        "SUCCESS_SECURE", 
        "FAILED_STILL_VULNERABLE", 
        "FAILED_BUSINESS_LOGIC_REGRESSION", 
        "MANUAL_REVIEW_REQUIRED"
    ]
    verdict_confidence: Literal["HIGH", "MEDIUM", "LOW"]
    chain_completeness_check: str
    bypass_analysis_notes: str
    feedback_for_patcher: Optional[str] = None
    retry_limit_exceeded: bool = False


class VerificationReport(BaseModel):
    overall_status: Literal["READY_FOR_DEPLOYMENT", "BLOCKED", "PARTIAL_WITH_REVIEW", "NO_EXPLOITS_CONFIRMED"]
    blocking_findings: List[str] = Field(default_factory=list)
    manual_review_findings: List[str] = Field(default_factory=list)
    summary_counts: VerificationSummaryCounts
    results: List[VerificationResult] = Field(default_factory=list)


def get_checker_llm() -> ChatOpenAI:
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("GROQ_API_KEY")
    base_url = os.getenv("OPENAI_BASE_URL") or os.getenv("OPENAI_API_BASE")
    model_name = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    if not api_key:
        if base_url and ("localhost" in base_url or "127.0.0.1" in base_url):
            api_key = "ollama"
        else:
            raise ValueError("Missing LLM API Key! Please set OPENAI_API_KEY in your .env file.")

    return ChatOpenAI(
        model=model_name,
        api_key=api_key,
        base_url=base_url,
        temperature=0.0,
        max_tokens=3000,
    )


async def checker_agent(state: Selector) -> dict:
    active_debugger = state.get("active_debugger", [])
    remediation_plan = state.get("remediation_plan", [])
    test_results = state.get("test_results", [])
    codebase_paths = state.get("codebase_path", [])
    repo_path = codebase_paths[0] if codebase_paths else "."

    # Fast-pass: No exploits or patches evaluated
    if not active_debugger and not remediation_plan:
        logger.info("[Checker Agent] No exploits or patches to evaluate. Pipeline clear.")
        return {
            "verification_report": [],
            "verification_status": "READY_FOR_DEPLOYMENT",
            "messages": ["[Checker Agent] Fast-pass: Clean bill of health. No exploits confirmed."]
        }

    system = """You are an Autonomous DevSecOps Verification Engine — the Lead Security Auditor
and QA Gatekeeper. Nothing ships past you without an explicit verdict.
Your objective: ingest the original exploits, patches applied, and regression test results,
and definitively determine whether each vulnerability is neutralized without breaking business logic.

EVALUATION CRITERIA:
1. EXPLOIT NEUTRALIZATION: Does the patch actually neutralize the root cause?
2. BUSINESS REGRESSION: Did the patch break valid input or existing API contracts?
3. BYPASS ANALYSIS: Could an attacker trivially evade this fix with alternate syntax?
4. HUMAN REVIEW: If requires_human_review was flagged, verdict must be MANUAL_REVIEW_REQUIRED.

OVERALL STATUS RULES:
- READY_FOR_DEPLOYMENT: All findings are SUCCESS_SECURE.
- BLOCKED: Any finding is FAILED_STILL_VULNERABLE or FAILED_BUSINESS_LOGIC_REGRESSION.
- PARTIAL_WITH_REVIEW: Findings are either SUCCESS_SECURE or MANUAL_REVIEW_REQUIRED.

Output ONLY valid JSON matching the VerificationReport schema."""

    human = """<VERIFIED_EXPLOITS>
{verified_exploits}
</VERIFIED_EXPLOITS>

<REMEDIATION_PLAN>
{remediation_plan}
</REMEDIATION_PLAN>

<TEST_EXECUTION_RESULTS>
{test_execution_results}
</TEST_EXECUTION_RESULTS>

Evaluate the effectiveness and safety of the applied patches. Return ONLY the structured VerificationReport JSON."""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system),
        ("human", human)
    ])

    try:
        llm = get_checker_llm()
        structured_llm = llm.with_structured_output(VerificationReport)
        chain = prompt | structured_llm

        report: VerificationReport = await chain.ainvoke({
            "verified_exploits": "\n".join(active_debugger),
            "remediation_plan": "\n".join(remediation_plan),
            "test_execution_results": "\n".join(test_results),
        })

        logger.info("[Checker Agent] Verification completed. Overall status: %s", report.overall_status)

        # Autonomous HITL Alert if blocked or requires human review
        if report.overall_status in ("BLOCKED", "PARTIAL_WITH_REVIEW") or report.manual_review_findings:
            await dispatch_hitl_alert(
                title=f"Deployment Gate: {report.overall_status}",
                summary=(
                    f"Aegis Gatekeeper status is '{report.overall_status}'. "
                    f"Blocking issues: {len(report.blocking_findings)}, "
                    f"Manual review required: {len(report.manual_review_findings)}."
                ),
                severity="CRITICAL" if report.overall_status == "BLOCKED" else "MODERATE",
                details={
                    "overall_status": report.overall_status,
                    "blocking_findings": ", ".join(report.blocking_findings) or "None",
                    "manual_review_findings": ", ".join(report.manual_review_findings) or "None",
                    "total_evaluated": report.summary_counts.total_evaluated,
                },
                codebase_path=repo_path,
            )

        return {
            "verification_report": [report.model_dump_json()],
            "verification_status": report.overall_status,
            "messages": [f"[Checker Agent] Gatekeeper decision: {report.overall_status}."]
        }

    except Exception as e:
        logger.error("[Checker Agent Error] Verification failed: %s", e)
        return {
            "verification_report": [],
            "verification_status": "BLOCKED",
            "messages": [f"[Checker Agent Error] Verification evaluation crashed: {str(e)}"]
        }