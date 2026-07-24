
import asyncio
import io
import json
import os
import shutil
import tarfile
import tempfile
from typing import Any, Dict, List, Literal, Optional
from langchain_core.prompts import ChatPromptTemplate
import docker
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from site_analysing_agent import Selector


class CleanRoomSandbox:
    """
    Hardened, ephemeral Docker runner designed for Blue Team patch verification.
    Executes regression tests against a freshly patched workspace in total isolation.
    """
    IMAGE =  "swarm:latest"  # Pre-built image with python/pytest pre-installed

    def __init__(self, network_name: str = "aegis_verification_net"):
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

        # Spin up clean room container
        self.container = self.client.containers.run(
            image=self.IMAGE,
            command="tail -f /dev/null",
            detach=True,
            network=self.network_name,
            user="1000:1000",
            read_only=False, # Granted write permissions inside /tmp for test execution
            mem_limit="512m",
            memswap_limit="512m",
            nano_cpus=1_000_000_000,
            pids_limit=100,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            tmpfs={"/tmp": "size=100M,exec,uid=1000,gid=1000"},
        )

    def upload_workspace(self, workspace_dir: str):
        """Archives and transfers the patched workspace into the container's /tmp directory."""
        tarstream = io.BytesIO()
        with tarfile.open(fileobj=tarstream, mode="w") as tar:
            for root, _, files in os.walk(workspace_dir):
                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, workspace_dir)
                    tar.add(full_path, arcname=rel_path)
        tarstream.seek(0)
        
        # Ensure target workspace directory exists inside container
        self.container.exec_run(["mkdir", "-p", "/tmp/workspace"])
        self.container.put_archive("/tmp/workspace", tarstream)

    async def execute_test(self, test_filename: str, timeout_s: int = 20) -> Dict[str, Any]:
        """Executes a single test script inside the sandbox and captures outputs."""
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
        except asyncio.TimeoutError:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": "Error: Regression test execution exceeded hard timeout."
            }

        return {
            "exit_code": exit_code,
            "stdout": (stdout or b"").decode("utf-8", errors="ignore"),
            "stderr": (stderr or b"").decode("utf-8", errors="ignore")
        }

    def stop(self):
        """Destroys the container and network context."""
        if self.container:
            try:
                self.container.stop(timeout=2)
                self.container.remove(force=True)
            except Exception:
                pass
            self.container = None
async def sandbox_execution_node(state: Selector) -> dict:
    raw_path = state.get("codebase_path", [])
    source_codebase = raw_path[0] if raw_path else ""
    remediation_raw = state.get("remediation_plan", [])

    if not source_codebase or not os.path.exists(source_codebase):
        return {"test_results": [json.dumps({"error": "Invalid codebase path provided."})]}

    if not remediation_raw:
        return {"test_results": [json.dumps({"info": "No remediation plan found to test."})]}

    print("[Sandbox_Execution] Initializing Clean Room verification environment...")
    
    execution_logs: List[str] = []

    # 1. Parse Remediation Plan JSON
    patches = []
    for plan_str in remediation_raw:
        try:
            plan_data = json.loads(plan_str)
            patches.append(plan_data)
        except json.JSONDecodeError:
            continue

    # 2. Work inside an isolated temporary directory on the host
    with tempfile.TemporaryDirectory() as temp_workspace:
        # Copy original codebase to temp workspace
        if os.path.isdir(source_codebase):
            shutil.copytree(source_codebase, temp_workspace, dirs_exist_ok=True)
        else:
            shutil.copy2(source_codebase, temp_workspace)

        # 3. Apply patches to the temporary workspace files
        test_files_created = []
        for patch in patches:
            patch_id = patch.get("id", "UNKNOWN")
            file_rel_path = patch.get("file_path", "")
            original_code = patch.get("original_code_snippet", "")
            patched_code = patch.get("patched_code_snippet", "")
            regression_test = patch.get("regression_test", "")

            target_file_full = os.path.join(temp_workspace, file_rel_path)

            # Apply Code Replacement
            if os.path.exists(target_file_full) and original_code:
                with open(target_file_full, "r", encoding="utf-8", errors="ignore") as f:
                    file_content = f.read()
                
                if original_code in file_content:
                    updated_content = file_content.replace(original_code, patched_code)
                    with open(target_file_full, "w", encoding="utf-8") as f:
                        f.write(updated_content)

            # Write Regression Test File
            test_filename = f"test_aegis_{patch_id}.py"
            test_file_full = os.path.join(temp_workspace, test_filename)
            with open(test_file_full, "w", encoding="utf-8") as f:
                f.write(regression_test)
            
            test_files_created.append((patch_id, test_filename))

        # 4. Spin up Clean Room Docker Sandbox
        sandbox = CleanRoomSandbox()
        sandbox.start()

        try:
            # Upload patched workspace to container
            sandbox.upload_workspace(temp_workspace)

            # Execute each regression test inside the clean sandbox
            for patch_id, test_filename in test_files_created:
                res = await sandbox.execute_test(test_filename)
                
                test_record = {
                    "patch_id": patch_id,
                    "test_file": test_filename,
                    "exit_code": res["exit_code"],
                    "status": "PASSED" if res["exit_code"] == 0 else "FAILED",
                    "stdout": res["stdout"],
                    "stderr": res["stderr"]
                }
                execution_logs.append(json.dumps(test_record))

        finally:
            sandbox.stop()

    return {
        "test_results": execution_logs,
    }
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
    verdict_confidence: Literal["HIGH", "MEDIUM", "LOW"] = Field(
        description="Confidence level based on test evidence clarity and completeness"
    )
    chain_completeness_check: str = Field(
        description="Confirmation that all steps of a multi-hop chain are neutralized, not just the entry."
    )
    bypass_analysis_notes: str = Field(
        description="Attacker-perspective review checking for trivial evasions or new attack surfaces."
    )
    feedback_for_patcher: Optional[str] = Field(
        description="Precise technical instructions for the patch agent if the verdict is FAILED. None if SUCCESS."
    )
    retry_limit_exceeded: bool = Field(
        description="True if the finding has hit the max retry limit, breaking the loop."
    )

class VerificationReport(BaseModel):
    overall_status: Literal["READY_FOR_DEPLOYMENT", "BLOCKED", "PARTIAL_WITH_REVIEW"]
    blocking_findings: List[str] = Field(
        description="List of exploit IDs that resulted in a FAILED verdict."
    )
    manual_review_findings: List[str] = Field(
        description="List of exploit IDs flagged for human intervention."
    )
    summary_counts: VerificationSummaryCounts
    results: List[VerificationResult] = Field(default_factory=list)

async def checker_agent(state:Selector):
    system="""
    You are an Autonomous DevSecOps Verification Engine — the Lead Security Auditor 
and QA Gatekeeper. You operate as the final validation node in the pipeline, sitting 
between the Remediation node and production deployment. Nothing ships past you 
without an explicit verdict. Your objective is to ingest the original exploits, 
the patches applied, and regression test execution results, and definitively 
determine whether each vulnerability is neutralized without breaking legitimate 
business logic — and whether the pipeline as a whole is safe to deploy.

INPUT DATA SOURCES:
1. <VERIFIED_EXPLOITS> — original attack vectors, payloads, targets, and 
   chain_steps (if a multi-hop chain from the correlation node).
2. <REMEDIATION_PLAN> — patches applied (original vs. patched snippets), 
   regression tests, blast_radius, and requires_human_review flags.
3. <TEST_EXECUTION_RESULTS> — stdout/stderr, HTTP status codes, and response 
   bodies from running regression tests against the patched sandbox.
4. <RETRY_COUNT> — how many times this specific finding has already looped 
   through patch→verify. If absent, assume this is attempt 1.

═══════════════════════════════════
STAGE 1 — EXPLOIT NEUTRALIZATION VERIFICATION
═══════════════════════════════════
Cross-reference `payload_used` against `patched_code_snippet` and the actual 
test results (not just the code's apparent intent):
- Parameterization vs. blocklist — does the fix use framework-native 
  parameterized queries/prepared statements, or a brittle string/regex filter?
- Authorization — does the code now check ownership against the trusted 
  session/JWT `user_id`, or did it just remove/hide a UI element?
- Test evidence — did the malicious test case return the expected block 
  (401/403/400/422), or does a 200/500 indicate the exploit still works or 
  the server crashed (crash-on-attack is its own finding: availability risk, 
  not a fix)?
- CHAIN COMPLETENESS — if this exploit was a multi-hop `chain_steps` entry 
  from the correlation node, verify EVERY step in the chain is now blocked, 
  not just the entry point. A patch that closes step 1 but leaves step 2 
  reachable via a different route must NOT be marked SUCCESS_SECURE.

═══════════════════════════════════
STAGE 2 — BUSINESS LOGIC REGRESSION CHECK
═══════════════════════════════════
Analyze the legitimate/safe test cases in <TEST_EXECUTION_RESULTS>:
- Did the patch block legitimate users or valid input (overly aggressive 
  validation, regex too strict, allow-list missing a valid field)?
- Is the API contract intact — same response schema/shape for healthy 
  requests, no new required fields breaking existing clients?
- Latency/behavior change — does the patch introduce a blocking call 
  (e.g., synchronous lookup) that could newly violate expected performance 
  characteristics, if that data is available in test results?
- Any legitimate-case test failure → `FAILED_BUSINESS_LOGIC_REGRESSION`, 
  regardless of how well the exploit itself was blocked.

═══════════════════════════════════
STAGE 3 — BYPASS, EVASION & NEW-SURFACE ANALYSIS
═══════════════════════════════════
Evaluate `patched_code_snippet` from an attacker's perspective, not just 
against the original payload:
- Trivial bypass — case variation, encoding tricks, alternate syntax 
  (`UNION`, nested queries, whitespace/comment insertion) that the exact 
  original payload wouldn't test but the same root cause would still allow.
- New vulnerability introduced — swallowed exceptions causing inconsistent 
  state, a new injection point in the sanitization logic itself, a broadened 
  exception handler that now masks unrelated errors.
- Incomplete root-cause fix — the patch addresses the symptom at the 
  reported endpoint but the same insecure pattern (e.g., same raw-query 
  helper function) is still reachable from a different, unpatched caller — 
  flag this explicitly even though it's outside the original exploit's path.
- If bypassable or root cause unaddressed → `FAILED_STILL_VULNERABLE` with 
  explicit, technical `feedback_for_patcher` (what specifically remains 
  exploitable, not just "try again").

═══════════════════════════════════
STAGE 4 — RETRY LOOP SAFETY
═══════════════════════════════════
- If `RETRY_COUNT` for a given finding has already reached 3 without 
  reaching SUCCESS_SECURE, do NOT return `FAILED_STILL_VULNERABLE` again 
  to trigger another automatic retry. Instead return 
  `MANUAL_REVIEW_REQUIRED` with `retry_limit_exceeded: true` — this breaks 
  the loop and routes to a human rather than cycling indefinitely.
- Any finding where `requires_human_review` was already `true` in the 
  <REMEDIATION_PLAN> (e.g., WIDE blast radius, major dependency bump) is 
  verified for correctness but always resolves to at most 
  `MANUAL_REVIEW_REQUIRED`, never auto-approved to `SUCCESS_SECURE`.

═══════════════════════════════════
STAGE 5 — PER-FINDING VERDICT
═══════════════════════════════════
- SUCCESS_SECURE — exploit (and full chain, if applicable) neutralized, 
  all tests pass, business logic intact, no new surface introduced.
- FAILED_STILL_VULNERABLE — root cause not fixed or trivially bypassable.
- FAILED_BUSINESS_LOGIC_REGRESSION — secured but broke legitimate functionality.
- MANUAL_REVIEW_REQUIRED — too complex to verify autonomously (architectural 
  shift, dependency overhaul, retry limit exceeded, or pre-flagged high 
  blast radius).
Attach a `verdict_confidence: HIGH|MEDIUM|LOW` — LOW confidence (e.g., test 
results were partial/ambiguous, or static-only evidence with no live test 
output) should push borderline cases toward `MANUAL_REVIEW_REQUIRED` rather 
than a guessed SUCCESS_SECURE.

═══════════════════════════════════
STAGE 6 — PIPELINE-LEVEL AGGREGATION
═══════════════════════════════════
Derive `overall_status` from the full set of per-finding verdicts, not just 
majority vote:
- READY_FOR_DEPLOYMENT — every finding is SUCCESS_SECURE.
- BLOCKED — any single finding is FAILED_STILL_VULNERABLE or 
  FAILED_BUSINESS_LOGIC_REGRESSION (one unresolved critical/high finding 
  blocks the whole batch, even if others passed).
- PARTIAL_WITH_REVIEW — all findings are either SUCCESS_SECURE or 
  MANUAL_REVIEW_REQUIRED (nothing outright failed, but not fully autonomous-clear).
Never return READY_FOR_DEPLOYMENT if any CRITICAL or HIGH-impact finding 
(per the original `impact` rating) is not SUCCESS_SECURE, even if lower 
-severity findings all passed.

═══════════════════════════════════
OUTPUT CONTRACT
═══════════════════════════════════
- Output ONLY valid JSON adhering strictly to the VerificationReport schema.
- No markdown, narration, or text outside the JSON payload.
- Every applied patch has one VerificationResult object: 
  [id] [verdict] [verdict_confidence] [chain_completeness_check] 
  [bypass_analysis_notes] [feedback_for_patcher] [retry_limit_exceeded].
- Top-level: [overall_status] [blocking_findings] [manual_review_findings] 
  [summary_counts].
- If `overall_status` is not READY_FOR_DEPLOYMENT, every non-SUCCESS_SECURE 
  finding must include precise, technical `feedback_for_patcher` so the loop 
  can retry — vague feedback (e.g., "still vulnerable") is not acceptable.
- Never include exploit payloads or attack code in `feedback_for_patcher` 
  beyond what's necessary to describe the bypass technique category.
"""

    human="""
    <VERIFIED_EXPLOITS>
{verified_exploits}
</VERIFIED_EXPLOITS>

<REMEDIATION_PLAN>
{remediation_plan}
</REMEDIATION_PLAN>

<TEST_EXECUTION_RESULTS>
{test_execution_results}
</TEST_EXECUTION_RESULTS>

Evaluate the effectiveness and safety of the applied patches based on the test execution results and codebase logic. Return ONLY the structured VerificationReport JSON.
"""

    prompt=ChatPromptTemplate.from_messages([("system",system),("human",human)])
    llm=ChatOpenAI(model="gpt-4.1-mini",temperature=0.0,max_tokens=2000)
    structured_llm=llm.with_structured_output(VerificationReport)
    chain=prompt | structured_llm
    report=await chain.ainvoke({
        "verified_exploits":"\n".join(state.get("active_debugger",[])),
        "remediation_plan":"\n".join(state.get("remediation_plan",[])),
        "test_execution_results":"\n".join(state.get("test_results",[]))
    })
    return {
        "verification_report": [report.model_dump_json()],
        "verification_status": report.overall_status 
    }