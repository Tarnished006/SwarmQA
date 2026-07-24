
import asyncio
import io
from json import tool
import os
import re
import tarfile
from typing import List, Literal
from urllib.parse import urlparse
from langchain_core.prompts import ChatPromptTemplate
from langchain.agents import create_tool_calling_agent, AgentExecutor
import docker
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from triage_agent import Selector


class ScopeViolationError(Exception):
    pass


class SecurePersistentSandbox:
    """
    Hardened, network-isolated Docker sandbox for running LLM-generated
    verification scripts against a single authorized target.

    Security posture:
    - No internet egress: the Docker network is created with internal=True,
      so the container can reach ONLY other containers on the same network
      (i.e. the target under test). No public internet, no cloud metadata
      endpoint (169.254.169.254), nothing outside scope.
    - Non-root user, read-only root filesystem, all capabilities dropped.
    - Memory+swap, CPU, and PID limits to block resource exhaustion.
    - Files are delivered via put_archive (tar), never shell string
      interpolation — eliminates the heredoc shell-injection bug.
    - Every exec is wrapped in a hard timeout at both the container level
      (`timeout` binary) and the asyncio level as a backstop.
    """

    IMAGE = "swarm:latest" # pre-built — see Dockerfile.sandbox below

    def __init__(self, network_name: str = "aegis_sandbox_net", allowed_host: str | None = None):
        self.client = docker.from_env()
        self.network_name = network_name
        self.allowed_host = allowed_host
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
            read_only=True,
            mem_limit="512m",
            memswap_limit="512m",       # prevents swap from doubling the effective cap
            nano_cpus=1_000_000_000,
            pids_limit=100,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            tmpfs={"/tmp": "size=100M,exec,uid=1000,gid=1000"},
        )

    def _write_script(self, script_code: str, filename: str = "current_attack.py"):
        data = script_code.encode("utf-8")
        tarstream = io.BytesIO()
        with tarfile.open(fileobj=tarstream, mode="w") as tar:
            info = tarfile.TarInfo(name=filename)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        tarstream.seek(0)
        self.container.put_archive("/tmp", tarstream)

    def _check_scope(self, script_code: str):
        """Heuristic defense-in-depth only — the internal=True network is the
        real control. This just gives a clean, immediate rejection + audit
        trail when a script names an out-of-scope host explicitly."""
        if not self.allowed_host:
            return
        for host in re.findall(r"https?://([^/\s\"'\)]+)", script_code):
            hostname = host.split(":")[0]
            if hostname not in (self.allowed_host, "localhost", "127.0.0.1"):
                raise ScopeViolationError(
                    f"Script references out-of-scope host '{hostname}'; "
                    f"authorized target is '{self.allowed_host}'."
                )

    async def execute_script(self, script_code: str, timeout_s: int = 15) -> str:
        if not self.container:
            return "Error: Sandbox container is not running."
        try:
            self._check_scope(script_code)
        except ScopeViolationError as e:
            return f"BLOCKED_OUT_OF_SCOPE: {e}"

        await asyncio.to_thread(self._write_script, script_code)

        def _run():
            return self.container.exec_run(
                ["timeout", str(timeout_s), "python3", "/tmp/current_attack.py"],
                demux=True,
            )

        try:
            exit_code, (stdout, stderr) = await asyncio.wait_for(
                asyncio.to_thread(_run), timeout=timeout_s + 5
            )
        except asyncio.TimeoutError:
            return "Error: script execution exceeded hard timeout and was aborted."

        out = (stdout or b"").decode("utf-8", errors="ignore")
        err = (stderr or b"").decode("utf-8", errors="ignore")
        return f"Exit Code: {exit_code}\nSTDOUT:\n{out}\nSTDERR:\n{err}"

    def stop(self):
        if self.container:
            try:
                self.container.stop(timeout=2)
                self.container.remove(force=True)
            except Exception:
                pass
            self.container = None

ALLOWED_SANDBOX_SUFFIXES = tuple(
    s.strip() for s in os.getenv(
        "ALLOWED_SANDBOX_SUFFIXES", ".sandbox.internal,.staging.internal,localhost,127.0.0.1"
    ).split(",")
)

class VerifiedExploit(BaseModel):
    id: str = Field(description="Unique exploit ID, e.g., EXP-001")
    attack_chain_stage: Literal[
        "RECONNAISSANCE", 
        "INITIAL_ACCESS", 
        "PRIVILEGE_ESCALATION", 
        "LATERAL_MOVEMENT", 
        "IMPACT"
    ]
    mitre_technique_id: str = Field(description="Closest MITRE ATT&CK technique ID, e.g., T1190 or T1078")
    target: str = Field(description="Specific target endpoint, form, or parameter")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    reproduction_evidence: str = Field(description="Concrete observed evidence proving the exploit (HTTP status, DB error, timing anomaly)")
    remediation_target: str = Field(description="Exact file, controller, or config path for downstream Patch Debugger")


class ActiveExploitReport(BaseModel):
    sandbox_target_url: str
    verified_exploits: List[VerifiedExploit] = Field(default_factory=list)


# ── 2. Scope Validation Gate ──────────────────────────────────────────
def _validate_scope(target_url: str) -> tuple[bool, str, str]:
    if not target_url:
        return False, "", "No target_url provided."
    hostname = urlparse(target_url).hostname or ""
    if not hostname:
        return False, "", "target_url has no resolvable hostname."
    if not any(hostname.endswith(s) for s in ALLOWED_SANDBOX_SUFFIXES):
        return False, hostname, (
            f"Hostname '{hostname}' does not match allowed sandbox suffixes "
            f"{ALLOWED_SANDBOX_SUFFIXES}; refusing without explicit authorization."
        )
    return True, hostname, ""


async def active_tester_agent(state: Selector):
    target_url = state.get("url", "")
    correlated_raw = state.get("cleaned_errors", [])
    correlated_str = "\n".join(correlated_raw) if correlated_raw else "No prior static findings."

    # Code-Enforced Engagement Gate
    ok, hostname, reason = _validate_scope(target_url)
    if not ok:
        return {
            "active_debugger": [],
            "verification_status": "SCOPE_CLARIFICATION_REQUIRED",
            "messages": [f"[Active_Tester] Scope Blocked: {reason}"]
        }

    # Initialize Hardened Sandbox
    sandbox = SecurePersistentSandbox(network_name="aegis_sandbox_net", allowed_host=hostname)
    sandbox.start()

    @tool
    async def execute_attack_script(script_code: str) -> str:
        """
        Executes a Python verification script inside the isolated,
        network-restricted sandbox. Use this to send HTTP requests, crawl
        pages, fuzz parameters, and confirm vulnerability hypotheses against
        the authorized target only. Scripts naming any other host are
        blocked before execution.
        """
        return await sandbox.execute_script(script_code)

    # Merged Red Team Operator System Prompt
    system_prompt = f"""You are an Autonomous Red Team Operator — an Adversarial Simulation Engine replicating real-world threat-actor tradecraft against a single authorized target environment.

ENGAGEMENT SCOPE (hard boundary — never violate):
- Authorized target host: {hostname}
- Authorized target URL: {target_url}
- Anything outside this host is OUT OF SCOPE. Never touch or pivot to other hosts.

RULES OF ENGAGEMENT:
- No destructive actions, no denial-of-service, no real user data exfiltration (synthetic/canary data only), no persistence left behind.
- Prove impact with the MINIMUM action necessary (read one canary record, flip one non-destructive flag).

ATTACK CHAIN METHODOLOGY (MITRE ATT&CK Staged):
1. RECONNAISSANCE: Review static hypotheses in <CORRELATED_ATTACK_HYPOTHESES>, prioritizing Critical/High surfaces (auth bypass, injection, IDOR, privilege escalation).
2. INITIAL ACCESS / EXPLOITATION: Write Python scripts using `execute_attack_script` to test each prioritized hypothesis against {target_url}. Record real observed behavior (HTTP status, response diffs, timing anomalies) as evidence.
3. PRIVILEGE ESCALATION / LATERAL MOVEMENT: Where initial access succeeds, test whether it chains further (e.g. IDOR exposing an admin object) strictly within {hostname}.
4. IMPACT VALIDATION: Confirm the weakness with minimal intrusion.
5. ATT&CK MAPPING: Associate each confirmed vulnerability with its MITRE ATT&CK technique ID (e.g., T1190, T1078).

OPERATIONAL RULES:
- Treat ONLY actual observed sandbox responses as evidence — never assume outcomes.
- UNCONFIRMED = SILENT: If a hypothesis cannot be reproduced in the sandbox, omit it.
- Stop testing when all hypotheses are verified or invalid, then write a complete plain-text summary of your confirmed findings."""

    human_prompt = """Target URL: {target_url}

<CORRELATED_ATTACK_HYPOTHESES>
{correlated_findings}
</CORRELATED_ATTACK_HYPOTHESES>

Begin scoped verification and output your findings summary."""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", human_prompt),
        ("placeholder", "{agent_scratchpad}"),
    ])

    tools = [execute_attack_script]
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.0)
    agent = create_tool_calling_agent(llm, tools, prompt)
    agent_executor = AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,
        max_iterations=15,
        max_execution_time=180,
    )

    try:
        # Step 1: Execute tool-calling attack loop
        response = await agent_executor.ainvoke({
            "target_url": target_url,
            "correlated_findings": correlated_str,
        })
        raw_transcript = response["output"]

        # Step 2: Convert transcript to strict Pydantic ActiveExploitReport JSON
        structuring_llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.0) # FIXED MODEL NAME
        structured_llm = structuring_llm.with_structured_output(ActiveExploitReport)
        
        structuring_prompt = ChatPromptTemplate.from_messages([
            ("system", "Convert this red-team findings transcript into the ActiveExploitReport schema. "
                       "Include only findings with explicit reproduction evidence in the transcript; "
                       "drop anything speculative or unconfirmed."),
            ("human", "{transcript}"),
        ])
        
        report: ActiveExploitReport = await (structuring_prompt | structured_llm).ainvoke({"transcript": raw_transcript})

        return {
            "active_debugger": [e.model_dump_json() for e in report.verified_exploits],
            "verification_status": "EXPLOITS_CONFIRMED" if report.verified_exploits else "NO_EXPLOITS_CONFIRMED",
            "messages": [f"[Active_Tester] Confirmed {len(report.verified_exploits)} actionable exploits."]
        }
    finally:
        # Guarantee container destruction
        sandbox.stop()