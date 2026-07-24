import os
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field
from typing import List, Literal, TypedDict, Annotated
from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph.message import add_messages

class Selector(TypedDict):
    messages:Annotated[List,add_messages]
    url:str
    frontend_analysis:List[str]
    codebase_analysis:List[str]
    active_debugger:List[str]
    proposed_patch:List[str]
    verification_status: str
    codebase_path:List[str]
    cleaned_errors:List[str]
    remediation_plan:List[str]
    test_results:List[str]
    verification_report:List[str]
    next: str

class CodebaseFinding(BaseModel):
    id: str = Field(description="Unique identifier, e.g., SEC-001 or QA-002")
    layer: Literal[
        "API_SECURITY", 
        "TEST_COVERAGE", 
        "INFRASTRUCTURE", 
        "DEPENDENCY", 
        "DATABASE", 
        "OBSERVABILITY"
    ] = Field(description="Layer category")
    file_path: str = Field(description="Exact file path from input")
    category: str = Field(description="Sub-category from system prompt")
    issue_type: str = Field(description="Specific weakness or defect name")
    location: str = Field(description="Exact line number, function name, or test block")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(description="Severity rating")
    description: str = Field(description="Technical description citing exact variable names or parameters")

class CodebaseReport(BaseModel):
    findings: List[CodebaseFinding]
def collect_codebase_contents(path: str, max_files: int = 25, max_chars_per_file: int = 5000) -> str:
    """Reads source code files, manifests, and configs from target path into XML blocks."""
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f"<FILE path='{path}'>\n{f.read()[:max_chars_per_file]}\n</FILE>"
        except Exception as e:
            return f"Error reading file {path}: {e}"

    if not os.path.exists(path):
        return "Path does not exist."

    collected = []
    target_exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml", ".yml", ".sql", "Dockerfile", "docker-compose.yml"}
    ignore_dirs = {"node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build"}

    count = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in target_exts or file in target_exts or "docker" in file.lower():
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, path)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        collected.append(f"<FILE path='{rel_path}'>\n{f.read(max_chars_per_file)}\n</FILE>")
                        count += 1
                        if count >= max_files: break
                except Exception:
                    continue
        if count >= max_files: break

    return "\n\n".join(collected) if collected else "No supported source files found."

async def codebase_checker(state:Selector):
    codebase_path=state.get("codebase_path",[])
    if not codebase_path or not os.path.exists(codebase_path):
        return {"codebase_analysis":"Codebase path is invalid or does not exist."}
    codebase_contents = collect_codebase_contents(codebase_path)
    system="""
    You are an Autonomous Principal Software Architect combining Static Application 
Security Testing (SAST), Software Composition Analysis (SCA), Test Coverage 
Engineering, and Infrastructure/DevOps Review into a single analysis engine. 
You replace the combined function of a full-stack QA engineer, a DevOps/SRE 
engineer, and a cybersecurity analyst — for STATIC ANALYSIS purposes only. 
You operate as a single node in a larger DevSecOps pipeline: you ANALYZE 
source code, tests, manifests, and configs to output structured findings. 
You do not execute code, run tests, deploy anything, or write patches — 
downstream debugging/execution agents consume your output.

INPUT: You will receive one or more of <FILE_PATH>, <FILE_TYPE>, <SOURCE_CODE>, 
<TEST_FILE>, <MANIFEST>, or <DEPENDENCY_LOCKFILE>. Treat this as ground truth. 
Do not hallucinate files, endpoints, dependencies, or infrastructure not 
explicitly present in the provided text. If a layer has no applicable input 
type present, omit it silently.

═══════════════════════════════════
LAYER 1 — API & BUSINESS LOGIC SECURITY
═══════════════════════════════════
1. AUTH & AUTHZ — missing/improper auth decorators, broken JWT validation 
   (alg confusion, missing aud/iss/exp checks), hardcoded bypasses, IDOR at 
   controller level (record fetched by user-supplied ID without ownership check).
2. INJECTION SURFACES — raw/string-concatenated SQL, OS command injection 
   (`subprocess`/`exec` with unescaped input), unsafe deserialization 
   (`pickle.loads`, `yaml.load`, unvalidated `JSON.parse`→`eval`), SSRF via 
   user-controlled outbound URLs, template injection.
3. MASS ASSIGNMENT — endpoints binding raw JSON payloads to models without 
   field allow-listing (e.g., `{"role":"admin"}` on a self-update route).
4. MISSING RATE LIMITS / CSRF — state-changing endpoints (POST/PUT/DELETE) 
   without rate-limiting middleware or CSRF token checks where session-based 
   auth is used.

═══════════════════════════════════
LAYER 2 — TEST COVERAGE & QA ENGINEERING
═══════════════════════════════════
1. MISSING TEST COVERAGE — critical business-logic functions, controllers, 
   or exported modules with no corresponding unit/integration test file; 
   flag by function/route name.
2. UNTESTED ERROR PATHS — `catch`/`except` blocks, non-2xx response branches, 
   and validation-failure branches with no matching test assertion.
3. WEAK ASSERTIONS — tests that only check status codes/truthiness without 
   validating response shape, side effects, or state mutations.
4. FLAKY-PRONE PATTERNS — tests relying on real timers, unmocked network/DB 
   calls, shared mutable fixtures, or execution-order dependencies.
5. BOUNDARY/EDGE CASE GAPS — numeric overflow, empty arrays, null/undefined, 
   pagination limits, and concurrency (double-submit, race condition) cases 
   absent from test suites for the functions that need them.

═══════════════════════════════════
LAYER 3 — INFRASTRUCTURE, DEPLOYMENT & IaC
═══════════════════════════════════
1. CONTAINER SECURITY — Dockerfiles/Compose/K8s manifests running as `root`, 
   missing resource limits, exposed debug/metrics ports, hardcoded secrets 
   in env vars, missing `USER` directive, unpinned base image tags (`:latest`).
2. IaC MISCONFIGURATION — Terraform/CloudFormation/Helm: public S3/storage 
   buckets, overly permissive IAM policies (`*:*`), unencrypted volumes/DBs, 
   security groups open to `0.0.0.0/0`, missing state-file encryption.
3. CONFIG & HEADERS — missing HSTS/CSP/X-Frame-Options, permissive CORS 
   (`Access-Control-Allow-Origin: *` with credentials), default server 
   banners leaking software/version info.
4. CI/CD RISKS — `pull_request_target`/untrusted-checkout with write 
   permissions, plaintext secrets in workflow YAML, unpinned third-party 
   Actions (no SHA pin), missing branch-protection-dependent gates.

═══════════════════════════════════
LAYER 4 — DEPENDENCY & SUPPLY CHAIN
═══════════════════════════════════
1. VULNERABLE / OUTDATED PACKAGES — dependencies in lockfiles with known 
   CVEs or major-version staleness relative to the manifest's stated range.
2. LOCKFILE INTEGRITY — missing lockfile, mismatched lockfile/manifest 
   versions, or `*`/unpinned ranges on direct dependencies.
3. LICENSE & PROVENANCE RISK — copyleft or unlicensed packages in 
   production dependency trees; typosquat-pattern package names.

═══════════════════════════════════
LAYER 5 — DATA & DATABASE LAYER
═══════════════════════════════════
1. SCHEMA/MIGRATION RISKS — destructive migrations without a down-migration 
   or backup step, missing indexes on frequently-filtered/foreign-key columns, 
   nullable columns on fields required by application logic.
2. QUERY PERFORMANCE — N+1 query patterns, unbounded `SELECT *`/missing 
   pagination on list endpoints, missing transaction boundaries on multi-step 
   writes (race-condition/partial-write risk).
3. BACKUP/DR GAPS — datastore configs with no backup/retention policy 
   defined in the provided manifest.

═══════════════════════════════════
LAYER 6 — OBSERVABILITY & ERROR HANDLING
═══════════════════════════════════
1. PII/SECRET LEAKAGE — logging configs or statements dumping raw request 
   bodies, headers, tokens, or PII to stdout/files.
2. VERBOSE ERROR RESPONSES — global handlers leaking stack traces, file 
   paths, or connection strings to the client instead of a generic 500.
3. MISSING OBSERVABILITY — state-changing or high-risk code paths (auth, 
   payment, privilege changes) with no logging/metrics/tracing instrumentation.

═══════════════════════════════════
OUTPUT CONTRACT
═══════════════════════════════════
- Output ONLY valid JSON matching the target schema. Do not include introductory text, markdown headers, or freeform commentary.
- Each finding object must populate the following keys:
  • "id": Unique string identifier (e.g., "SEC-001", "QA-002")
  • "layer": Layer name (e.g., "API_SECURITY", "TEST_COVERAGE", "INFRASTRUCTURE", "DEPENDENCY", "DATABASE", "OBSERVABILITY")
  • "file_path": Exact path from the input
  • "category": Sub-category from the instruction layer
  • "issue_type": Specific weakness or defect name
  • "location": Exact line number, function name, or test block
  • "severity": One of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
  • "description": Specific technical issue description citing exact variable names or parameters
- Group findings by root cause; do not duplicate the same underlying flaw across multiple call sites.
- If evidence for a category is insufficient, omit it silently rather than speculating.
- Never generate working exploit code, malicious payloads, or final code patches — only identify the defective code block and the required remediation type.
    """
    human="""
    Target Codebase Path: {codebase_path}

<CODEBASE_INPUT>
{codebase_contents}
</CODEBASE_INPUT>

Perform a complete static analysis on the source code provided above and return ONLY the structured findings JSON array.
    """
    prompt=ChatPromptTemplate.from_messages([("system",system),("human",human)])
    llm=ChatOpenAI(model="gpt-4.1-mini",temperature=0.0,max_tokens=2000)
    structured_llm=llm.with_structured_output(CodebaseReport)
    chain=prompt | structured_llm
    report=await chain.ainvoke({"codebase_path":codebase_path})
    findings_list= [f.model_dump_json() for f in report.findings]
    return {
        "codebase_analysis": findings_list
    }