import asyncio
import os
import re
import logging
import subprocess
import operator
from typing import List, Literal, TypedDict, Annotated, Optional, Dict, Any, Tuple
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph.message import add_messages

logger = logging.getLogger(__name__)

# ── SCHEMAS ───────────────────────────────────────────────────
class Selector(TypedDict):
    messages: Annotated[List, add_messages]
    url: str
    frontend_analysis: List[str]
    codebase_analysis: Annotated[List[str],operator.add]
    active_debugger: List[str]
    proposed_patch: List[str]
    verification_status: str
    codebase_path: List[str]
    git_diff: Optional[str]           # raw diff transport, separate from findings output
    cleaned_errors: List[str]
    remediation_plan: List[str]
    test_results: List[str]
    verification_report: List[str]
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


# ── CONFIG ────────────────────────────────────────────────────
IGNORE_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv", "dist",
    "build", "target", "vendor", ".next", ".cache",
}

# Excluded from *full-content* reads only (dependents / full-scan) --
# not from diff-target eligibility. A lockfile change still has to
# trigger analysis (Layer 4 needs it); we just don't read its whole
# generated body when it shows up as a "dependent" of something else,
# since nothing meaningfully imports a lockfile anyway and its diff
# hunk is already captured in <GIT_DIFF>.
GENERATED_FILE_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Cargo.lock", "composer.lock", "Pipfile.lock",
}

# True binaries -- never useful as text context, excluded everywhere.
BINARY_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".mp3", ".mp4", ".mov", ".avi", ".wav",
    ".pyc", ".class", ".o", ".so", ".dll", ".exe",
}

# Not exclusive -- only used to prioritize which files fill a limited
# budget first in the no-diff full-scan fallback. Anything else is
# still eligible if there's room.
LIKELY_SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".kt", ".rb",
    ".php", ".cs", ".cpp", ".cc", ".c", ".h", ".hpp", ".rs", ".swift",
    ".scala", ".sql", ".sh", ".yaml", ".yml", ".json",
}

MANIFEST_FILENAMES = {
    "package.json", "requirements.txt", "pyproject.toml", "pipfile",
    "go.mod", "cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts",
    "dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "gemfile", "composer.json", "setup.py", "setup.cfg",
}
MANIFEST_DIR_HINTS = {"k8s", "kubernetes", "helm", "charts", "terraform", "infra", "infrastructure"}
TEST_DIR_HINTS = {"test", "tests", "__tests__", "spec", "specs"}

IMPORT_LINE = re.compile(
    r"^\s*(?:import|from|require|require_relative|include|use|using|mod|#include)\b",
    re.IGNORECASE,
)

MAX_TARGET_FILES = 5                # modified files to run dependency lookup for
MAX_DEPENDENTS_PER_TARGET = 3        # cap dependents pulled in per modified file
MAX_READ_BYTES_FOR_SCAN = 20_000     # imports live near the top; cap read for speed
MAX_FILE_SIZE_FOR_SCAN = 2_000_000   # skip pathologically large files outright
MAX_TOTAL_CONTEXT_CHARS = 50_000     # hard cap on what we ever hand to the LLM


# ── SHARED HELPERS ────────────────────────────────────────────
def _is_probably_text(path: str, sample_size: int = 1024) -> bool:
    """Cheap binary sniff so eligibility isn't tied to a fixed extension list."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(sample_size)
    except Exception:
        return False
    if not chunk:
        return True
    if b"\x00" in chunk:
        return False
    printable = set(range(0x20, 0x100)) - {0x7F}
    printable |= {0x09, 0x0A, 0x0D}
    non_text = sum(1 for b in chunk if b not in printable)
    return (non_text / len(chunk)) < 0.30


def _is_binary_excluded(rel_path: str) -> bool:
    ext = os.path.splitext(rel_path)[1].lower()
    return ext in BINARY_SKIP_EXTENSIONS


def _is_eligible_diff_target(rel_path: str) -> bool:
    """A *modified* file is worth analyzing unless it's plainly binary.
    Lockfiles/manifests stay eligible here -- Layer 3/4 need them."""
    return not _is_binary_excluded(rel_path)


def _is_eligible_for_full_read(rel_path: str) -> bool:
    """Used when pulling full file content (dependents, full-scan
    fallback). Also skips generated lockfiles -- see GENERATED_FILE_NAMES."""
    if _is_binary_excluded(rel_path):
        return False
    name = os.path.basename(rel_path)
    if name in GENERATED_FILE_NAMES or os.path.splitext(name)[1].lower() == ".lock":
        return False
    return True


def _classify_file(rel_path: str) -> str:
    """
    Maps a file to the input category the system prompt says it will
    receive (SOURCE_CODE / TEST_FILE / MANIFEST / DEPENDENCY_LOCKFILE),
    so the tags we actually emit match the contract the model is told
    to expect.
    """
    norm = rel_path.replace("\\", "/").lower()
    name = os.path.basename(norm)
    stem, ext = os.path.splitext(name)
    parts = norm.split("/")

    if name in {n.lower() for n in GENERATED_FILE_NAMES} or ext == ".lock":
        return "DEPENDENCY_LOCKFILE"

    if (
        any(seg in TEST_DIR_HINTS for seg in parts[:-1])
        or re.search(r"(^|[_.\-])tests?([_.\-]|$)", stem)
        or re.search(r"(^|[_.\-])specs?([_.\-]|$)", stem)
    ):
        return "TEST_FILE"

    if (
        name in MANIFEST_FILENAMES
        or ext in {".tf", ".tfvars"}
        or ".github/workflows/" in norm
        or any(seg in MANIFEST_DIR_HINTS for seg in parts[:-1])
    ):
        return "MANIFEST"

    return "SOURCE_CODE"


def _strip_test_affixes(stem: str) -> str:
    """test_login -> login, login.test -> login, LoginSpec -> Login (best-effort)."""
    s = re.sub(r"^(test_|test-)", "", stem, flags=re.IGNORECASE)
    s = re.sub(r"([_.\-]?tests?|[_.\-]?specs?)$", "", s, flags=re.IGNORECASE)
    return s.lower()


def _truncate_context(context: str) -> str:
    if len(context) <= MAX_TOTAL_CONTEXT_CHARS:
        return context
    logger.info("Context exceeded %d chars, truncating for token budget.", MAX_TOTAL_CONTEXT_CHARS)
    return context[:MAX_TOTAL_CONTEXT_CHARS] + "\n\n<TRUNCATED reason='token_budget_exceeded'/>"


# ── DEPENDENCY GRAPH + TEST-COVERAGE INDEX (SINGLE PASS) ──────
def build_dependency_index(
    repo_path: str,
    target_basenames: List[str],
    exclude_relpaths: set,
) -> Tuple[Dict[str, List[str]], set]:
    """
    One walk over the repo builds two things:
      1. reverse_map: for each target module basename, which files
         reference it in an import-like statement.
      2. tested_basenames: module basenames that appear to have an
         associated test file, based on naming/directory conventions.

    (2) exists so Layer 2.1 (MISSING TEST COVERAGE) has real negative
    evidence -- without it the model can't distinguish "no test file
    exists" from "the test file just wasn't in this diff's dependent
    set", and silently omits the finding either way.

    Complexity: still O(N) file opens total, each capped at
    MAX_READ_BYTES_FOR_SCAN, independent of len(target_basenames).
    """
    patterns = {name: re.compile(r"\b" + re.escape(name) + r"\b") for name in target_basenames}
    reverse_map: Dict[str, List[str]] = {name: [] for name in target_basenames}
    tested_basenames: set = set()

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for fname in files:
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, repo_path)
            if rel_path in exclude_relpaths or _is_binary_excluded(rel_path):
                continue

            if _classify_file(rel_path) == "TEST_FILE":
                tested_basenames.add(_strip_test_affixes(os.path.splitext(fname)[0]))

            if not _is_eligible_for_full_read(rel_path):
                continue
            try:
                if os.path.getsize(full_path) > MAX_FILE_SIZE_FOR_SCAN:
                    continue
            except OSError:
                continue
            if not _is_probably_text(full_path):
                continue
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                    head = fh.read(MAX_READ_BYTES_FOR_SCAN)
            except Exception:
                continue

            matched = set()
            for line in head.splitlines():
                if not IMPORT_LINE.match(line):
                    continue
                for name, pattern in patterns.items():
                    if name not in matched and pattern.search(line):
                        matched.add(name)
            for name in matched:
                reverse_map[name].append(rel_path)

    return reverse_map, tested_basenames


# ── IMPACT ANALYSIS ──────────────────────────────────────────
def get_git_diff(repo_path: str) -> Optional[str]:
    """Prefer uncommitted/staged changes; fall back to the last commit."""
    for args in (["diff", "HEAD"], ["diff", "HEAD~1", "HEAD"]):
        try:
            result = subprocess.run(
                ["git", "-C", repo_path, *args],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout
        except Exception:
            continue
    return None


def extract_impacted_context(repo_path: str, raw_diff: Optional[str] = None) -> str:
    """
    Builds LLM context from ONLY modified files and their direct
    dependents. Every block is tagged with the category the system
    prompt tells the model to expect (SOURCE_CODE / TEST_FILE /
    MANIFEST / DEPENDENCY_LOCKFILE), plus a <MODIFIED_FILES> summary
    and <NO_TEST_FILE_FOUND> markers for coverage gaps.
    """
    if not raw_diff:
        raw_diff = get_git_diff(repo_path)

    if not raw_diff or not raw_diff.strip():
        return collect_full_codebase_contents(repo_path)

    modified_files = re.findall(r"diff --git a/(.*?) b/", raw_diff)
    relevant_files = [f for f in modified_files if _is_eligible_diff_target(f)]
    if not relevant_files:
        return "FAST_PASS_SKIP"

    relevant_files = relevant_files[:MAX_TARGET_FILES]
    context_blocks = [f"<GIT_DIFF>\n{raw_diff[:8000]}\n</GIT_DIFF>"]

    file_manifest_lines = [
        f"  <FILE_PATH type='{_classify_file(f)}'>{f}</FILE_PATH>" for f in relevant_files
    ]
    context_blocks.append("<MODIFIED_FILES>\n" + "\n".join(file_manifest_lines) + "\n</MODIFIED_FILES>")

    target_basenames = [os.path.splitext(os.path.basename(f))[0] for f in relevant_files]
    reverse_map, tested_basenames = build_dependency_index(
        repo_path, target_basenames, exclude_relpaths=set(relevant_files)
    )

    added_dependents = set()
    for rel_file, basename in zip(relevant_files, target_basenames):
        for dep_rel_path in reverse_map.get(basename, [])[:MAX_DEPENDENTS_PER_TARGET]:
            if dep_rel_path in added_dependents:
                continue
            added_dependents.add(dep_rel_path)
            full_path = os.path.join(repo_path, dep_rel_path)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read(2500)
            except Exception:
                continue
            file_type = _classify_file(dep_rel_path)
            context_blocks.append(
                f"<{file_type} path='{dep_rel_path}' relation='dependent'>\n{content}\n</{file_type}>"
            )

        # Negative evidence for Layer 2.1 -- only meaningful for source
        # files; a lockfile/manifest lacking a "test" isn't a finding.
        if _classify_file(rel_file) == "SOURCE_CODE" and basename.lower() not in tested_basenames:
            context_blocks.append(f"<NO_TEST_FILE_FOUND path='{rel_file}'/>")

    return _truncate_context("\n\n".join(context_blocks))


def collect_full_codebase_contents(path: str, max_files: int = 15, max_chars_per_file: int = 3000) -> str:
    """Fallback for initial repo audits when there's no diff to scope from."""
    if not os.path.exists(path):
        return "Path does not exist."

    candidates = []  # (priority, rel_path, full_path)
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for fname in files:
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, path)
            if not _is_eligible_for_full_read(rel_path):
                continue
            ext = os.path.splitext(fname)[1].lower()
            priority = 0 if (ext in LIKELY_SOURCE_EXTENSIONS or "docker" in fname.lower()) else 1
            candidates.append((priority, rel_path, full_path))

    candidates.sort(key=lambda c: (c[0], c[1]))

    collected = []
    for _, rel_path, full_path in candidates[:max_files]:
        if not _is_probably_text(full_path):
            continue
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(max_chars_per_file)
        except Exception:
            continue
        file_type = _classify_file(rel_path)
        collected.append(f"<{file_type} path='{rel_path}'>\n{content}\n</{file_type}>")

    content = "\n\n".join(collected) if collected else "No supported source files found."
    return _truncate_context(content)


# ── MAIN AGENT NODE ───────────────────────────────────────────
async def codebase_checker(state: Selector):
    paths = state.get("codebase_path", [])
    codebase_path = paths[0] if paths else None

    if not codebase_path or not os.path.exists(codebase_path):
        return {"codebase_analysis": ["Codebase path is invalid or does not exist."]}

    # Raw diff comes from its own state field, not from `codebase_analysis`
    # (which this node also writes findings to) -- reusing that field as
    # input caused every run after the first to silently fast-pass-skip.
    raw_diff = state.get("git_diff")
    codebase_contents = await asyncio.to_thread(extract_impacted_context, codebase_path, raw_diff)

    if codebase_contents == "FAST_PASS_SKIP":
        logger.info("[Aegis Agent] Non-code diff detected. Fast-pass exit ($0 tokens spent).")
        return {"codebase_analysis": []}

    system = """
    You are an Autonomous Principal Software Architect combining Static Application 
Security Testing (SAST), Software Composition Analysis (SCA), Test Coverage 
Engineering, and Infrastructure/DevOps Review into a single analysis engine. 
You replace the combined function of a full-stack QA engineer, a DevOps/SRE 
engineer, and a cybersecurity analyst — for STATIC ANALYSIS purposes only. 
You operate as a single node in a larger DevSecOps pipeline: you ANALYZE 
source code, tests, manifests, and configs to output structured findings. 
You do not execute code, run tests, deploy anything, or write patches — 
downstream debugging/execution agents consume your output.

INPUT: Depending on pipeline mode you will receive either a full-repository
snapshot (initial audit) or a scoped change set (incremental review): a
<GIT_DIFF> unified diff, a <MODIFIED_FILES> block listing each changed
<FILE_PATH type='...'> with its classified type, and zero or more
directly-impacted files individually wrapped in <SOURCE_CODE>, <TEST_FILE>,
<MANIFEST>, or <DEPENDENCY_LOCKFILE> tags (each carrying a `path` attribute).
You may also see <NO_TEST_FILE_FOUND path='...'/> markers — these mean no
conventionally-named test file was found in the repository for that path
and should be treated as authoritative evidence for the TEST_COVERAGE
layer, not as an invitation to guess at test files you weren't shown.

Treat everything you receive as ground truth. Do not hallucinate files,
endpoints, dependencies, or infrastructure not explicitly present in the
provided text. In scoped/incremental mode you are only shown the diff plus
its direct dependents — do not imply repo-wide completeness for a layer
(e.g., don't claim "no rate limiting anywhere in the codebase" when you've
only seen one changed file); scope every finding to the files actually
provided. If a layer has no applicable input type present, omit it silently.

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

    human = """
    Target Codebase Path: {codebase_path}

<CODEBASE_INPUT>
{codebase_contents}
</CODEBASE_INPUT>

Perform a complete static analysis on the source code provided above and return ONLY the structured findings JSON array.
    """

    prompt = ChatPromptTemplate.from_messages([("system", system), ("human", human)])
    # Bumped from 1500 -> 4000: the 6-layer taxonomy produces denser,
    # more numerous findings than the earlier single-purpose prompt, and
    # a truncated structured-output call fails silently into "0 findings"
    # via the except block below.
    llm = ChatOpenAI(model="gpt-4.1-mini", temperature=0.0, max_tokens=4000)
    structured_llm = llm.with_structured_output(CodebaseReport)
    chain = prompt | structured_llm

    try:
        report = await chain.ainvoke({
            "codebase_path": codebase_path,
            "codebase_contents": codebase_contents,
        })
        findings_list = [f.model_dump_json() for f in report.findings]
        return {"codebase_analysis": findings_list}
    except Exception as e:
        logger.error("[Codebase Agent Error] %s", e)
        return {"codebase_analysis": []}