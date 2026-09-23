import os
import logging
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langgraph.graph.message import add_messages
from typing import Literal, Optional, List, Annotated, TypedDict
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("aegis.triage_agent")
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


# ── OUTPUT SCHEMAS ────────────────────────────────────────────
class CorrelatedHypothesis(BaseModel):
    id: str = Field(description="Unique correlated ID, e.g., CORR-001")
    root_cause: str = Field(description="The underlying defect driving the vulnerability")
    chain_steps: List[str] = Field(
        description="Ordered execution steps for multi-hop attacks. Single-step for pairwise findings."
    )
    frontend_reference: Optional[str] = Field(
        default=None,
        description="Exact frontend element (selector/label + form action or param name)"
    )
    backend_reference: Optional[str] = Field(
        default=None,
        description="Exact backend reference (file path + function/route + line number)"
    )
    # Structured fields for downstream active_tester and patch_agent correlation
    endpoint: Optional[str] = Field(
        default=None,
        description="Resolved API endpoint, e.g., '/api/v1/users/{id}'"
    )
    parameter: Optional[str] = Field(
        default=None,
        description="Resolved vulnerable parameter or variable name, e.g., 'user_id'"
    )
    impact: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    confidence: Literal["CONFIRMED", "LIKELY"]
    verification_technique: str = Field(
        description="Testing category required, e.g., 'authorization boundary test', 'parameterization check'"
    )


class TriageReport(BaseModel):
    prioritized_hypotheses: List[CorrelatedHypothesis] = Field(default_factory=list)


# ── UNIFIED MODEL LOADER ──────────────────────────────────────
def get_triage_llm() -> ChatOpenAI:
    """
    Unified, fail-safe OpenAI-compatible model loader.
    Reads standard environment variables:
    - OPENAI_API_KEY: API key (Groq, OpenAI, DeepSeek, etc.)
    - OPENAI_BASE_URL: Endpoint URL (optional, e.g. for Groq, Ollama)
    - OPENAI_MODEL: Model identifier (defaults to gpt-4o-mini)
    """
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("GROQ_API_KEY")
    base_url = os.getenv("OPENAI_BASE_URL") or os.getenv("OPENAI_API_BASE")
    model_name = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    if not api_key:
        if base_url and ("localhost" in base_url or "127.0.0.1" in base_url):
            api_key = "ollama"
        else:
            raise ValueError(
                "Missing LLM API Key! Please set OPENAI_API_KEY in your .env file."
            )

    return ChatOpenAI(
        model=model_name,
        api_key=api_key,
        base_url=base_url,
        temperature=0.0,
        max_tokens=4000,
    )


# ── MAIN AGENT NODE ───────────────────────────────────────────
async def triage_agent(state: Selector) -> dict:
    """
    Correlation and triage node — sits between static analysis and active verification.

    Ingests frontend findings (Finding[]) and codebase findings (CodebaseFinding[])
    from upstream agents, correlates them by shared endpoint/parameter, constructs
    multi-hop attack chains, and emits a prioritized CorrelatedHypothesis list
    into `cleaned_errors` for the Red Team.
    """
    frontend_raw = state.get("frontend_analysis", [])
    codebase_raw = state.get("codebase_analysis", [])

    # ── FAST-PASS: Nothing to correlate ──────────────────────
    if not frontend_raw and not codebase_raw:
        logger.info(
            "[Triage Agent] Both upstream agents returned empty findings. "
            "Fast-pass exit ($0 tokens spent)."
        )
        return {
            "cleaned_errors": [],
            "messages": ["[Triage Agent] Fast-pass: No findings from Recon Team to correlate."]
        }

    frontend_str = "\n".join(frontend_raw) if frontend_raw else "No frontend findings recorded."
    codebase_str = "\n".join(codebase_raw) if codebase_raw else "No codebase findings recorded."

    logger.info(
        "[Triage Agent] Correlating %d frontend + %d codebase findings ...",
        len(frontend_raw), len(codebase_raw)
    )

    # ── SYSTEM PROMPT ─────────────────────────────────────────
    system_prompt = """You are an Autonomous DevSecOps Correlation & Vulnerability Triage Engine.
You sit between independent static analyzers and the active verification layer.

Your objective: ingest frontend and backend findings, reconcile contradictions, eliminate
duplicates, construct multi-step attack chains, and output a unified, confidence-scored,
prioritized hypothesis list for downstream active testing and patching.

INPUT DATA SOURCES:
1. <FRONTEND_ANALYSIS> — DOM-level attack surfaces. Each finding is a JSON object with fields:
   id, layer, category, target_element, target_url_or_path, param_name, http_method, risk_priority, test_action.

2. <CODEBASE_ANALYSIS> — API controllers, SQL queries, auth gaps, infra flaws. Each finding is JSON with fields:
   id, layer, file_path, category, issue_type, location, route_or_endpoint, param_or_variable,
   vulnerable_snippet, severity, description.

═══════════════════════════════════
STAGE 1 — ENTITY RESOLUTION
═══════════════════════════════════
Normalize both inputs into a common reference space:
- Match DOM form `target_url_or_path` and `param_name` to backend `route_or_endpoint` and `param_or_variable`.
- Where ambiguous (generic field name like `id` appears in multiple controllers), retain all candidates.
- For each resolved pair, populate the `endpoint` and `parameter` fields in your output — these are
  REQUIRED by the downstream patch_agent for automated file targeting.

═══════════════════════════════════
STAGE 2 — CORRELATION & CHAIN CONSTRUCTION
═══════════════════════════════════
1. PAIRWISE LINKING — connect a frontend finding to its backend counterpart when Stage 1 gives a confident match.
2. MULTI-HOP CHAINS — if a correlated finding (e.g., IDOR on /api/orders/{id}) exposes data that a second
   finding (e.g., missing role check on admin route) could leverage, construct as a single chained entry
   with an ordered `chain_steps` array.
3. DEDUPLICATE BY ROOT CAUSE — merge findings that describe the same underlying defect. Never emit the same root cause twice.
4. CONFLICT RESOLUTION — if frontend and backend disagree (e.g., client-side validation present but server
   has none), the backend finding wins for severity — client-side controls are never trusted as mitigating.
5. SINGLE-SOURCE FINDINGS — if a finding exists in only one layer but is HIGH/CRITICAL severity, still emit
   it. Populate only the applicable reference field (frontend_reference or backend_reference).

═══════════════════════════════════
STAGE 3 — SEVERITY & CONFIDENCE
═══════════════════════════════════
IMPACT (what happens if exploited):
- CRITICAL: auth bypass, full IDOR chain to sensitive data, RCE-class injection
- HIGH: single-layer confirmed injection/IDOR, privilege escalation path
- MEDIUM: exploitable only under additional unconfirmed conditions
- LOW: defense-in-depth gap with no direct exploitation path

CONFIDENCE:
- CONFIRMED: UI surface AND backend weakness both present with clean entity match
- LIKELY: strong entity match but one side inferred rather than directly observed

Only CONFIRMED and LIKELY hypotheses are emitted. Drop SPECULATIVE findings silently.

═══════════════════════════════════
STAGE 4 — FALSE POSITIVE FILTERING
═══════════════════════════════════
Omit findings with: no reachable UI entry point AND no externally callable route (dead code),
theoretical weaknesses without evidenced trigger path, or DOM-only support from disabled/hidden elements.

═══════════════════════════════════
OUTPUT CONTRACT
═══════════════════════════════════
- Output ONLY valid JSON matching the TriageReport schema (prioritized_hypotheses array).
- No markdown, narration, or caveats outside the JSON.
- Each entry MUST populate: id, root_cause, chain_steps, impact, confidence, verification_technique.
- MUST populate `endpoint` and `parameter` whenever a backend finding provides route_or_endpoint / param_or_variable.
- Never generate exploit scripts, payloads, or working attack code."""

    human_prompt = """<FRONTEND_ANALYSIS>
{frontend_findings}
</FRONTEND_ANALYSIS>

<CODEBASE_ANALYSIS>
{codebase_findings}
</CODEBASE_ANALYSIS>

Correlate, deduplicate, and reconcile the findings above into a prioritized attack hypothesis list."""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", human_prompt)
    ])

    try:
        llm = get_triage_llm()
        structured_llm = llm.with_structured_output(TriageReport)
        chain = prompt | structured_llm

        report: TriageReport = await chain.ainvoke({
            "frontend_findings": frontend_str,
            "codebase_findings": codebase_str,
        })

        cleaned_errors = [h.model_dump_json() for h in report.prioritized_hypotheses]

        # Log what the triage found — critical for debugging pipeline
        for h in report.prioritized_hypotheses:
            logger.info(
                "[Triage Agent] %s | %s/%s | endpoint=%s | param=%s",
                h.id, h.impact, h.confidence,
                h.endpoint or "N/A", h.parameter or "N/A"
            )

        logger.info(
            "[Triage Agent] Produced %d correlated hypotheses from %d+%d raw findings.",
            len(cleaned_errors), len(frontend_raw), len(codebase_raw)
        )

        return {
            "cleaned_errors": cleaned_errors,
            "messages": [
                f"[Triage Agent] Correlated {len(cleaned_errors)} attack hypotheses "
                f"from {len(frontend_raw)} frontend + {len(codebase_raw)} codebase findings."
            ]
        }

    except Exception as e:
        logger.error("[Triage Agent Error] Correlation failed: %s", e)
        return {
            "cleaned_errors": [],
            "messages": [f"[Triage Agent Error] Correlation LLM invocation failed: {str(e)}"]
        }