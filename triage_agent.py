from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langgraph.graph.message import add_messages
from typing import Literal, Optional, List,Annotated, TypedDict
from pydantic import BaseModel, Field


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

class VerifiedExploit(BaseModel):
    id: str = Field(
        description="Unique exploit ID, e.g., EXP-001"
    )
    attack_chain_stage: Literal[
        "RECONNAISSANCE", 
        "INITIAL_ACCESS", 
        "PRIVILEGE_ESCALATION", 
        "LATERAL_MOVEMENT", 
        "IMPACT"
    ]
    mitre_technique_id: str = Field(
        description="Closest MITRE ATTACK technique ID, e.g., T1190 or T1078"
    )
    target: str = Field(
        description="Specific target endpoint, form, or parameter"
    )
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    reproduction_evidence: str = Field(
        description="Concrete observed evidence proving the exploit (HTTP status, DB error, timing anomaly)"
    )
    remediation_target: str = Field(
        description="Exact file, controller, or config path for downstream Patch Debugger"
    )
class CorrelatedHypothesis(BaseModel):
    id: str = Field(description="Unique correlated ID, e.g., CORR-001")
    root_cause: str = Field(description="The underlying defect driving the vulnerability")
    chain_steps: List[str] = Field(
        description="Ordered array of execution steps for multi-hop attacks. For pairwise, just list the single interaction step."
    )
    frontend_reference: Optional[str] = Field(
        description="Exact frontend element (selector/label/testid + form action or param name)"
    )
    backend_reference: Optional[str] = Field(
        description="Exact backend reference (file path + function/route name + line number)"
    )
    impact: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    confidence: Literal["CONFIRMED", "LIKELY"]
    verification_technique: str = Field(
        description="Category of testing required (e.g., 'authorization boundary test', 'parameterization check')"
    )

class TriageReport(BaseModel):
    prioritized_hypotheses: List[CorrelatedHypothesis]

async def triage_agent(state: Selector) -> dict:
    frontend_raw = state.get("frontend_analysis", [])
    codebase_raw = state.get("codebase_analysis", [])

    frontend_str = "\n".join(frontend_raw) if frontend_raw else "No frontend findings recorded."
    codebase_str = "\n".join(codebase_raw) if codebase_raw else "No codebase findings recorded."

    system_prompt = """
    You are an Autonomous DevSecOps Correlation & Vulnerability Triage Engine — the 
synthesis node that sits between independent static analyzers and the active 
verification layer. Your objective is to ingest frontend and backend findings, 
reconcile contradictions, eliminate duplicates, construct multi-step attack 
chains across layers, and output a unified, confidence-scored, prioritized 
hypothesis list for downstream verification.

INPUT DATA SOURCES:
1. <FRONTEND_ANALYSIS> — DOM-level attack surfaces, form inputs/actions, IDOR 
   candidates, client-side trust signals.
2. <CODEBASE_ANALYSIS> — API controllers, raw SQL/queries, missing auth 
   decorators, mass-assignment risks, infra/config flaws.
3. <INFRA_ANALYSIS> (if present) — container, IaC, CI/CD, and dependency 
   findings from the DevOps layer, for chains that cross into deployment risk.

═══════════════════════════════════
STAGE 1 — ENTITY RESOLUTION
═══════════════════════════════════
Before correlating, normalize both inputs into a common reference space:
- Match DOM form `action` attributes and fetch/XHR call targets to backend 
  route definitions.
- Match DOM input `name`/`id` attributes to controller parameter names, 
  request-body fields, and SQL/ORM query variables.
- Match DOM-visible object identifiers (order IDs, user IDs, slugs) to 
  their corresponding database lookup calls.
- Where a match is ambiguous (e.g., a generic field name like `id` appears 
  in multiple controllers), retain all plausible candidates rather than 
  guessing — flag as `entity_match_confidence: LOW` and carry all candidates 
  into Stage 2.

═══════════════════════════════════
STAGE 2 — CORRELATION & CHAIN CONSTRUCTION
═══════════════════════════════════
1. PAIRWISE LINKING — connect a frontend finding to its backend counterpart 
   when Stage 1 produces a confident match (e.g., an unvalidated DOM field 
   feeding directly into an unescaped SQL query).
2. MULTI-HOP CHAINS — do not stop at pairwise links. If a correlated finding 
   (e.g., IDOR on `/api/orders/{id}`) exposes data that a second, separate 
   finding (e.g., missing role check on an admin route) could then leverage, 
   construct the multi-step hypothesis as a single chained entry with an 
   ordered `chain_steps` array, not two disconnected findings.
3. DEDUPLICATE BY ROOT CAUSE — if both analyzers describe the same underlying 
   defect from different vantage points, merge into one finding carrying 
   both `frontend_reference` and `backend_reference` fields. Never emit the 
   same root cause twice.
4. CONFLICT RESOLUTION — if the two analyses disagree (e.g., frontend infers 
   a field is validated based on a visible `pattern` attribute, but backend 
   shows no server-side re-validation), the backend finding wins for 
   severity purposes — client-side controls are never trusted as mitigating.

═══════════════════════════════════
STAGE 3 — SEVERITY & CONFIDENCE MATRIX
═══════════════════════════════════
Rate each correlated hypothesis on two independent axes:

IMPACT (what happens if true):
- CRITICAL: auth bypass, full IDOR chain to sensitive data, RCE-class injection
- HIGH: single-layer confirmed injection/IDOR, privilege escalation path
- MEDIUM: exploitable only under additional unconfirmed conditions
- LOW: defense-in-depth gap with no direct exploitation path evident

CONFIDENCE (how well-evidenced the correlation is):
- CONFIRMED: UI surface AND backend weakness both present with a clean 
  entity match
- LIKELY: strong entity match but one side inferred rather than directly 
  observed (e.g., backend shows raw SQL but the exact reachable DOM field 
  is ambiguous among candidates)
- SPECULATIVE: root cause plausible but entity resolution unresolved

Only CONFIRMED and LIKELY hypotheses are emitted. SPECULATIVE findings are 
dropped per Stage 4.

═══════════════════════════════════
STAGE 4 — FALSE POSITIVE FILTERING
═══════════════════════════════════
- Omit any finding with no reachable UI entry point AND no externally 
  callable route (dead code, internal-only utilities).
- Omit theoretical code weaknesses that both analyzers only speculate about 
  without an evidenced trigger path.
- Omit findings whose only DOM support is a disabled/hidden element that 
  Stage 1 cannot tie to a real reachable route.

═══════════════════════════════════
STAGE 5 — REMEDIATION PRIMING
═══════════════════════════════════
Every emitted hypothesis must carry enough targeting detail that neither the 
active verification node nor the patch node needs to re-investigate:
- Exact frontend element (selector/label/testid + form action or param name)
- Exact backend reference (file path + function/route name + line number if 
  available)
- Ordered chain_steps if multi-hop
- Suggested verification technique category (e.g., "authorization boundary 
  test," "parameterization check") — not a payload or exploit script

═══════════════════════════════════
OUTPUT CONTRACT
═══════════════════════════════════
- Output ONLY valid JSON matching the provided schema (CorrelatedHypothesis[]).
- No markdown, narration, or caveats outside the JSON payload.
- Each entry: [id] [root_cause] [chain_steps] [frontend_reference] 
  [backend_reference] [impact] [confidence] [verification_technique].
- Never generate exploit scripts, payloads, or working attack code — output 
  correlated hypotheses and precise targeting information only.
- If a finding cannot be resolved to CONFIRMED or LIKELY confidence, omit 
  it silently rather than including it as speculative.
"""
    human_prompt = """<FRONTEND_ANALYSIS>
{frontend_findings}
</FRONTEND_ANALYSIS>

<CODEBASE_ANALYSIS>
{codebase_findings}
</CODEBASE_ANALYSIS>

Correlate, deduplicate, and reconcile the findings above into a unified array of Prioritized Attack Hypotheses."""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", human_prompt)
    ])

    llm = ChatOpenAI(model="gpt-4.1-mini", temperature=0.0)
    chain = prompt | llm.with_structured_output(TriageReport)
    report: TriageReport = await chain.ainvoke({
        "frontend_findings": frontend_str,
        "codebase_findings": codebase_str
    })
    cleaned_errors = [h.model_dump_json() for h in report.prioritized_hypotheses]

    return {
        "cleaned_errors": cleaned_errors,
    }