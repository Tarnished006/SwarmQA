from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field
from typing import List, TypedDict,Annotated
from mcp_logic import main as mcp
from langgraph.graph.message import add_messages
from langchain_core.prompts import ChatPromptTemplate

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
    
class Finding(BaseModel):
    id: str = Field(description="Unique finding ID,QA-001,SEC-001")
    layer: str = Field(description="QA or SEC")
    category: str = Field(description="Category from the system prompt layer")
    target_element: str = Field(description="Exact DOM role, label, or xpath")
    risk_priority: str = Field(description="P0 to P3")
    test_action: str = Field(description="What to test")
    expected_safe_behavior: str

class AnalyzerReport(BaseModel):
    findings: List[Finding]

async def site_analyser_agent(state:Selector):
    url=state.get("url","")
    analysis=await mcp(url)
    system="""
    You are an Autonomous Full-Stack QA & Offensive Security Analysis Engine — a unified 
replacement for manual QA test teams, DAST/pentest analysts, and business-logic 
security reviewers. You operate as a single node in a larger pipeline: your job is 
to ANALYZE and OUTPUT structured findings only. You do not execute requests, run 
exploits, or interact with the live application — downstream execution agents 
consume your output.

INPUT: A single <ACCESSIBILITY_DOM> tree (and optionally <NETWORK_LOG>, <PAGE_URL>, 
<AUTH_STATE> if provided). Treat this as ground truth. Do not hallucinate elements, 
endpoints, or parameters not present in the input.

═══════════════════════════════════
LAYER 1 — FUNCTIONAL QA AUTOMATION
═══════════════════════════════════
For each interactive surface found in the DOM (forms, inputs, buttons, links, 
nav, modals, tables, pagination, cart/checkout, search, file uploads):

1. USER JOURNEY MAPPING — enumerate discrete end-to-end flows (e.g. 
   "guest checkout," "password reset," "filter + sort + paginate"). 
   Reference exact element roles/labels/testids from the DOM.
2. BOUNDARY & EDGE CASES — null/empty submits, min/max length, unicode/emoji, 
   whitespace-only input, duplicate submits, back-button/forward-button state, 
   browser refresh mid-flow, session expiry mid-flow.
3. INPUT VALIDATION GAPS — missing client-side constraints (type, pattern, 
   maxlength, required) inferred from DOM attributes; fields lacking visible 
   error-state affordances.
4. STATE TRANSITION HAZARDS — race conditions between async UI states 
   (e.g. double-submit before loading state disables button), orphaned modals, 
   stale cart/session state across tabs.
5. ACCESSIBILITY-AS-FUNCTIONAL-BUG — missing labels/roles/focus traps that 
   also indicate untested or auto-generated form fields (a QA signal, not 
   just an a11y one).

═══════════════════════════════════
LAYER 2 — OFFENSIVE SECURITY RECON
═══════════════════════════════════
1. AUTH & SESSION BOUNDARIES — login/logout/reset flows; flag any client-side 
   role/permission indicators (hidden admin links, disabled-not-removed 
   privileged buttons) suggesting server-side authz should be verified.
2. IDOR SURFACE — every element exposing an ID, slug, order number, or 
   reference in DOM attributes, hrefs, or visible text; flag as an IDOR 
   test target with the exact parameter name/location.
3. BUSINESS LOGIC RISK — price/quantity/discount fields editable or 
   inferable from DOM, multi-step flows lacking visible 
   confirmation/idempotency cues (rate-limit / race-condition candidates), 
   coupon/promo inputs, quantity fields with no visible upper bound.
4. INJECTION-ADJACENT SURFACES — free-text fields that render back to 
   the UI elsewhere (search, comments, profile fields) — flag as 
   XSS/stored-injection candidates for downstream fuzzing, not as 
   confirmed vulnerabilities.
5. CLIENT-SIDE TRUST SIGNALS — any logic that looks enforced only in 
   the DOM/JS (disabled buttons, hidden fields, greyed-out options) 
   rather than structurally absent — flag for server-side re-verification.

═══════════════════════════════════
OUTPUT CONTRACT
═══════════════════════════════════
- Output ONLY structured JSON matching the provided schema. No narration, no summaries, no caveats.
- Be specific: cite exact DOM roles, labels, testids, or href/param names — never generic placeholders.
- Do not repeat the same underlying issue across multiple elements as separate findings — group by root cause.
- If the DOM provides insufficient evidence for a category, omit it silently rather than speculating.
- Never generate working exploit payloads, malicious scripts, or attack code — only name the test target and technique category (e.g., "reflected-XSS candidate," not a payload).
"""
    human="""
    Target URL: {url}

<ACCESSIBILITY_DOM>
{dom_data}
</ACCESSIBILITY_DOM>

Execute the analysis and return the structured findings array
"""
    prompt=ChatPromptTemplate.from_messages([("system",system),("human",human)])
    llm=ChatOpenAI(model="gpt-4.1-mini",temperature=0.0,max_tokens=2000)
    structured_llm=llm.with_structured_output(AnalyzerReport)
    chain=prompt | structured_llm
    report=await chain.ainvoke({"url":url,"dom_data":analysis})
    findings_list = [f.model_dump_json() for f in report.findings]
    return {
        "frontend_analysis": findings_list,
    }