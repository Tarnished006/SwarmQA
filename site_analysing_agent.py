import os
import re
import asyncio
import ipaddress
import logging
from html.parser import HTMLParser
from urllib.parse import urlparse
from typing import List, Literal, TypedDict, Annotated, Optional
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph.message import add_messages
from mcp_logic import main as mcp

logger = logging.getLogger(__name__)

# ── SCHEMAS ───────────────────────────────────────────────────
class Selector(TypedDict):
    messages: Annotated[List, add_messages]
    url: str
    frontend_analysis: List[str]
    codebase_analysis: List[str]
    active_debugger: List[str]
    proposed_patch: List[str]
    verification_status: str
    codebase_path: List[str]
    git_diff: Optional[str]        # Transport field for raw git diff
    cleaned_errors: List[str]
    remediation_plan: List[str]
    test_results: List[str]
    verification_report: List[str]
    next: str

class Finding(BaseModel):
    id: str = Field(description="Unique finding ID, e.g., QA-001, SEC-001")
    layer: Literal["QA", "SEC"] = Field(description="QA or SEC")
    category: str = Field(description="Category from the system prompt layer")
    target_element: str = Field(description="Exact DOM role, label, or xpath")
    risk_priority: Literal["P0", "P1", "P2", "P3"] = Field(description="P0 to P3")
    test_action: str = Field(description="What to test")
    expected_safe_behavior: str

class AnalyzerReport(BaseModel):
    findings: List[Finding]

# ── FAST-PASS: FRONTEND-RELEVANT FILE DETECTION ───────────────
FRONTEND_EXTENSIONS = {
    ".html", ".htm", ".css", ".scss", ".sass", ".less", ".styl",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".vue", ".svelte", ".astro",
    ".json",
    ".ejs", ".jinja", ".jinja2", ".hbs", ".handlebars", ".mustache",
    ".pug", ".jade", ".twig", ".erb", ".liquid", ".mdx",
}

# ── URL SAFETY GUARD ───────────────────────────────────────────
BLOCKED_HOSTNAMES = {"localhost", "metadata.google.internal"}

def _is_url_safe_to_fetch(url: str) -> bool:
    """
    Basic guardrail before handing an externally-influenced URL to the scraper.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False
        
    if parsed.scheme not in {"http", "https"}:
        return False
        
    hostname = (parsed.hostname or "").lower()
    if not hostname or hostname in BLOCKED_HOSTNAMES:
        return False
        
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    except ValueError:
        pass  # hostname, not a literal IP
        
    return True

# ── DOM OPTIMIZATION & TOKEN COMPRESSION ──────────────────────
MAX_DOM_CHARS = 40_000
MAX_ATTR_VALUE_LEN = 300
SKIP_SUBTREE_TAGS = {"script", "style", "svg", "noscript"}
STRIP_ATTR_KEYS = {"style"}

class _DomCleaner(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: List[str] = []
        self._skip_depth = 0
        self._skip_tag: Optional[str] = None

    def _render_attrs(self, attrs) -> str:
        parts = []
        for key, value in attrs:
            if key is None or key.lower() in STRIP_ATTR_KEYS:
                continue
            if value is None:
                parts.append(f" {key}")
                continue
            if len(value) > MAX_ATTR_VALUE_LEN:
                value = value[:MAX_ATTR_VALUE_LEN] + "...[TRUNCATED]"
            parts.append(f' {key}="{value}"')
        return "".join(parts)

    def handle_starttag(self, tag, attrs):
        if self._skip_depth > 0:
            if tag == self._skip_tag:
                self._skip_depth += 1
            return
        if tag in SKIP_SUBTREE_TAGS:
            self._skip_depth, self._skip_tag = 1, tag
            return
        self.out.append(f"<{tag}{self._render_attrs(attrs)}>")

    def handle_startendtag(self, tag, attrs):
        if self._skip_depth > 0:
            return
        if tag in SKIP_SUBTREE_TAGS:
            return
        self.out.append(f"<{tag}{self._render_attrs(attrs)}/>")

    def handle_endtag(self, tag):
        if self._skip_depth > 0:
            if tag == self._skip_tag:
                self._skip_depth -= 1
                if self._skip_depth == 0:
                    self._skip_tag = None
            return
        self.out.append(f"</{tag}>")

    def handle_data(self, data):
        if self._skip_depth > 0:
            return
        text = data.strip()
        if text:
            self.out.append(text)

    def handle_comment(self, data):
        pass

def _clean_via_parser(raw_dom: str) -> Optional[str]:
    try:
        cleaner = _DomCleaner()
        cleaner.feed(raw_dom)
        cleaner.close()
        return "\n".join(cleaner.out)
    except Exception:
        return None

def _clean_via_regex_fallback(raw_dom: str) -> str:
    cleaned = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', raw_dom, flags=re.IGNORECASE)
    cleaned = re.sub(r'<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>', '', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'<svg\b[^<]*(?:(?!<\/svg>)<[^<]*)*<\/svg>', '[SVG_ICON]', cleaned, flags=re.IGNORECASE)
    return cleaned

def clean_dom_for_llm(raw_dom: str, max_chars: int = MAX_DOM_CHARS) -> str:
    if not raw_dom:
        return ""
        
    cleaned = _clean_via_parser(raw_dom)
    if cleaned is None:
        logger.warning("[Site Analyser] DOM parser failed, using regex fallback.")
        cleaned = _clean_via_regex_fallback(raw_dom)
        
    cleaned = re.sub(r'data:image\/[^;]+;base64,[a-zA-Z0-9+/=]+', '[BASE64_IMAGE]', cleaned)
    cleaned = re.sub(r'\n\s*\n', '\n', cleaned)
    
    if len(cleaned) > max_chars:
        logger.info("DOM size exceeded limit. Truncating to %d chars.", max_chars)
        cutoff = cleaned.rfind(">", 0, max_chars)
        cutoff = cutoff + 1 if cutoff != -1 and cutoff > max_chars * 0.5 else max_chars
        return cleaned[:cutoff] + "\n\n<TRUNCATED reason='token_budget_exceeded'/>"
        
    return cleaned

# ── MAIN AGENT NODE ───────────────────────────────────────────
MCP_SCRAPE_TIMEOUT_SECONDS = 30

async def site_analyser_agent(state: Selector):
    url = state.get("url", "")
    if not url:
        return {"frontend_analysis": ["No target URL provided."]}
        
    if not _is_url_safe_to_fetch(url):
        logger.warning("[Site Analyser] Refusing to fetch disallowed URL: %s", url)
        return {"frontend_analysis": ["Target URL failed safety validation."]}

    # 1. SMART TRIGGER (FAST-PASS)
    raw_diff = state.get("git_diff")
    if raw_diff and raw_diff.strip():
        modified_files = re.findall(r"diff --git a/(.*?) b/", raw_diff)
        has_frontend_changes = any(
            os.path.splitext(f)[1].lower() in FRONTEND_EXTENSIONS for f in modified_files
        )
        if modified_files and not has_frontend_changes:
            logger.info("[Site Analyser] Non-frontend diff detected. Fast-pass exit ($0 tokens spent).")
            return {"frontend_analysis": []}

    # 2. RUN HEADLESS SCRAPE (MCP) & CLEAN ACCESSIBILITY TREE
    try:
        raw_analysis = await asyncio.wait_for(mcp(url), timeout=MCP_SCRAPE_TIMEOUT_SECONDS)
        cleaned_dom = clean_dom_for_llm(raw_analysis)
    except asyncio.TimeoutError:
        logger.error("[Site Analyser Error] MCP scrape timed out after %ds for URL %s", MCP_SCRAPE_TIMEOUT_SECONDS, url)
        return {"frontend_analysis": []}
    except Exception as e:
        logger.error("[Site Analyser Error] MCP scraping failed for URL %s: %s", url, e)
        return {"frontend_analysis": []}

    if not cleaned_dom.strip():
        return {"frontend_analysis": []}

    # 3. LLM ANALYSIS PROMPT
    system = """
    You are an Autonomous Full-Stack QA & Offensive Security Analysis Engine — a unified replacement for manual QA test teams, DAST/pentest analysts, and business-logic security reviewers. You operate as a single node in a larger pipeline: your job is to ANALYZE and OUTPUT structured findings only. You do not execute requests, run exploits, or interact with the live application — downstream execution agents consume your output.

INPUT: A single <ACCESSIBILITY_DOM> tree (and optionally <NETWORK_LOG>, <PAGE_URL>, <AUTH_STATE> if provided). Treat this as ground truth. Do not hallucinate elements, endpoints, or parameters not present in the input.

═══════════════════════════════════
LAYER 1 — FUNCTIONAL QA AUTOMATION
═══════════════════════════════════
For each interactive surface found in the DOM (forms, inputs, buttons, links, nav, modals, tables, pagination, cart/checkout, search, file uploads):
1. USER JOURNEY MAPPING — enumerate discrete end-to-end flows (e.g. "guest checkout," "password reset," "filter + sort + paginate"). Reference exact element roles/labels/testids from the DOM.
2. BOUNDARY & EDGE CASES — null/empty submits, min/max length, unicode/emoji, whitespace-only input, duplicate submits, back-button/forward-button state, browser refresh mid-flow, session expiry mid-flow.
3. INPUT VALIDATION GAPS — missing client-side constraints (type, pattern, maxlength, required) inferred from DOM attributes; fields lacking visible error-state affordances.
4. STATE TRANSITION HAZARDS — race conditions between async UI states (e.g. double-submit before loading state disables button), orphaned modals, stale cart/session state across tabs.
5. ACCESSIBILITY-AS-FUNCTIONAL-BUG — missing labels/roles/focus traps that also indicate untested or auto-generated form fields (a QA signal, not just an a11y one).

═══════════════════════════════════
LAYER 2 — OFFENSIVE SECURITY RECON
═══════════════════════════════════
1. AUTH & SESSION BOUNDARIES — login/logout/reset flows; flag any client-side role/permission indicators (hidden admin links, disabled-not-removed privileged buttons) suggesting server-side authz should be verified.
2. IDOR SURFACE — every element exposing an ID, slug, order number, or reference in DOM attributes, hrefs, or visible text; flag as an IDOR test target with the exact parameter name/location.
3. BUSINESS LOGIC RISK — price/quantity/discount fields editable or inferable from DOM, multi-step flows lacking visible confirmation/idempotency cues (rate-limit / race-condition candidates), coupon/promo inputs, quantity fields with no visible upper bound.
4. INJECTION-ADJACENT SURFACES — free-text fields that render back to the UI elsewhere (search, comments, profile fields) — flag as XSS/stored-injection candidates for downstream fuzzing, not as confirmed vulnerabilities.
5. CLIENT-SIDE TRUST SIGNALS — any logic that looks enforced only in the DOM/JS (disabled buttons, hidden fields, greyed-out options, inline event handlers referencing privileged-looking function names) rather than structurally absent — flag for server-side re-verification.

═══════════════════════════════════
OUTPUT CONTRACT
═══════════════════════════════════
- Output ONLY structured JSON matching the provided schema. No narration, no summaries, no caveats.
- Be specific: cite exact DOM roles, labels, testids, or href/param names — never generic placeholders.
- Do not repeat the same underlying issue across multiple elements as separate findings — group by root cause.
- If the DOM provides insufficient evidence for a category, omit it silently rather than speculating.
- Never generate working exploit payloads, malicious scripts, or attack code — only name the test target and technique category (e.g., "reflected-XSS candidate," not a payload).
"""
    human = """
    Target URL: {url}

<ACCESSIBILITY_DOM>
{dom_data}
</ACCESSIBILITY_DOM>

Execute the analysis and return the structured findings array.
"""
    prompt = ChatPromptTemplate.from_messages([("system", system), ("human", human)])
    llm = ChatOpenAI(model="gpt-4.1-mini", temperature=0.0, max_tokens=3500)
    structured_llm = llm.with_structured_output(AnalyzerReport)
    chain = prompt | structured_llm
    
    try:
        report = await chain.ainvoke({"url": url, "dom_data": cleaned_dom})
        findings_list = [f.model_dump_json() for f in report.findings]
        return {"frontend_analysis": findings_list}
    except Exception as e:
        logger.error("[Site Analyser Error] Structured LLM generation failed: %s", e)
        return {"frontend_analysis": []}