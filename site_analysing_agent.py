import os
import re
import json
import asyncio
import ipaddress
import logging
from html.parser import HTMLParser
from urllib.parse import urlparse
from typing import List, Literal, TypedDict, Annotated, Optional, Dict, Any
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph.message import add_messages
from dotenv import load_dotenv
from mcp_logic import main as mcp

load_dotenv()

logger = logging.getLogger("aegis.site_analyser")
logging.basicConfig(level=logging.INFO)

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
    git_diff: Optional[str]
    cleaned_errors: List[str]
    remediation_plan: List[str]
    test_results: List[str]
    verification_report: List[str]
    next: str

class Finding(BaseModel):
    id: str = Field(description="Unique finding ID, e.g., QA-001, SEC-001")
    layer: Literal["QA", "SEC"] = Field(description="QA (Functional/boundary) or SEC (Security/offensive)")
    category: str = Field(description="Category, e.g., AUTH, IDOR, INJECTION, INPUT_VALIDATION, BUSINESS_LOGIC")
    target_element: str = Field(description="Exact DOM role, tag, or label, e.g., 'Search input [name=q]'")
    target_url_or_path: Optional[str] = Field(default=None, description="Action URL or link path, e.g., '/api/v1/search'")
    param_name: Optional[str] = Field(default=None, description="Form input or query parameter name, e.g., 'q', 'id'")
    http_method: Optional[str] = Field(default=None, description="HTTP method if applicable: GET, POST, PUT, DELETE")
    risk_priority: Literal["P0", "P1", "P2", "P3"] = Field(description="P0 (Critical) to P3 (Low)")
    test_action: str = Field(description="Exact test or fuzz action to verify this surface")
    expected_safe_behavior: str = Field(description="Safe expected application behavior")

class AnalyzerReport(BaseModel):
    findings: List[Finding] = Field(default_factory=list)


# ── CONFIGURATION & MODEL FACTORY ─────────────────────────────
ALLOW_LOCAL_TARGETS = os.getenv("ALLOW_LOCAL_TARGETS", "true").lower() in ("true", "1", "yes")

CLOUD_METADATA_HOSTS = {
    "metadata.google.internal",
    "169.254.169.254",      # AWS / Azure / GCP link-local metadata
    "fd00:ec2::254",        # AWS IPv6 metadata
}

FRONTEND_EXTENSIONS = {
    ".html", ".htm", ".css", ".scss", ".sass", ".less",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".vue", ".svelte", ".astro", ".json",
    ".ejs", ".jinja", ".jinja2", ".hbs", ".mustache", ".pug"
}

def get_analyser_llm():
    """
    Unified, fail-safe OpenAI-compatible model loader.
    Reads standard environment variables:
    - OPENAI_API_KEY: API key (Groq, OpenAI, DeepSeek, etc.)
    - OPENAI_BASE_URL: Endpoint URL (optional, e.g. for Groq, Ollama, DeepSeek)
    - OPENAI_MODEL: Model identifier (defaults to gpt-4o-mini)
    """
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("GROQ_API_KEY") or os.getenv("DEEPSEEK_API_KEY")
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
        max_tokens=2000
    )


# ── URL SAFETY GUARD ───────────────────────────────────────────
def _is_url_safe_to_fetch(url: str) -> bool:
    """
    Guards against SSRF while allowing legitimate local test environments.
    """
    if not url or not isinstance(url, str):
        return False
        
    try:
        parsed = urlparse(url.strip())
    except Exception:
        return False

    if parsed.scheme not in {"http", "https"}:
        return False

    hostname = (parsed.hostname or "").lower()
    if not hostname or hostname in CLOUD_METADATA_HOSTS:
        return False

    # Check if literal IP
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_multicast or ip.is_reserved:
            return False
        if not ALLOW_LOCAL_TARGETS:
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
    except ValueError:
        # Hostname string (not literal IP)
        if not ALLOW_LOCAL_TARGETS and hostname in {"localhost"}:
            return False

    return True


# ── INTERACTIVE SURFACE EXTRACTOR (TOKEN OPTIMIZER) ───────────
class _InteractiveSurfaceExtractor(HTMLParser):
    """
    Slashes token consumption by 80-90%.
    Extracts ONLY security and QA relevant attack surfaces:
    - Forms (action, method, enctype)
    - Inputs (name, type, pattern, required, min, max, value for state/hidden)
    - Buttons & Dropdowns
    - Actionable links (with query parameters or API/admin routes)
    - Meta CSRF tokens
    """
    INTERESTING_PATH_KEYWORDS = {
        "api", "admin", "login", "logout", "auth", "user", "order",
        "edit", "delete", "token", "search", "upload", "download", "pay"
    }
    SKIP_TAGS = {"script", "style", "svg", "noscript", "iframe"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.surfaces: List[str] = []
        self.meta_tags: List[str] = []
        self.current_form: Optional[Dict[str, Any]] = None
        self.current_tag: Optional[str] = None
        self.current_button_attrs: Dict[str, str] = {}
        self.current_button_text: List[str] = []
        self.skip_depth: int = 0

    def handle_starttag(self, tag: str, attrs: list):
        tag = tag.lower()
        attr_dict = {k.lower(): (v or "") for k, v in attrs if k}

        if tag in self.SKIP_TAGS:
            self.skip_depth += 1
            return
        if self.skip_depth > 0:
            return

        # 1. Meta CSRF / Tokens
        if tag == "meta":
            name = attr_dict.get("name") or attr_dict.get("property") or ""
            content = attr_dict.get("content") or ""
            if any(k in name.lower() for k in ("csrf", "token", "auth")):
                self.meta_tags.append(f"<META name='{name}' content='{content[:100]}'/>")
            return

        # 2. Forms
        if tag == "form":
            action = attr_dict.get("action", "")
            method = attr_dict.get("method", "GET").upper()
            form_id = attr_dict.get("id") or attr_dict.get("name") or "unnamed_form"
            self.current_form = {
                "header": f"<FORM id='{form_id}' action='{action}' method='{method}'>",
                "elements": [],
                "footer": "</FORM>"
            }
            return

        # 3. Inputs
        if tag == "input":
            input_type = attr_dict.get("type", "text").lower()
            name = attr_dict.get("name") or attr_dict.get("id") or "unnamed_input"
            required = " required='true'" if "required" in attr_dict else ""
            pattern = f" pattern='{attr_dict['pattern']}'" if "pattern" in attr_dict else ""
            
            val = ""
            if input_type in ("hidden", "checkbox", "radio") or any(k in name.lower() for k in ("csrf", "token", "id")):
                val_content = attr_dict.get("value", "")[:100]
                val = f" value='{val_content}'"

            elem_str = f"  <INPUT type='{input_type}' name='{name}'{val}{required}{pattern}/>"
            if self.current_form:
                self.current_form["elements"].append(elem_str)
            else:
                self.surfaces.append(elem_str.strip())
            return

        # 4. Textarea & Select
        if tag in ("textarea", "select"):
            name = attr_dict.get("name") or attr_dict.get("id") or f"unnamed_{tag}"
            elem_str = f"  <{tag.upper()} name='{name}'/>"
            if self.current_form:
                self.current_form["elements"].append(elem_str)
            else:
                self.surfaces.append(elem_str.strip())
            return

        # 5. Buttons
        if tag == "button":
            self.current_tag = "button"
            self.current_button_attrs = attr_dict
            self.current_button_text = []
            return

        # 6. Actionable Links
        if tag == "a":
            href = attr_dict.get("href", "")
            if href and not href.startswith("#") and not href.startswith("javascript:"):
                parsed = urlparse(href)
                has_params = bool(parsed.query)
                path_lower = parsed.path.lower()
                is_sensitive = any(kw in path_lower for kw in self.INTERESTING_PATH_KEYWORDS)
                if has_params or is_sensitive:
                    self.surfaces.append(f"<ACTIONABLE_LINK href='{href}'/>")

    def handle_endtag(self, tag: str):
        tag = tag.lower()
        if tag in self.SKIP_TAGS and self.skip_depth > 0:
            self.skip_depth -= 1
            return

        if tag == "form" and self.current_form:
            form_lines = [self.current_form["header"]] + self.current_form["elements"] + [self.current_form["footer"]]
            self.surfaces.append("\n".join(form_lines))
            self.current_form = None

        if tag == "button" and self.current_tag == "button":
            text = "".join(self.current_button_text).strip()[:40]
            b_type = self.current_button_attrs.get("type", "submit")
            b_name = self.current_button_attrs.get("name", "")
            btn_str = f"  <BUTTON type='{b_type}' name='{b_name}'>{text}</BUTTON>"
            if self.current_form:
                self.current_form["elements"].append(btn_str)
            else:
                self.surfaces.append(btn_str.strip())
            self.current_tag = None
            self.current_button_text = []

    def handle_data(self, data: str):
        if self.current_tag == "button":
            self.current_button_text.append(data)


def clean_dom_for_llm(raw_dom: str, max_chars: int = 8000) -> str:
    """
    Extracts the compact interactive attack surface from raw HTML or JSON.
    Reduces 40,000 chars of HTML down to ~800 chars of pure attack surface.
    """
    if not raw_dom or not raw_dom.strip():
        return ""

    if "<ACCESSIBILITY_DOM_ERROR>" in raw_dom:
        return raw_dom

    trimmed = raw_dom.strip()
    if trimmed.startswith("{") or trimmed.startswith("["):
        try:
            data = json.loads(trimmed)
            return json.dumps(data, indent=2)[:max_chars]
        except Exception:
            pass

    try:
        extractor = _InteractiveSurfaceExtractor()
        extractor.feed(raw_dom)
        extractor.close()

        blocks = []
        if extractor.meta_tags:
            blocks.append("<SECURITY_METADATA>\n" + "\n".join(extractor.meta_tags) + "\n</SECURITY_METADATA>")
        if extractor.surfaces:
            blocks.append("<INTERACTIVE_SURFACES>\n" + "\n".join(extractor.surfaces) + "\n</INTERACTIVE_SURFACES>")

        result = "\n\n".join(blocks).strip()
        if not result:
            return "No interactive forms, inputs, or security surfaces detected on the target page."

        if len(result) > max_chars:
            return result[:max_chars] + "\n...[TRUNCATED]"
        return result

    except Exception as e:
        logger.warning("[Site Analyser] Interactive extractor error: %s. Fallback applied.", e)
        cleaned = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', raw_dom, flags=re.IGNORECASE)
        cleaned = re.sub(r'<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>', '', cleaned, flags=re.IGNORECASE)
        return cleaned[:max_chars]


# ── MAIN AGENT NODE ───────────────────────────────────────────
MCP_SCRAPE_TIMEOUT_SECONDS = 35

async def site_analyser_agent(state: Selector) -> dict:
    url = state.get("url", "")
    if not url:
        return {
            "frontend_analysis": [json.dumps({"error": "No target URL provided."})],
            "messages": ["[Site Analyser] Skipped: No target URL provided."]
        }

    if not _is_url_safe_to_fetch(url):
        logger.warning("[Site Analyser] Refusing to fetch disallowed URL: %s", url)
        return {
            "frontend_analysis": [json.dumps({"error": f"Target URL failed safety validation: {url}"})],
            "messages": [f"[Site Analyser] Security check blocked URL: {url}"]
        }

    # 1. SMART TRIGGER (FAST-PASS)
    raw_diff = state.get("git_diff")
    if raw_diff and raw_diff.strip():
        modified_files = re.findall(r"diff --git a/(.*?) b/", raw_diff)
        has_frontend_changes = any(
            os.path.splitext(f)[1].lower() in FRONTEND_EXTENSIONS for f in modified_files
        )
        if modified_files and not has_frontend_changes:
            logger.info("[Site Analyser] Non-frontend diff detected. Fast-pass exit ($0 tokens spent).")
            return {
                "frontend_analysis": [],
                "messages": ["[Site Analyser] Fast-pass exit: No frontend code changes detected in diff."]
            }

    # 2. RUN HEADLESS SCRAPE (MCP) & EXTRACT ATTACK SURFACES
    try:
        raw_analysis = await asyncio.wait_for(mcp(url), timeout=MCP_SCRAPE_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        err_msg = f"Browser crawl timed out after {MCP_SCRAPE_TIMEOUT_SECONDS}s for {url}"
        logger.error("[Site Analyser Error] %s", err_msg)
        return {
            "frontend_analysis": [json.dumps({"error": err_msg})],
            "messages": [f"[Site Analyser Error] {err_msg}"]
        }
    except Exception as e:
        err_msg = f"Browser crawl failed for {url}: {str(e)}"
        logger.error("[Site Analyser Error] %s", err_msg)
        return {
            "frontend_analysis": [json.dumps({"error": err_msg})],
            "messages": [f"[Site Analyser Error] {err_msg}"]
        }

    # 3. DETECT INTERNAL MCP CRAWLER FAILURES
    if "<ACCESSIBILITY_DOM_ERROR>" in raw_analysis:
        logger.error("[Site Analyser] Playwright MCP reported an error: %s", raw_analysis)
        return {
            "frontend_analysis": [json.dumps({"error": "Playwright scrape failed", "details": raw_analysis})],
            "messages": [f"[Site Analyser] Crawler error: {raw_analysis[:120]}"]
        }

    cleaned_surface = clean_dom_for_llm(raw_analysis)
    if not cleaned_surface or "No interactive forms" in cleaned_surface:
        logger.info("[Site Analyser] No interactive attack surfaces found on %s", url)
        return {
            "frontend_analysis": [],
            "messages": [f"[Site Analyser] No actionable interactive surfaces discovered on {url}."]
        }

    # 4. COMPACT STRUCTURED LLM ANALYSIS PROMPT
    system = """You are an Autonomous Offensive Security & QA Reconnaissance Engine.
Your task is to analyze the extracted interactive attack surfaces of a web application.
Identify the highest-priority functional validation gaps and offensive vulnerability surfaces.

Focus on:
1. AUTH & SESSION: Login/signup/password reset forms, missing CSRF tokens, role flags.
2. IDOR & BOLA: Actionable links or hidden inputs exposing record IDs, account numbers, or slugs.
3. INJECTION CANDIDATES: Search bars, comment boxes, file uploads lacking input validation or client constraints.
4. BUSINESS LOGIC RISKS: Price, quantity, or discount inputs editable in DOM with missing limits.

CONTRACT:
- Output ONLY structured findings matching the AnalyzerReport schema.
- Populate exact 'target_url_or_path', 'param_name', and 'http_method' for each finding to assist downstream backend correlation.
- Be concise and omit trivial cosmetic or minor accessibility issues. Capped at top 6 critical surfaces.
"""

    human = """Target URL: {url}

<INTERACTIVE_ATTACK_SURFACES>
{surface_data}
</INTERACTIVE_ATTACK_SURFACES>

Identify the high-risk attack surfaces and return the structured report."""

    prompt = ChatPromptTemplate.from_messages([("system", system), ("human", human)])
    
    try:
        llm = get_analyser_llm()
        structured_llm = llm.with_structured_output(AnalyzerReport)
        chain = prompt | structured_llm
        
        report: AnalyzerReport = await chain.ainvoke({
            "url": url,
            "surface_data": cleaned_surface
        })

        findings_list = [f.model_dump_json() for f in report.findings]
        logger.info("[Site Analyser] Successfully identified %d attack surfaces on %s", len(findings_list), url)

        return {
            "frontend_analysis": findings_list,
            "messages": [f"[Site Analyser] Discovered {len(findings_list)} actionable frontend attack surfaces."]
        }

    except Exception as e:
        logger.error("[Site Analyser Error] LLM generation failed: %s", e)
        return {
            "frontend_analysis": [],
            "messages": [f"[Site Analyser Error] Analysis LLM invocation failed: {str(e)}"]
        }