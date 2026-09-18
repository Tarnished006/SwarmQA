import os
import asyncio
from typing import Annotated, TypedDict, List, Optional, Literal, Dict, Any
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

from site_analysing_agent import site_analyser_agent
from codebase_agent import codebase_checker
from triage_agent import triage_agent
from active_test_agent import active_tester_agent
from patch_agent import fixing_agent
from checking_agent import checker_agent, sandbox_execution_node
from deploy_agent import deploy_agent

load_dotenv()

# ── SHARED STATE DEFINITION ───────────────────────────────────
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
    # Set by deploy_agent after gatekeeper clears READY_FOR_DEPLOYMENT
    deployment_status: Optional[str]   # DEPLOYED_AND_LIVE | DEPLOYMENT_FAILED | SKIPPED
    deployment_url: Optional[str]

class SupervisorDecision(BaseModel):
    next_node: Literal["Recon_Team", "Red_Team", "Blue_Team", "Deploy_Gate", "FINISH"] = Field(
        description="The next specialized team to route the task to, or FINISH if the pipeline is secure."
    )
    reasoning: str


def get_supervisor_llm() -> ChatOpenAI:
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
    )


async def aegis_supervisor(state: Selector) -> dict:
    """
    Supervisor router with deterministic fast-path (0 tokens) and LLM fallback.
    """
    v_status = state.get("verification_status", "PENDING")
    deploy_status = state.get("deployment_status")
    has_cleaned = bool(state.get("cleaned_errors"))
    has_exploits = bool(state.get("active_debugger"))

    # ── Fast Deterministic Routing ($0 tokens) ────────────────
    # 1. Already deployed or deployment completed/failed
    if deploy_status in ("DEPLOYED_AND_LIVE", "DEPLOYMENT_FAILED", "SKIPPED"):
        return {"next": "FINISH"}

    # 2. Clean bill of health or gate blocked/manual review
    if v_status in ("NO_EXPLOITS_CONFIRMED", "BLOCKED", "PARTIAL_WITH_REVIEW"):
        return {"next": "FINISH"}

    # 3. Verified secure: hand off to Deploy_Gate
    if v_status == "READY_FOR_DEPLOYMENT":
        return {"next": "Deploy_Gate"}

    # 4. Recon needed
    if not has_cleaned:
        return {"next": "Recon_Team"}

    # 5. Red Team active probing
    if has_cleaned and not has_exploits and v_status == "PENDING":
        return {"next": "Red_Team"}

    # 6. Blue Team patch and verification
    if has_exploits and v_status == "PENDING":
        return {"next": "Blue_Team"}

    # ── LLM Routing Fallback (for complex/ambiguous states) ────
    system_prompt = """You are the Aegis DevSecOps Supervisor. Route work dynamically based on state:
    1. Empty `cleaned_errors` -> Route to Recon_Team.
    2. Has `cleaned_errors` but empty `active_debugger` -> Route to Red_Team.
    3. Has `active_debugger` but `verification_status` is PENDING -> Route to Blue_Team.
    4. `verification_status` is READY_FOR_DEPLOYMENT -> Route to Deploy_Gate.
    5. `verification_status` is BLOCKED, PARTIAL_WITH_REVIEW, or NO_EXPLOITS_CONFIRMED -> Route to FINISH.
    """
    human_prompt = f"""
    Current State:
    - Recon Done: {has_cleaned}
    - Exploits Verified: {has_exploits}
    - Verification Status: {v_status}
    - Deployment Status: {deploy_status}
    Who acts next?
    """
    prompt = ChatPromptTemplate.from_messages([("system", system_prompt), ("human", human_prompt)])
    try:
        llm = get_supervisor_llm()
        chain = prompt | llm.with_structured_output(SupervisorDecision)
        decision = await chain.ainvoke({})
        return {"next": decision.next_node}
    except Exception:
        return {"next": "FINISH"}

recon_graph_builder = StateGraph(Selector)
recon_graph_builder.add_node("site_analyser_agent", site_analyser_agent)
recon_graph_builder.add_node("codebase_checker", codebase_checker)
recon_graph_builder.add_node("triage_agent", triage_agent)

recon_graph_builder.add_edge(START, "site_analyser_agent")
recon_graph_builder.add_edge("site_analyser_agent", "codebase_checker")
recon_graph_builder.add_edge("codebase_checker", "triage_agent")
recon_graph_builder.add_edge("triage_agent", END)
recon_team = recon_graph_builder.compile()

# Build Red Team Subgraph
red_graph_builder = StateGraph(Selector)
red_graph_builder.add_node("active_tester_agent", active_tester_agent)
red_graph_builder.add_edge(START, "active_tester_agent")
red_graph_builder.add_edge("active_tester_agent", END)
red_team = red_graph_builder.compile()

# Build Blue Team Subgraph
blue_graph_builder = StateGraph(Selector)
blue_graph_builder.add_node("fixing_agent", fixing_agent)
blue_graph_builder.add_node("sandbox_execution_node", sandbox_execution_node)
blue_graph_builder.add_node("checker_agent", checker_agent)

blue_graph_builder.add_edge(START, "fixing_agent")
blue_graph_builder.add_edge("fixing_agent", "sandbox_execution_node")
blue_graph_builder.add_edge("sandbox_execution_node", "checker_agent")
blue_graph_builder.add_edge("checker_agent", END)
blue_team = blue_graph_builder.compile()

# Build Main Supervisor Graph
workflow = StateGraph(Selector)
workflow.add_node("Supervisor", aegis_supervisor)
workflow.add_node("Recon_Team", recon_team)
workflow.add_node("Red_Team", red_team)
workflow.add_node("Blue_Team", blue_team)
workflow.add_node("Deploy_Gate", deploy_agent)

# The entry point is always the Supervisor
workflow.add_edge(START, "Supervisor")

# Conditional Router based on the 'next' key returned by Supervisor
workflow.add_conditional_edges(
    "Supervisor",
    lambda state: state["next"],
    {
        "Recon_Team": "Recon_Team",
        "Red_Team": "Red_Team",
        "Blue_Team": "Blue_Team",
        "Deploy_Gate": "Deploy_Gate",
        "FINISH": END
    }
)
workflow.add_edge("Recon_Team", "Supervisor")
workflow.add_edge("Red_Team", "Supervisor")
workflow.add_edge("Blue_Team", "Supervisor")
workflow.add_edge("Deploy_Gate", END)

aegis_app = workflow.compile()