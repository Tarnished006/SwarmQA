import os
import asyncio
from langgraph.graph import StateGraph,START,END
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv
from typing import Annotated, TypedDict, List, Optional,Literal,List,Dict,Any
from langgraph.graph.message import add_messages
from checking_agent import checker_agent, sandbox_execution_node
from mcp_logic import main as mcp
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field
import io
import re
import tarfile
import docker
from urllib.parse import urlparse
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain_core.tools import tool
import json
import tempfile
import shutil
from patch_agent import fixing_agent
from site_analysing_agent import site_analyser_agent
from codebase_agent import codebase_checker
from triage_agent import triage_agent
from active_test_agent import active_tester_agent

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
# ── 5. THE MULTI-AGENT SUPERVISOR ────────────────────────────────
class SupervisorDecision(BaseModel):
    next_node: Literal["Recon_Team", "Red_Team", "Blue_Team", "FINISH"] = Field(
        description="The next specialized team to route the task to, or FINISH if the pipeline is secure."
    )
    reasoning: str

async def aegis_supervisor(state: Selector) -> dict:
    system_prompt = """You are the Aegis DevSecOps Supervisor. Route work dynamically based on state:
    1. Empty `cleaned_errors` -> Route to Recon_Team.
    2. Has `cleaned_errors` but empty `active_debugger` -> Route to Red_Team.
    3. Has `active_debugger` but `verification_status` is not READY_FOR_DEPLOYMENT -> Route to Blue_Team.
    4. `verification_status` is READY_FOR_DEPLOYMENT or NO_EXPLOITS_CONFIRMED -> Route to FINISH.
    """
    human_prompt = f"""
    Current State:
    - Recon Done: {bool(state.get("cleaned_errors"))}
    - Exploits Verified: {bool(state.get("active_debugger"))}
    - Verification Status: {state.get("verification_status", "PENDING")}
    Who acts next?
    """
    prompt = ChatPromptTemplate.from_messages([("system", system_prompt), ("human", human_prompt)])
    llm = ChatOpenAI(model="gpt-4.1-mini", temperature=0.0) 
    chain = prompt | llm.with_structured_output(SupervisorDecision)
    decision = await chain.ainvoke({})
    
    # Update the routing state
    return {"next": decision.next_node}

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
        "FINISH": END
    }
)
workflow.add_edge("Recon_Team", "Supervisor")
workflow.add_edge("Red_Team", "Supervisor")
workflow.add_edge("Blue_Team", "Supervisor")

aegis_app = workflow.compile()