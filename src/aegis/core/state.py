"""
src/aegis/core/state.py — Shared State Schema and Models for Project Aegis.
"""
from typing import Annotated, TypedDict, List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field
from langgraph.graph.message import add_messages


class Selector(TypedDict):
    """
    Central shared state passed between all Aegis LangGraph nodes.
    """
    messages: Annotated[List, add_messages]
    url: str
    codebase_path: List[str]
    git_diff: Optional[str]
    frontend_analysis: List[str]
    codebase_analysis: List[str]
    cleaned_errors: List[str]
    active_debugger: List[str]
    proposed_patch: List[str]
    remediation_plan: List[str]
    test_results: List[str]
    verification_report: List[str]
    verification_status: str
    next: str
    deployment_status: Optional[str]
    deployment_url: Optional[str]


class SupervisorDecision(BaseModel):
    next_node: Literal["Recon_Team", "Red_Team", "Blue_Team", "Deploy_Team", "FINISH"] = Field(
        description="The next specialized team to route the task to, or FINISH if the pipeline is secure."
    )
    reasoning: str
