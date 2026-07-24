import os
import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict, Any

# Import your compiled LangGraph app from your main graph script
# Replace `your_graph_file` with the actual filename where `aegis_app` is defined
from agent import aegis_app

app = FastAPI(
    title="Project Aegis — Autonomous DevSecOps Engine",
    description="Multi-Agent Security Correlation, Exploitation & Remediation API",
    version="1.0.0"
)

# Enable CORS for future frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── REQUEST & RESPONSE SCHEMAS ────────────────────────────────
class AuditRequest(BaseModel):
    target_url: str
    codebase_path: str

class AuditResponse(BaseModel):
    status: str
    verification_status: str
    cleaned_errors_count: int
    active_debugger_count: int
    remediation_patches_count: int
    summary: Dict[str, Any]


# ── ENDPOINTS ─────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "engine": "Project Aegis",
        "status": "Online",
        "interactive_docs": "/docs"
    }


@app.post("/api/v1/run-audit", response_model=AuditResponse)
async def run_security_audit(request: AuditRequest):
    """
    Triggers the full Aegis Multi-Agent Pipeline:
    Supervisor -> Recon Team -> Red Team -> Blue Team -> Verification
    """
    if not os.path.exists(request.codebase_path):
        raise HTTPException(
            status_code=400, 
            detail=f"Codebase path '{request.codebase_path}' does not exist on the server host."
        )

    # Initial state initialization matching the `Selector` TypedDict
    initial_state = {
        "messages": [],
        "url": request.target_url,
        "frontend_analysis": [],
        "codebase_analysis": [],
        "active_debugger": [],
        "proposed_patch": [],
        "verification_status": "PENDING",
        "codebase_path": [request.codebase_path],
        "cleaned_errors": [],
        "remediation_plan": [],
        "test_results": [],
        "verification_report": [],
        "next": "Recon_Team"
    }

    try:
        
        # Invoke the multi-agent graph asynchronously
        final_state = await aegis_app.ainvoke(initial_state)

        return AuditResponse(
            status="COMPLETED",
            verification_status=final_state.get("verification_status", "UNKNOWN"),
            cleaned_errors_count=len(final_state.get("cleaned_errors", [])),
            active_debugger_count=len(final_state.get("active_debugger", [])),
            remediation_patches_count=len(final_state.get("remediation_plan", [])),
            summary={
                "verification_report": final_state.get("verification_report", []),
                "remediation_plan": final_state.get("remediation_plan", []),
                "active_debugger": final_state.get("active_debugger", [])
            }
        )

    except Exception as e:
        print(f"[Aegis Engine Error] {str(e)}")
        raise HTTPException(status_code=500, detail=f"Pipeline Execution Failed: {str(e)}")


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)