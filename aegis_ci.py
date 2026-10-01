"""
aegis_ci.py — Enterprise CI/CD Autonomous Security Gate for Project Aegis.

Usage in GitHub Actions or Local Pre-Push:
    python aegis_ci.py --repo . --base-ref origin/main --fail-on-critical
"""
import os
import sys
import json
import asyncio
import logging
import argparse
import subprocess
from typing import Optional, Dict, Any

try:
    from aegis.agents.supervisor import aegis_app
except ImportError:
    from agent import aegis_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("aegis.ci")


def extract_git_diff(repo_path: str, base_ref: Optional[str] = None, diff_file: Optional[str] = None) -> Optional[str]:
    """
    Extracts git diff for the current pull request or commit range.
    """
    if diff_file and os.path.isfile(diff_file):
        try:
            with open(diff_file, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
                logger.info("[CI Diff] Loaded %d chars from diff file: %s", len(content), diff_file)
                return content
        except Exception as e:
            logger.warning("[CI Diff] Could not read diff file: %s", e)

    if not base_ref:
        base_ref = "HEAD~1"

    candidates = [
        ["git", "diff", f"{base_ref}...HEAD"],
        ["git", "diff", base_ref],
        ["git", "diff", "HEAD~1"],
        ["git", "diff", "--staged"],
    ]

    for cmd in candidates:
        try:
            res = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace"
            )
            if res.returncode == 0 and res.stdout.strip():
                logger.info("[CI Diff] Successfully extracted %d chars using: %s", len(res.stdout), " ".join(cmd))
                return res.stdout
        except Exception:
            continue

    logger.info("[CI Diff] No uncommitted or branch diff detected. Proceeding with full repo scan.")
    return None


def render_github_step_summary(final_state: Dict[str, Any], output_path: Optional[str] = None) -> str:
    """
    Generates an enterprise-grade GitHub Step Summary in markdown.
    """
    v_status = final_state.get("verification_status", "UNKNOWN")
    active_debugger = final_state.get("active_debugger", [])
    remediation_plan = final_state.get("remediation_plan", [])
    cleaned_errors = final_state.get("cleaned_errors", [])
    verification_report = final_state.get("verification_report", [])

    status_badge = {
        "READY_FOR_DEPLOYMENT": "PASSED (Ready for Deployment)",
        "NO_EXPLOITS_CONFIRMED": "PASSED (No Exploits Found)",
        "BLOCKED": "FAILED (Blocked by Security Gate)",
        "PARTIAL_WITH_REVIEW": "WARNING (Requires Human Sign-Off)",
    }.get(v_status, f"STATUS: {v_status}")

    lines = [
        f"# Project Aegis Security Gate Report",
        "",
        f"**Gate Status**: `{status_badge}`",
        "",
        "### Audit Telemetry Overview",
        "| Metric | Count | Description |",
        "| :--- | :--- | :--- |",
        f"| **Correlated Findings** | `{len(cleaned_errors)}` | Frontend/Backend cross-correlated attack vectors |",
        f"| **Active Exploits / Anomalies** | `{len(active_debugger)}` | Confirmed vulnerabilities or silent behavioral anomalies |",
        f"| **Synthesized Patches** | `{len(remediation_plan)}` | Self-healing patches verified in clean-room sandbox |",
        "",
    ]

    # Active Exploits Section
    if active_debugger:
        lines.append("### Active Exploits & Critical Anomalies")
        lines.append("| ID | Type | Target | Risk / Evidence |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for item in active_debugger:
            try:
                data = json.loads(item)
                item_id = data.get("id", "EXP")
                if data.get("is_anomaly"):
                    anom_type = f"[CRITICAL ANOMALY] {data.get('anomaly_type', 'BEHAVIORAL')}"
                    target = data.get("target", "N/A")
                    evidence = data.get("risk_analysis", data.get("observed_telemetry", ""))
                else:
                    anom_type = f"[EXPLOIT] {data.get('attack_chain_stage', 'BREACH')}"
                    target = data.get("target", "N/A")
                    evidence = data.get("cause_of_breach", data.get("reproduction_evidence", ""))
                
                evidence_clean = evidence.replace("\n", " ").replace("|", "\\|")[:120]
                lines.append(f"| `{item_id}` | `{anom_type}` | `{target}` | {evidence_clean}... |")
            except Exception:
                continue
        lines.append("")

    # Remediation Plan Section
    if remediation_plan:
        lines.append("### Automated Remediation Patches")
        lines.append("| Patch ID | Target File | Blast Radius | Rollback Plan |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for item in remediation_plan:
            try:
                data = json.loads(item)
                lines.append(
                    f"| `{data.get('id')}` | `{data.get('file_path')}` | "
                    f"`{data.get('blast_radius')}` | `{data.get('rollback_plan')}` |"
                )
            except Exception:
                continue
        lines.append("")

    # Verification Report Section
    if verification_report:
        lines.append("### Clean-Room Regression Report")
        for report in verification_report:
            lines.append(f"> {report}")
        lines.append("")

    # Deployment Gate Telemetry
    deploy_status = final_state.get("deployment_status")
    deploy_url = final_state.get("deployment_url")
    if deploy_status and deploy_status != "SKIPPED":
        deploy_badge = {
            "DEPLOYED_AND_LIVE": "PASSED (Deployed & Verified Live)",
            "DEPLOYMENT_FAILED": "FAILED (Deployment or Smoke Tests Failed)",
        }.get(deploy_status, deploy_status)
        lines.append("### Cloud Deployment Gate")
        lines.append(f"- **Deployment Status**: `{deploy_badge}`")
        if deploy_url:
            lines.append(f"- **Target Live URL**: {deploy_url}")
        lines.append("")

    summary_content = "\n".join(lines)

    # Write to target path (e.g. $GITHUB_STEP_SUMMARY)
    if output_path:
        try:
            with open(output_path, "a", encoding="utf-8") as f:
                f.write("\n" + summary_content + "\n")
            logger.info("[CI Summary] Written to: %s", output_path)
        except Exception as e:
            logger.warning("[CI Summary] Could not write to %s: %s", output_path, e)

    return summary_content


async def run_ci_gate(args: argparse.Namespace) -> int:
    """
    Main asynchronous CI execution loop.
    """
    repo_path = os.path.abspath(args.repo)
    if not os.path.isdir(repo_path):
        logger.error("Repository path does not exist: %s", repo_path)
        return 1

    target_url = args.target_url or os.getenv("TARGET_URL", "http://localhost:8000")
    git_diff = extract_git_diff(repo_path, base_ref=args.base_ref, diff_file=args.diff_file)

    logger.info("============================================================")
    logger.info("PROJECT AEGIS -- AUTONOMOUS CI/CD SECURITY GATE")
    logger.info("============================================================")
    logger.info("Target Repository: %s", repo_path)
    logger.info("Target URL:        %s", target_url)
    logger.info("Base Ref:          %s", args.base_ref or "HEAD~1")
    logger.info("Git Diff Present:  %s", "YES" if git_diff else "NO (Full Scan)")
    logger.info("============================================================")

    deploy_platform = getattr(args, "deploy_platform", None)
    if deploy_platform:
        os.environ["AEGIS_DEPLOY_PLATFORM"] = deploy_platform

    initial_state = {
        "messages": [],
        "url": target_url,
        "frontend_analysis": [],
        "codebase_analysis": [],
        "active_debugger": [],
        "proposed_patch": [],
        "verification_status": "PENDING",
        "codebase_path": [repo_path],
        "git_diff": git_diff,
        "cleaned_errors": [],
        "remediation_plan": [],
        "test_results": [],
        "verification_report": [],
        "deployment_status": None,
        "deployment_url": None,
        "next": "Recon_Team",
    }

    try:
        final_state = await aegis_app.ainvoke(initial_state)
    except Exception as e:
        logger.error("[CI Execution Error] LangGraph execution failed: %s", e)
        return 1

    v_status = final_state.get("verification_status", "UNKNOWN")
    deploy_status = final_state.get("deployment_status")
    logger.info("[CI Gate Completed] Final Verification Status: %s | Deployment Status: %s", v_status, deploy_status)

    # Resolve summary output path (prioritize GITHUB_STEP_SUMMARY environment variable)
    summary_path = os.getenv("GITHUB_STEP_SUMMARY") or args.summary_file
    render_github_step_summary(final_state, output_path=summary_path)

    # Optional JSON report export
    if args.json_report:
        try:
            with open(args.json_report, "w", encoding="utf-8") as f:
                json.dump({
                    "verification_status": v_status,
                    "deployment_status": deploy_status,
                    "deployment_url": final_state.get("deployment_url"),
                    "cleaned_errors": final_state.get("cleaned_errors", []),
                    "active_debugger": final_state.get("active_debugger", []),
                    "remediation_plan": final_state.get("remediation_plan", []),
                    "verification_report": final_state.get("verification_report", []),
                }, f, indent=2)
            logger.info("[CI JSON Report] Saved to: %s", args.json_report)
        except Exception as e:
            logger.warning("[CI JSON Report] Failed to write JSON report: %s", e)

    # Exit code determination
    if deploy_status == "DEPLOYMENT_FAILED" and args.fail_on_critical:
        logger.error("[CI Result: FAIL] Deployment or post-deploy smoke tests failed.")
        return 1

    if v_status in ("READY_FOR_DEPLOYMENT", "NO_EXPLOITS_CONFIRMED"):
        logger.info("[CI Result: PASS] Security gates cleared.")
        return 0

    if args.fail_on_critical:
        logger.error("[CI Result: FAIL] Security gates rejected status '%s'.", v_status)
        return 1

    logger.warning("[CI Result: WARNING] Completed with status '%s'.", v_status)
    return 0


def main():
    parser = argparse.ArgumentParser(description="Project Aegis Autonomous CI/CD Security Gate")
    parser.add_argument("--repo", default=".", help="Path to local repository root")
    parser.add_argument("--target-url", default=None, help="Target URL for dynamic recon and probe checks")
    parser.add_argument("--base-ref", default=None, help="Base Git ref to diff against (e.g. origin/main, HEAD~1)")
    parser.add_argument("--diff-file", default=None, help="Path to pre-computed git diff file")
    parser.add_argument("--deploy-platform", default=None, help="Target deployment platform (vercel, render, railway, aws_ecs). Overrides AEGIS_DEPLOY_PLATFORM env var.")
    parser.add_argument("--fail-on-critical", action="store_true", default=False, help="Exit with code 1 if status is not READY_FOR_DEPLOYMENT or deploy fails")
    parser.add_argument("--summary-file", default="aegis_summary.md", help="Path to write GitHub step summary markdown")
    parser.add_argument("--json-report", default=None, help="Path to write raw JSON audit report")

    args = parser.parse_args()
    code = asyncio.run(run_ci_gate(args))
    sys.exit(code)


if __name__ == "__main__":
    main()
