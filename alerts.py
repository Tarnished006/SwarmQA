"""
alerts.py — Autonomous Human-In-The-Loop (HITL) Alerting Dispatcher for Project Aegis.

Notifies developers and security engineers autonomously even when they are not actively
monitoring the terminal or dashboard.

Supported Notification Channels:
1. Webhooks (Discord, Slack, MS Teams, generic JSON via ALERT_WEBHOOK_URL).
2. Local Durable Alert Artifact (.aegis_alerts/ALERT_<timestamp>.md in codebase).
3. High-visibility Terminal ANSI Warning Banners.
"""
import os
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any
import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("aegis.alerts")


def _format_discord_payload(title: str, summary: str, severity: str, details: Dict[str, Any]) -> dict:
    color_map = {
        "CRITICAL": 0xFF0000,  # Red
        "HIGH": 0xFF5500,      # Orange-Red
        "MODERATE": 0xFFA500,  # Orange
        "MEDIUM": 0xFFFF00,    # Yellow
        "LOW": 0x00FF00,       # Green
    }
    color = color_map.get(severity.upper(), 0x3498DB)

    fields = []
    for k, v in details.items():
        fields.append({"name": str(k).replace("_", " ").title(), "value": f"`{str(v)[:300]}`", "inline": True})

    return {
        "content": f"🚨 **Aegis Security Alert** [{severity.upper()}]",
        "embeds": [
            {
                "title": title,
                "description": summary,
                "color": color,
                "fields": fields[:8],
                "footer": {"text": "Project Aegis — Autonomous DevSecOps Engine"},
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        ]
    }


def _format_slack_payload(title: str, summary: str, severity: str, details: Dict[str, Any]) -> dict:
    fields = [
        {"type": "mrkdwn", "text": f"*{str(k).replace('_', ' ').title()}:*\n`{str(v)[:200]}`"}
        for k, v in details.items()
    ]
    return {
        "text": f"🚨 *Aegis Security Alert [{severity.upper()}]:* {title}",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"🚨 Aegis Alert: {title}"[:150]},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": summary},
            },
            {
                "type": "section",
                "fields": fields[:8],
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"*Timestamp:* {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"}
                ]
            }
        ]
    }


async def dispatch_hitl_alert(
    title: str,
    summary: str,
    severity: str = "HIGH",
    details: Optional[Dict[str, Any]] = None,
    codebase_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Dispatches an autonomous Human-In-The-Loop alert across multiple channels:
    1. Webhook (Slack / Discord / Teams) if ALERT_WEBHOOK_URL is configured in .env.
    2. Durable markdown artifact file in `<codebase>/.aegis_alerts/`.
    3. Prominent ANSI terminal log.
    """
    details = details or {}
    webhook_url = os.getenv("ALERT_WEBHOOK_URL", "").strip()
    status_report: Dict[str, Any] = {
        "webhook_sent": False,
        "artifact_file": None,
        "delivered_at": datetime.utcnow().isoformat() + "Z",
    }

    # ── 1. DURABLE MARKDOWN ARTIFACT FILE ─────────────────────────
    try:
        base_dir = codebase_path if (codebase_path and os.path.exists(codebase_path)) else "."
        alerts_dir = os.path.join(base_dir, ".aegis_alerts")
        os.makedirs(alerts_dir, exist_ok=True)

        timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_title = "".join(c if c.isalnum() else "_" for c in title)[:30]
        filename = f"ALERT_{timestamp_str}_{safe_title}.md"
        filepath = os.path.join(alerts_dir, filename)

        md_content = f"""# 🚨 Human-In-The-Loop Security Alert

**Title**: {title}  
**Severity**: `{severity.upper()}`  
**Generated At**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Status**: `ACTION_REQUIRED`  

---

## Summary
{summary}

---

## Technical Details
| Parameter | Value |
| :--- | :--- |
"""
        for k, v in details.items():
            md_content += f"| **{str(k).replace('_', ' ').title()}** | `{v}` |\n"

        md_content += """
---

## Required Action
A critical security patch or anomaly was flagged with `requires_human_review = True`.
1. Review the affected file and the proposed patch snippet above.
2. Confirm that business logic and database constraints are preserved.
3. Deploy or reject the patch in your pull request review.
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(md_content)

        status_report["artifact_file"] = filepath
        logger.info("[HITL Alert] Durable alert saved to %s", filepath)

    except Exception as e:
        logger.warning("[HITL Alert] Failed to write alert artifact file: %s", e)

    # ── 2. WEBHOOK DISPATCH (SLACK / DISCORD / GENERIC) ───────────
    if webhook_url:
        try:
            if "discord.com" in webhook_url:
                payload = _format_discord_payload(title, summary, severity, details)
            elif "slack.com" in webhook_url:
                payload = _format_slack_payload(title, summary, severity, details)
            else:
                payload = {
                    "title": title,
                    "summary": summary,
                    "severity": severity,
                    "details": details,
                    "timestamp": datetime.utcnow().isoformat(),
                }

            async with httpx.AsyncClient(timeout=6.0) as client:
                res = await client.post(webhook_url, json=payload)
                if res.status_code in (200, 204):
                    status_report["webhook_sent"] = True
                    logger.info("[HITL Alert] Webhook delivered successfully (HTTP %d).", res.status_code)
                else:
                    logger.warning("[HITL Alert] Webhook returned non-200 status: %d", res.status_code)
        except Exception as e:
            logger.warning("[HITL Alert] Failed to dispatch webhook: %s", e)
    else:
        logger.info("[HITL Alert] No ALERT_WEBHOOK_URL set. Notification saved locally to artifact file.")

    # ── 3. PROMINENT TERMINAL BANNER ──────────────────────────────
    print("\n" + "=" * 60)
    print(f"[AEGIS HITL ALERT - {severity.upper()}]: {title}")
    print(f"   Summary: {summary}")
    if status_report["artifact_file"]:
        print(f"   Durable File: {status_report['artifact_file']}")
    print("=" * 60 + "\n")

    return status_report
