import asyncio
import json
import logging
import os
from fastmcp import Client
from fastmcp.client.transports import StdioTransport

logger = logging.getLogger("aegis.mcp_crawler")

# ── CONFIG ────────────────────────────────────────────────────
# Pinned version so npm doesn't do a registry lookup on every launch should update manually when a new version is released
MCP_PACKAGE = os.getenv("PLAYWRIGHT_MCP_VERSION", "@playwright/mcp@0.0.80")

# Per-operation timeouts (seconds)
NAVIGATE_TIMEOUT    = 20   # page load timeout
WAIT_TIMEOUT        = 8    # SPA settle wait
SNAPSHOT_TIMEOUT    = 15   # accessibility tree extraction
NETWORK_TIMEOUT     = 5    # network request log collection
TOTAL_CRAWL_TIMEOUT = 60   # hard wall-clock cap for the entire crawl

MAX_RETRIES         = 2    # retry attempts on transient failures
RETRY_DELAY_BASE    = 1.5  # seconds, doubles each retry

# How many network requests to include (caps token usage)
MAX_NETWORK_REQUESTS = 40

# JS that waits for the page to reach network-idle state
# Works on React, Vue, Angular, and SSR apps
_SPA_WAIT_JS = """
() => new Promise((resolve) => {
    let idle;
    const reset = () => {
        clearTimeout(idle);
        idle = setTimeout(resolve, 800);  // 800ms quiescent = settled
    };
    const obs = new PerformanceObserver((list) => {
        if (list.getEntries().some(e => e.initiatorType === 'fetch' || e.initiatorType === 'xmlhttprequest'))
            reset();
    });
    try { obs.observe({ entryTypes: ['resource'] }); } catch (e) { /* ignore */ }
    reset();  // start the timer immediately in case page is already idle
    setTimeout(resolve, 3000);  // hard cap: don't wait more than 3s
})
"""

# JS fallback: extracts interactive elements if accessibility snapshot fails
_DOM_EXTRACT_JS = """
() => {
    const extract = (el) => ({
        tag: el.tagName.toLowerCase(),
        id: el.id || null,
        name: el.getAttribute('name') || null,
        type: el.getAttribute('type') || el.tagName.toLowerCase(),
        role: el.getAttribute('role') || null,
        text: (el.innerText || el.textContent || '').trim().slice(0, 80),
        href: el.href || null,
        action: el.action || null,
        method: el.method || null,
        placeholder: el.getAttribute('placeholder') || null,
    });
    const selectors = 'a[href], button, input, select, textarea, form, [role="button"], [role="link"], [role="menuitem"]';
    return Array.from(document.querySelectorAll(selectors)).map(extract).slice(0, 200);
}
"""


async def _safe_call(client: Client, tool: str, args: dict, timeout: float) -> str:
    """
    Wraps a single MCP tool call with an individual timeout.
    Returns a string result or raises on failure.
    """
    result = await asyncio.wait_for(
        client.call_tool(name=tool, arguments=args),
        timeout=timeout,
    )
    return str(result)


async def _crawl_once(client: Client, url: str) -> str:
    """
    Executes one full crawl attempt against a live MCP browser session.
    Returns a multi-section string combining:
      - Accessibility snapshot (or JS DOM fallback)
      - Network requests log (hidden API endpoints)
    """
    # ── Step 1: Navigate ─────────────────────────────────────────
    logger.info("[MCP] Navigating to %s ...", url)
    await _safe_call(client, "browser_navigate", {"url": url}, NAVIGATE_TIMEOUT)

    # First try browser_wait_for (network idle), then JS-based fallback
    try:
        await asyncio.wait_for(
            client.call_tool("browser_wait_for", {"time": 2000}),
            timeout=WAIT_TIMEOUT,
        )
    except Exception:
        pass 

    # JS network-idle wait (works regardless of Playwright's own idle detection)
    try:
        await asyncio.wait_for(
            client.call_tool("browser_evaluate", {"expression": _SPA_WAIT_JS}),
            timeout=WAIT_TIMEOUT,
        )
    except Exception:
        pass  

    sections = []

    # ── Step 3: Accessibility Snapshot (primary) ──────────────────
    snapshot_ok = False
    try:
        logger.info("[MCP] Taking accessibility snapshot ...")
        snapshot_raw = await _safe_call(client, "browser_snapshot", {}, SNAPSHOT_TIMEOUT)
        if snapshot_raw and len(snapshot_raw) > 50:
            sections.append(f"<ACCESSIBILITY_SNAPSHOT>\n{snapshot_raw}\n</ACCESSIBILITY_SNAPSHOT>")
            snapshot_ok = True
            logger.info("[MCP] Snapshot: %d bytes.", len(snapshot_raw))
    except Exception as e:
        logger.warning("[MCP] Snapshot failed (%s). Falling back to JS DOM extraction.", e)

    # ── Step 4: JS DOM Fallback (if snapshot failed) ──────────────
    if not snapshot_ok:
        try:
            logger.info("[MCP] Attempting JS DOM extraction fallback ...")
            js_raw = await _safe_call(
                client, "browser_evaluate", {"expression": _DOM_EXTRACT_JS}, SNAPSHOT_TIMEOUT
            )
            sections.append(f"<DOM_ELEMENTS_FALLBACK>\n{js_raw}\n</DOM_ELEMENTS_FALLBACK>")
            logger.info("[MCP] JS fallback: %d bytes.", len(js_raw))
        except Exception as e:
            logger.error("[MCP] JS DOM extraction also failed: %s", e)
            # Both methods failed — return error sentinel
            return f"<ACCESSIBILITY_DOM_ERROR>Snapshot failed and JS fallback failed: {e}</ACCESSIBILITY_DOM_ERROR>"

    # ── Step 5: Network Request Harvesting ───────────────────────
    # These are real API endpoints that are often NOT visible in the HTML.
    try:
        logger.info("[MCP] Harvesting network requests (hidden API discovery) ...")
        net_raw = await _safe_call(client, "browser_network_requests", {}, NETWORK_TIMEOUT)
        if net_raw and len(net_raw) > 20:
            # Truncate if very large — we only care about endpoint patterns
            net_trimmed = net_raw[:8000] if len(net_raw) > 8000 else net_raw
            sections.append(f"<NETWORK_REQUESTS count='up_to_{MAX_NETWORK_REQUESTS}'>\n{net_trimmed}\n</NETWORK_REQUESTS>")
            logger.info("[MCP] Network requests: %d bytes captured.", len(net_raw))
    except Exception as e:
        logger.debug("[MCP] Network request harvest skipped: %s", e)
        # Non-fatal: this is bonus data

    return "\n\n".join(sections)


async def main(url: str) -> str:
    """
    Production-grade Playwright MCP crawler.

    Connects to Playwright MCP via StdioTransport, navigates to the target URL,
    extracts the accessibility snapshot + network requests, and returns a
    structured multi-section string for the site_analysing_agent to parse.

    Retries up to MAX_RETRIES times on transient failures.
    Returns an <ACCESSIBILITY_DOM_ERROR> sentinel on permanent failure.
    """
    logger.info("[MCP] Launching Playwright MCP (%s) for: %s", MCP_PACKAGE, url)

    transport = StdioTransport(
        command="npx",
        args=["-y", MCP_PACKAGE, "--isolated"],  # --isolated: fresh browser context per run
    )

    last_error = None
    for attempt in range(1, MAX_RETRIES + 2):  # +2 = initial + MAX_RETRIES
        try:
            async with asyncio.timeout(TOTAL_CRAWL_TIMEOUT):
                async with Client(transport) as client:
                    result = await _crawl_once(client, url)
                    logger.info(
                        "[MCP] Crawl complete (attempt %d). Total output: %d bytes.",
                        attempt, len(result)
                    )
                    return result

        except asyncio.TimeoutError:
            last_error = f"Total crawl timeout exceeded ({TOTAL_CRAWL_TIMEOUT}s)"
            logger.error("[MCP] Attempt %d/%d timed out: %s", attempt, MAX_RETRIES + 1, last_error)
        except Exception as e:
            last_error = str(e)
            logger.error("[MCP] Attempt %d/%d failed: %s", attempt, MAX_RETRIES + 1, e)

        if attempt <= MAX_RETRIES:
            delay = RETRY_DELAY_BASE * (2 ** (attempt - 1))  # 1.5s, 3s
            logger.info("[MCP] Retrying in %.1fs ...", delay)
            await asyncio.sleep(delay)

    error_msg = f"All {MAX_RETRIES + 1} crawl attempts failed. Last error: {last_error}"
    logger.error("[MCP] %s", error_msg)
    return f"<ACCESSIBILITY_DOM_ERROR>{error_msg}</ACCESSIBILITY_DOM_ERROR>"
