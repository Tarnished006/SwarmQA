"""
mcp_logic.py -- Project Aegis Stealth Browser Crawler
======================================================
Replaces the npx @playwright/mcp subprocess approach with direct
playwright-python + playwright-stealth to bypass Cloudflare Bot Management,
DataDome, Akamai Bot Manager, PerimeterX, and similar fingerprint-based
bot detection systems.

Stealth techniques applied:
  1. playwright-stealth library -- patches navigator.webdriver, chrome.runtime,
     permissions.query, Notification.requestPermission, plugins, mimeTypes
  2. chromium --headless=new -- avoids HeadlessChrome UA string
  3. Real Chrome user-agent strings (randomly selected)
  4. Randomised viewport, timezone, locale per session
  5. sec-ch-ua / accept-language HTTP headers injected
  6. Human-like pre-interaction mouse movement (bezier steps)
  7. Cookie jar persistence across retries (same context object reused)
  8. Bot-beacon URL interception and blocking (Akamai, DataDome etc.)

Environment variables:
  CRAWLER_HEADLESS    -- "true" (default) or "false" for visible browser
  CRAWLER_TIMEOUT_S   -- Total crawl wall-clock cap (default: 90)
  CRAWLER_MAX_RETRIES -- Number of retry attempts (default: 2)
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
import re
from typing import Optional

logger = logging.getLogger("aegis.mcp_crawler")

# -- CONFIG ------------------------------------------------------------------
HEADLESS          = os.getenv("CRAWLER_HEADLESS", "true").lower() in ("true", "1", "yes")
TOTAL_CRAWL_TIMEOUT = int(os.getenv("CRAWLER_TIMEOUT_S",   "90"))
MAX_RETRIES        = int(os.getenv("CRAWLER_MAX_RETRIES",   "2"))
NAVIGATE_TIMEOUT   = 30_000   # ms
WAIT_AFTER_LOAD    = 2_000    # ms -- SPA settle
MAX_NETWORK_REQS   = 40

# -- USER AGENT POOL ---------------------------------------------------------
# Real Chrome/Edge UA strings -- rotate per session to avoid fingerprint reuse.
_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
]

# sec-ch-ua values matching the UA strings above
_CH_UA_MAP = {
    "Chrome/126": '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
    "Chrome/125": '"Not/A)Brand";v="8", "Chromium";v="125", "Google Chrome";v="125"',
    "Edg/125":    '"Not/A)Brand";v="8", "Chromium";v="125", "Microsoft Edge";v="125"',
    "Firefox":    None,  # Firefox does not send sec-ch-ua
    "Safari":     None,
}

# -- BOT BEACON BLOCK LIST ---------------------------------------------------
# These URLs are used purely for bot detection telemetry -- block them.
_BOT_BEACON_PATTERNS = [
    re.compile(r"datadome\.co"),
    re.compile(r"akam\.net/collect"),
    re.compile(r"px-cloud\.net"),
    re.compile(r"perimeterx\.net"),
    re.compile(r"impervadns\.net"),
    re.compile(r"/_Incapsula_Resource"),
    re.compile(r"/cdn-cgi/challenge-platform"),
]

# -- JS UTILITIES ------------------------------------------------------------
_SPA_WAIT_JS = """
() => new Promise((resolve) => {
    let idle;
    const reset = () => { clearTimeout(idle); idle = setTimeout(resolve, 800); };
    const obs = new PerformanceObserver((list) => {
        if (list.getEntries().some(e => e.initiatorType === 'fetch' || e.initiatorType === 'xmlhttprequest'))
            reset();
    });
    try { obs.observe({ entryTypes: ['resource'] }); } catch(e) {}
    reset();
    setTimeout(resolve, 3000);
})
"""

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
    const selectors = 'a[href], button, input, select, textarea, form, [role="button"], [role="link"]';
    return Array.from(document.querySelectorAll(selectors)).map(extract).slice(0, 200);
}
"""


def _pick_ua() -> tuple[str, Optional[str]]:
    """
    Returns (user_agent, sec_ch_ua_value).
    Randomises per session.
    """
    ua = random.choice(_UA_POOL)
    ch_ua = None
    for fragment, val in _CH_UA_MAP.items():
        if fragment in ua:
            ch_ua = val
            break
    return ua, ch_ua


def _random_viewport() -> dict:
    """Return a randomised but realistic viewport size."""
    widths  = [1280, 1366, 1440, 1536, 1920]
    heights = [768, 800, 864, 900, 1080]
    return {"width": random.choice(widths), "height": random.choice(heights)}


def _random_locale() -> tuple[str, str]:
    """Return (locale, timezone) pair."""
    pairs = [
        ("en-US", "America/New_York"),
        ("en-GB", "Europe/London"),
        ("en-AU", "Australia/Sydney"),
        ("en-CA", "America/Toronto"),
    ]
    return random.choice(pairs)


async def _human_mouse_warmup(page) -> None:
    """
    Move the mouse in a human-like bezier curve before interacting.
    Cloudflare / PerimeterX track mouse entropy -- zero movement = bot.
    """
    try:
        vp = page.viewport_size or {"width": 1280, "height": 768}
        # Generate 3-5 random waypoints
        for _ in range(random.randint(3, 5)):
            x = random.randint(100, vp["width"] - 100)
            y = random.randint(100, vp["height"] - 100)
            await page.mouse.move(x, y, steps=random.randint(15, 30))
            await asyncio.sleep(random.uniform(0.05, 0.15))
    except Exception:
        pass  # Non-fatal


async def _intercept_bot_beacons(route) -> None:
    """Block known bot-detection telemetry URLs."""
    url = route.request.url
    for pattern in _BOT_BEACON_PATTERNS:
        if pattern.search(url):
            await route.abort()
            return
    await route.continue_()


async def _crawl_once(page, url: str) -> str:
    """
    Execute a single full crawl with stealth patches already applied to the page.
    Returns structured multi-section string.
    """
    logger.info("[Crawler] Navigating to %s ...", url)

    # Navigate with domcontentloaded first (faster, less detectable than load)
    await page.goto(url, wait_until="domcontentloaded", timeout=NAVIGATE_TIMEOUT)

    # Human-like mouse movement before anything else loads
    await _human_mouse_warmup(page)

    # Wait for SPA JS to settle
    try:
        await asyncio.wait_for(
            page.wait_for_timeout(WAIT_AFTER_LOAD),
            timeout=5,
        )
    except Exception:
        pass

    try:
        await asyncio.wait_for(
            page.evaluate(_SPA_WAIT_JS),
            timeout=8,
        )
    except Exception:
        pass

    sections = []

    # -- Accessibility snapshot (primary) --------------------------------
    snapshot_ok = False
    try:
        logger.info("[Crawler] Taking accessibility snapshot ...")
        snapshot_raw = await asyncio.wait_for(page.accessibility.snapshot(), timeout=15)
        import json
        snapshot_str = json.dumps(snapshot_raw, indent=2) if snapshot_raw else ""
        if snapshot_str and len(snapshot_str) > 50:
            sections.append(f"<ACCESSIBILITY_SNAPSHOT>\n{snapshot_str}\n</ACCESSIBILITY_SNAPSHOT>")
            snapshot_ok = True
            logger.info("[Crawler] Snapshot: %d bytes.", len(snapshot_str))
    except Exception as e:
        logger.warning("[Crawler] Snapshot failed (%s). Falling back to JS DOM.", e)

    # -- JS DOM fallback -------------------------------------------------
    if not snapshot_ok:
        try:
            logger.info("[Crawler] JS DOM extraction fallback ...")
            js_raw = await asyncio.wait_for(page.evaluate(_DOM_EXTRACT_JS), timeout=15)
            import json
            js_str = json.dumps(js_raw, indent=2) if js_raw else ""
            sections.append(f"<DOM_ELEMENTS_FALLBACK>\n{js_str}\n</DOM_ELEMENTS_FALLBACK>")
            logger.info("[Crawler] JS fallback: %d bytes.", len(js_str))
        except Exception as e:
            logger.error("[Crawler] JS DOM extraction also failed: %s", e)
            return f"<ACCESSIBILITY_DOM_ERROR>Snapshot failed and JS fallback failed: {e}</ACCESSIBILITY_DOM_ERROR>"

    # -- Network request harvesting (hidden API endpoint discovery) ------
    # Playwright does not have a built-in network_requests() like the MCP tool,
    # so we expose the requests captured by our route interception listener.
    try:
        # Evaluate performance entries to get resource URLs
        net_raw = await asyncio.wait_for(
            page.evaluate(
                f"""() => performance.getEntriesByType('resource')
                        .slice(0, {MAX_NETWORK_REQS})
                        .map(e => ({{url: e.name, type: e.initiatorType, duration: Math.round(e.duration)}}))"""
            ),
            timeout=5,
        )
        import json
        net_str = json.dumps(net_raw, indent=2) if net_raw else ""
        if net_str and len(net_str) > 20:
            net_trimmed = net_str[:8000] if len(net_str) > 8000 else net_str
            sections.append(f"<NETWORK_REQUESTS count='up_to_{MAX_NETWORK_REQS}'>\n{net_trimmed}\n</NETWORK_REQUESTS>")
            logger.info("[Crawler] Network requests: %d bytes captured.", len(net_str))
    except Exception as e:
        logger.debug("[Crawler] Network harvest skipped: %s", e)

    return "\n\n".join(sections)


async def main(url: str) -> str:
    """
    Production-grade stealth browser crawler.

    Launches a Chromium browser with full stealth patching applied
    (playwright-stealth), randomised fingerprint (UA, viewport, locale, timezone),
    bot-beacon blocking, and human-like mouse movement.

    Falls back to accessibility snapshot -> JS DOM extraction.
    Returns an <ACCESSIBILITY_DOM_ERROR> sentinel on permanent failure.

    Retries up to MAX_RETRIES times, reusing the same browser context
    (cookie jar persists -- looks like a returning human visitor).
    """
    try:
        from playwright.async_api import async_playwright
        from playwright_stealth import stealth_async
    except ImportError as e:
        logger.error("[Crawler] Missing dependency: %s. Run: pip install playwright playwright-stealth && playwright install chromium", e)
        return f"<ACCESSIBILITY_DOM_ERROR>Missing playwright dependency: {e}. Install with: pip install playwright playwright-stealth && playwright install chromium</ACCESSIBILITY_DOM_ERROR>"

    ua, ch_ua = _pick_ua()
    viewport  = _random_viewport()
    locale, tz = _random_locale()

    logger.info(
        "[Crawler] Launching stealth Chromium. UA=%s... viewport=%sx%s locale=%s",
        ua[:40], viewport["width"], viewport["height"], locale,
    )

    last_error = None

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=HEADLESS,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-features=IsolateOrigins,site-per-process",
                    "--disable-web-security",
                    "--disable-extensions",
                    "--no-first-run",
                    "--no-default-browser-check",
                ],
            )

            # One context per crawl session -- cookie jar persists across retries
            context = await browser.new_context(
                user_agent=ua,
                viewport=viewport,
                locale=locale,
                timezone_id=tz,
                accept_downloads=False,
                extra_http_headers={k: v for k, v in {
                    "sec-ch-ua": ch_ua,
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": '"Windows"',
                    "accept-language": f"{locale},{locale.split('-')[0]};q=0.9",
                }.items() if v is not None},
            )

            for attempt in range(1, MAX_RETRIES + 2):
                page = await context.new_page()

                # Apply stealth patches -- must happen BEFORE page.goto()
                await stealth_async(page)

                # Block bot-detection beacon URLs
                await page.route("**/*", _intercept_bot_beacons)

                try:
                    async with asyncio.timeout(TOTAL_CRAWL_TIMEOUT):
                        result = await _crawl_once(page, url)
                        logger.info(
                            "[Crawler] Crawl complete (attempt %d). Output: %d bytes.",
                            attempt, len(result),
                        )
                        await page.close()
                        await context.close()
                        await browser.close()
                        return result

                except asyncio.TimeoutError:
                    last_error = f"Total crawl timeout exceeded ({TOTAL_CRAWL_TIMEOUT}s)"
                    logger.error("[Crawler] Attempt %d/%d timed out.", attempt, MAX_RETRIES + 1)
                except Exception as e:
                    last_error = str(e)
                    logger.error("[Crawler] Attempt %d/%d failed: %s", attempt, MAX_RETRIES + 1, e)
                finally:
                    try:
                        await page.close()
                    except Exception:
                        pass

                if attempt <= MAX_RETRIES:
                    delay = 1.5 * (2 ** (attempt - 1))
                    logger.info("[Crawler] Retrying in %.1fs ...", delay)
                    await asyncio.sleep(delay)

            await context.close()
            await browser.close()

    except Exception as e:
        last_error = str(e)
        logger.error("[Crawler] Browser launch failed: %s", e)

    error_msg = f"All {MAX_RETRIES + 1} crawl attempts failed. Last error: {last_error}"
    logger.error("[Crawler] %s", error_msg)
    return f"<ACCESSIBILITY_DOM_ERROR>{error_msg}</ACCESSIBILITY_DOM_ERROR>"