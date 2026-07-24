import asyncio
import json
from fastmcp import Client
from fastmcp.client.transports import StdioTransport

async def main(url: str) -> str:
    """
    Connects to Playwright MCP via StdioTransport, navigates to the target URL,
    crawls the interactive frontend elements, and returns formatted DOM context.
    """
    print(f"[MCP_Crawler] Launching Playwright MCP for URL: {url}")

    # Configure StdioTransport directly for FastMCP
    transport = StdioTransport(
        command="npx",
        args=["-y", "@playwright/mcp@latest"]
    )

    client = Client(transport)

    async with client:
        try:
            # 1. Navigate to target URL
            await client.call_tool(
                name="navigate",
                arguments={"url": url}
            )

            # Allow SPAs/dynamic scripts to settle
            await asyncio.sleep(2)

            # 2. Extract DOM snapshot
            available_tools = [t.name for t in await client.list_tools()]
            
            if "get_accessibility_tree" in available_tools:
                res = await client.call_tool("get_accessibility_tree", arguments={})
                dom_data = str(res)
            elif "snapshot" in available_tools:
                res = await client.call_tool("snapshot", arguments={})
                dom_data = str(res)
            elif "evaluate" in available_tools:
                js_script = """
                () => {
                    const elements = Array.from(document.querySelectorAll('a, button, input, select, textarea, form, [role]'));
                    return elements.map(el => ({
                        tag: el.tagName,
                        id: el.id,
                        name: el.name,
                        role: el.getAttribute('role') || el.type,
                        text: el.innerText ? el.innerText.trim() : '',
                        action: el.action || el.href || null
                    }));
                }
                """
                res = await client.call_tool("evaluate", arguments={"script": js_script})
                dom_data = json.dumps(res, indent=2)
            else:
                dom_data = "Unable to extract DOM tree; no compatible Playwright snapshot tool found."

            print(f"[MCP_Crawler] Extracted {len(dom_data)} bytes of DOM data.")
            return dom_data

        except Exception as e:
            print(f"[MCP_Crawler Error] {e}")
            return f"<ACCESSIBILITY_DOM_ERROR>{str(e)}</ACCESSIBILITY_DOM_ERROR>"