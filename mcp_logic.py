from fastmcp.client.transports import StdioTransport
from fastmcp import Client
import asyncio

async def main():
    server={
  "mcpServers": {
    "playwright": {
      "command": "npx",
      "args": [
        "@playwright/mcp@latest"
      ]
    }
  }
}
    client=Client(server)
    async with client:
        tools=await client.list_tools()
        for tool in tools:
            print(tool)

asyncio.run(main())
    