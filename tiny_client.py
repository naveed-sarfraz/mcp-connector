"""Connect to a local or remote server and try a physician search."""

import argparse
import asyncio
import os

from dotenv import load_dotenv

from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import TextContent

DEFAULT_SERVER_URL = "http://127.0.0.1:8000/mcp"

load_dotenv()


async def main(server_url: str, text: str) -> None:
    transport = streamable_http_client(server_url)
    async with Client(transport) as client:
        tools = await client.list_tools()
        print("Tools:")
        for tool in tools.tools:
            print(f"- {tool.name}()")

        result = await client.call_tool(
            "search_dataset",
            {"text": text, "limit": 10},
        )
        if result.is_error:
            print(f"ERROR: {result.content[0].text}")
        else:
            print("RESULT:")
            for block in result.content:
                if isinstance(block, TextContent):
                    print(block.text)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Search the public physician MCP server."
    )
    parser.add_argument("text", help="text to find in physician name or specialty")
    parser.add_argument(
        "--url",
        default=os.getenv("MCP_SERVER_URL", DEFAULT_SERVER_URL),
        help="remote MCP URL (defaults to MCP_SERVER_URL or the local server)",
    )
    arguments = parser.parse_args()
    asyncio.run(main(arguments.url, arguments.text))
