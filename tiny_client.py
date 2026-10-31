"""Local STDIO smoke client for the open InsightMonk Reports MCP server."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from mcp import Client, StdioServerParameters
from mcp.types import TextContent

load_dotenv()


async def main(query: str) -> None:
    environment = os.environ.copy()
    environment["MCP_TRANSPORT"] = "stdio"
    server = StdioServerParameters(
        command=sys.executable,
        args=[str(Path(__file__).with_name("tiny_server.py"))],
        env=environment,
        cwd=str(Path(__file__).parent),
    )
    async with Client(server) as client:
        result = await client.call_tool(
            "search_reports",
            {"query": query, "limit": 10, "latest_only": True},
        )
        for block in result.content:
            if isinstance(block, TextContent):
                print(block.text)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search InsightMonk reports over STDIO.")
    parser.add_argument("query", help="question or report search text")
    arguments = parser.parse_args()
    asyncio.run(main(arguments.query))
