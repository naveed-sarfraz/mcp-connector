"""Local STDIO smoke client for an authorized InsightMonk user."""

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


async def main(search: str, user_id: str) -> None:
    environment = os.environ.copy()
    environment["MCP_TRANSPORT"] = "stdio"
    environment["MCP_DEV_USER_ID"] = user_id
    server = StdioServerParameters(
        command=sys.executable,
        args=[str(Path(__file__).with_name("tiny_server.py"))],
        env=environment,
        cwd=str(Path(__file__).parent),
    )
    async with Client(server) as client:
        result = await client.call_tool(
            "search_reports",
            {
                "search": search,
                "from_date": "2000-01-01",
                "to_date": "",
                "report_type": "Full",
                "page": 1,
                "limit": 10,
            },
        )
        for block in result.content:
            if isinstance(block, TextContent):
                print(block.text)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search InsightMonk reports over local STDIO.")
    parser.add_argument("search", help="report search text")
    parser.add_argument(
        "--user-id",
        default=os.getenv("MCP_DEV_USER_ID", ""),
        help="existing active application user ID (or set MCP_DEV_USER_ID)",
    )
    arguments = parser.parse_args()
    if not arguments.user_id:
        parser.error("--user-id or MCP_DEV_USER_ID is required")
    asyncio.run(main(arguments.search, arguments.user_id))
