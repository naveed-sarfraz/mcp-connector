"""Connect to a local or remote server and try a physician search."""

import argparse
import asyncio
import os

import httpx2
from dotenv import load_dotenv

from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import TextContent

DEFAULT_SERVER_URL = "http://127.0.0.1:8000/mcp"

load_dotenv()


async def main(server_url: str, token: str, text: str) -> None:
    response_statuses: list[int] = []

    # Record statuses because the SDK wraps some HTTP errors as MCP errors.
    async def record_response(response: httpx2.Response) -> None:
        response_statuses.append(response.status_code)

    # Send the user's token in the HTTP Authorization header.
    async with httpx2.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        event_hooks={"response": [record_response]},
    ) as http_client:
        transport = streamable_http_client(server_url, http_client=http_client)

        try:
            async with Client(transport) as client:
                tools = await client.list_tools()
                print("Tools:")
                for tool in tools.tools:
                    print(f"- {tool.name}()")

                result = await client.call_tool(
                    "search_dataset",
                    {"dataset": "supabase_data", "text": text, "limit": 10},
                )
                if result.is_error:
                    print(f"DENIED: {result.content[0].text}")
                else:
                    print("ALLOWED:")
                    for block in result.content:
                        if isinstance(block, TextContent):
                            print(block.text)
        except httpx2.HTTPStatusError as error:
            if error.response.status_code == 401:
                print("Authentication rejected: the bearer token is invalid.")
                return
            raise
        except ExceptionGroup:
            if 401 in response_statuses:
                print("Authentication rejected: the bearer token is invalid.")
                return
            raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Search the configured dataset with a bearer token."
    )
    parser.add_argument("text", help="text to find in physician name or specialty")
    parser.add_argument(
        "--url",
        default=os.getenv("MCP_SERVER_URL", DEFAULT_SERVER_URL),
        help="remote MCP URL (defaults to MCP_SERVER_URL or the local server)",
    )
    parser.add_argument(
        "--token",
        default=os.getenv("MCP_BEARER_TOKEN"),
        help="bearer token (defaults to MCP_BEARER_TOKEN)",
    )
    arguments = parser.parse_args()
    if not arguments.token:
        parser.error("set MCP_BEARER_TOKEN or pass --token")
    asyncio.run(main(arguments.url, arguments.token, arguments.text))
