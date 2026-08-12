"""The MCP registry, not a client-side filter, enforces tool capabilities."""

import sys
from pathlib import Path

import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from contextd.db import connect


async def _read_only_session(contextd_home: str):
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "contextd.cli",
            "serve",
            "--tools",
            "recall",
            "search",
            "timeline",
        ],
        env={
            "CONTEXTD_HOME": contextd_home,
            "CONTEXTD_CLIENT": "openclaw",
        },
    )
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            listed = await session.list_tools()
            names = {tool.name for tool in listed.tools}
            result = await session.call_tool(
                "note", {"text": "this must never become persistent"}
            )
    return names, result


def test_read_only_registry_omits_and_rejects_note(tmp_path, monkeypatch):
    archive = tmp_path / "archive"
    monkeypatch.setenv("CONTEXTD_HOME", str(archive))
    conn = connect()
    conn.close()

    names, result = anyio.run(_read_only_session, str(archive))

    assert names == {"recall", "search", "timeline"}
    assert result.is_error
    conn = connect()
    assert (
        conn.execute("SELECT COUNT(*) FROM events WHERE kind='note'").fetchone()[0] == 0
    )
    conn.close()


def test_openclaw_config_starts_the_restricted_server():
    repo = Path(__file__).resolve().parent.parent
    config = (repo / "clients" / "openclaw.json").read_text()
    assert '"--tools", "recall", "search", "timeline"' in config
