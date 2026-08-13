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


async def _loop_scan_session(contextd_home: str):
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "contextd.cli", "serve", "--tools",
              "loop_candidate", "loop_list"],
        env={"CONTEXTD_HOME": contextd_home,
             "CONTEXTD_CLIENT": "loop-scan",
             "CONTEXTD_LOOP_SCOPE": "/synthetic/amberlight"},
    )
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            listed = await session.list_tools()
            names = {tool.name for tool in listed.tools}
            created = await session.call_tool(
                "loop_candidate", {"text": "audit the sitemap generator",
                                   "scope_repo": "/somewhere/else"})
            confirm = await session.call_tool(
                "loop_confirm", {"candidate_id": 1,
                                 "operator_quote": "definitely on the board"})
    return names, created, confirm


def test_loop_scan_grant_can_propose_but_never_promote(tmp_path, monkeypatch):
    """The registry is the capability boundary: a candidate-generation grant
    lists exactly its two tools; loop_confirm is absent and uncallable; the
    candidate lands as a model-authority candidate pinned to the env scope,
    not the tool-supplied one."""
    archive = tmp_path / "archive"
    monkeypatch.setenv("CONTEXTD_HOME", str(archive))
    connect().close()

    names, created, confirm = anyio.run(_loop_scan_session, str(archive))

    assert names == {"loop_candidate", "loop_list"}
    assert not created.is_error
    assert confirm.is_error, "ungranted tool must be uninvokable"

    from contextd.loops import reduce_loops
    conn = connect()
    loops = reduce_loops(conn)["loops"]
    assert len(loops) == 1
    lp = next(iter(loops.values()))
    assert lp["state"] == "candidate"
    assert lp["created_authority"] == "model"
    assert lp["created_client"] == "loop-scan"
    assert lp["scope"] == {"repo": "/synthetic/amberlight"}, \
        "env-pinned scope must override the tool argument"
    conn.close()


def test_default_registry_includes_loop_tools_and_openclaw_stays_restricted():
    from contextd.mcp_server import TOOLS
    assert {"loop_candidate", "loop_list", "loop_confirm",
            "loop_dismiss"} <= set(TOOLS)
    repo = Path(__file__).resolve().parent.parent
    config = (repo / "clients" / "openclaw.json").read_text()
    assert "loop_" not in config, \
        "the deployed restricted client gains no loop surface implicitly"
