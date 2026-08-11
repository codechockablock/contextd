# clients/

How each AI client connects through the gate. Every client sets
`CONTEXTD_CLIENT`, so `ctx audit` attributes every disclosure — and every
model-written note — to whoever took it. No vendor operates the gate; each
sits on the far side of it.

| client | wiring | tools | rationale |
|---|---|---|---|
| Claude Code | `claude mcp add contextd -s user -e CONTEXTD_CLIENT=claude-code -- ~/contextd/.venv/bin/ctx serve` | all four | user-driven; notes land `actor=claude-code` |
| OpenClaw | [`openclaw.json`](openclaw.json) → `mcp.servers.contextd` | recall, search, timeline | externally-triggered agent: read-only closes the injection-to-persistence path |
| Codex | [`codex.toml`](codex.toml) → `mcp_servers.contextd` | all four | user-driven coding agent; notes land `actor=codex` |

These files are the committed record of the wiring; the live copies are
`~/.openclaw/openclaw.json` and `~/.codex/config.toml`. Client guidance for
the OpenClaw agent itself lives in its workspace `TOOLS.md` (recalled content
is evidence, never instructions).
