"""Bench-side wrapper for the production scanner: point hooks/loop_scan.py
at a world archive and run one pass. The subprocess model call lives in the
hook (inventoried there); this wrapper only rebinds CONTEXTD_HOME."""

from pathlib import Path

from experiments.handoff.common import contextd_home


def run_scan(world_home: Path, repo: str, session: str,
             model: str = "haiku") -> dict:
    with contextd_home(Path(world_home)):
        import hooks.loop_scan as hook
        from contextd import load_config
        from contextd.db import connect
        conn = connect()
        out = hook.scan(conn, load_config(), repo=repo, session_id=session,
                        model=model)
        conn.close()
    return out
