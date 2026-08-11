"""Lexical index: FTS5 queries and timeline reads. Embeddings are v0.1, on purpose."""

import re
from datetime import datetime, timezone

# occurrence time: visit time for browser events, ingest time for the rest
OCCURRED = "COALESCE(json_extract(e.meta, '$.visited_unix'), CAST(strftime('%s', e.ts) AS INTEGER))"


def fts_escape(query: str):
    terms = re.findall(r"[\w'-]+", query)
    return " ".join(f'"{t}"' for t in terms) if terms else None


def _epoch(s):
    if not s:
        return None
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def search(conn, query: str, limit: int = 20, highlight: bool = True,
           since=None, until=None):
    q = fts_escape(query)
    if not q:
        return []
    # highlight brackets can split a credential mid-token and defeat redaction;
    # any caller that redacts afterward must pass highlight=False
    mark = ("[", "]") if highlight else ("", "")
    window, args = "", []
    if (lo := _epoch(since)) is not None:
        window += f" AND {OCCURRED} >= ?"
        args.append(lo)
    if (hi := _epoch(until)) is not None:
        window += f" AND {OCCURRED} < ?"
        args.append(hi)
    sql = f"""
        SELECT e.id, e.ts, e.source, e.kind, e.uri,
               snippet(events_fts, 0, ?, ?, '…', 16) AS snip
        FROM events_fts JOIN events e ON e.id = events_fts.rowid
        WHERE events_fts MATCH ? AND e.kind != 'egress'{window}
        ORDER BY bm25(events_fts) LIMIT ?
        """

    def run(match):
        return conn.execute(sql, (*mark, match, *args, limit)).fetchall()

    rows = run(q)
    if not rows and '" "' in q:
        # every-term AND found nothing; degrade to any-term, bm25 still ranks
        rows = run(q.replace('" "', '" OR "'))
    return rows


def timeline(conn, since=None, until=None, source=None, kind=None, limit=200,
             exclude_egress=False):
    clauses, args = [], []
    if exclude_egress:
        clauses.append("kind != 'egress'")
    if since:
        clauses.append("ts >= ?")
        args.append(since)
    if until:
        clauses.append("ts <= ?")
        args.append(until + ("~" if len(until) <= 10 else ""))
    if source:
        clauses.append("source = ?")
        args.append(source)
    if kind:
        clauses.append("kind = ?")
        args.append(kind)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    args.append(limit)
    return conn.execute(
        f"SELECT id, ts, source, kind, uri, content, meta FROM events {where} "
        "ORDER BY id DESC LIMIT ?",
        args,
    ).fetchall()
