"""Lexical index: FTS5 queries and timeline reads. Embeddings are v0.1, on purpose."""

import re


def fts_escape(query: str):
    terms = re.findall(r"[\w'-]+", query)
    return " ".join(f'"{t}"' for t in terms) if terms else None


def search(conn, query: str, limit: int = 20):
    q = fts_escape(query)
    if not q:
        return []
    return conn.execute(
        """
        SELECT e.id, e.ts, e.source, e.kind, e.uri,
               snippet(events_fts, 0, '[', ']', '…', 16) AS snip
        FROM events_fts JOIN events e ON e.id = events_fts.rowid
        WHERE events_fts MATCH ? AND e.kind != 'egress'
        ORDER BY bm25(events_fts) LIMIT ?
        """,
        (q, limit),
    ).fetchall()


def timeline(conn, since=None, until=None, source=None, kind=None, limit=200):
    clauses, args = [], []
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
