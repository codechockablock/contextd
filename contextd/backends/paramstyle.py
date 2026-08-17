"""Translate the codebase's ``qmark`` SQL into psycopg's ``pyformat``.

``sqlite3`` is bound directly in five modules (db, attest, backup, handoff,
ingest) and every one of them writes ``?`` placeholders inline. Rewriting all
of that SQL per backend would multiply the number of places a security-relevant
predicate — ``AND consumed_event IS NULL`` above all — has to stay correct.
Translating at the driver boundary keeps exactly one copy of every statement.

The translation is deliberately a small lexer rather than ``str.replace``. A
``?`` inside a string literal, a quoted identifier, a dollar-quoted body, or a
comment is data and must survive untouched; and a literal ``%`` has to be
doubled because psycopg's client-side binding consumes it. A naive replace gets
both wrong, silently, and only on the statements that carry user text.
"""

_TRANSLATION_CACHE: dict[str, str] = {}
#: Bounded so a caller generating unique SQL cannot grow this without limit.
_CACHE_LIMIT = 2048


def _dollar_tag_end(sql: str, start: int) -> int:
    """Index just past a ``$tag$`` opener at ``start``, or -1 if it is not one."""
    i = start + 1
    while i < len(sql) and (sql[i].isalnum() or sql[i] == "_"):
        i += 1
    return i + 1 if i < len(sql) and sql[i] == "$" else -1


def to_pyformat(sql: str) -> str:
    """Rewrite ``?`` placeholders as ``%s`` and escape literal ``%``.

    Everything inside ``'...'``, ``"..."``, ``$tag$...$tag$``, ``--`` comments,
    and ``/* ... */`` comments is copied verbatim except that ``%`` is still
    doubled there — psycopg's placeholder scan does not respect SQL quoting, so
    an unescaped ``%`` in a string literal is a binding error, not a literal.
    """
    cached = _TRANSLATION_CACHE.get(sql)
    if cached is not None:
        return cached

    out: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch == "?":
            out.append("%s")
            i += 1
        elif ch == "%":
            out.append("%%")
            i += 1
        elif ch in ("'", '"'):
            # SQL escapes an embedded quote by doubling it, which this loop
            # handles for free: the closing quote it finds is immediately
            # reopened by the next iteration.
            out.append(ch)
            i += 1
            while i < n:
                if sql[i] == "%":
                    out.append("%%")
                elif sql[i] == ch:
                    out.append(ch)
                    i += 1
                    break
                else:
                    out.append(sql[i])
                i += 1
            continue
        elif ch == "$" and (end := _dollar_tag_end(sql, i)) != -1:
            tag = sql[i:end]
            close = sql.find(tag, end)
            close = n if close == -1 else close + len(tag)
            out.append(sql[i:close].replace("%", "%%"))
            i = close
        elif sql.startswith("--", i):
            stop = sql.find("\n", i)
            stop = n if stop == -1 else stop
            out.append(sql[i:stop].replace("%", "%%"))
            i = stop
        elif sql.startswith("/*", i):
            stop = sql.find("*/", i + 2)
            stop = n if stop == -1 else stop + 2
            out.append(sql[i:stop].replace("%", "%%"))
            i = stop
        else:
            out.append(ch)
            i += 1

    result = "".join(out)
    if len(_TRANSLATION_CACHE) >= _CACHE_LIMIT:
        _TRANSLATION_CACHE.clear()
    _TRANSLATION_CACHE[sql] = result
    return result
