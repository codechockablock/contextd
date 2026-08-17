# contextd — operating map (canonical copy: master)

Never read project state from this file. The canonical map lives on
master; from any lane:

    git show master:docs/operating-map.md

That copy carries the rule itself: never trust a lane checkout's copy
and never hand-mirror master content onto lanes — divergent copies
drifted, and the 2026-08-15 flaw sweep retired the practice along with
the stale lane checkouts. This lane's hand-mirrored copy (b28aa25;
recover it with `git show b28aa25:docs/operating-map.md`) proved the
point: it still said "signer not enrolled, field window not started"
after the canonical map had recorded both resolved.

Lane status, terminal: **delegation-grants** shipped and merged
2026-08-14 — see Done on the canonical map. This checkout is kept as
history; the flaw sweep removed its `.venv` deliberately so
pre-hardening code cannot execute against the live archive, which is
why gates and hooks that expect `.venv/` fail here. Run nothing from
this checkout against the live archive.
