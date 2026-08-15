"""The wire between the client plane and the authority plane.

Deliberately small. A newline-delimited JSON request/response over ``AF_UNIX``,
with a hard frame bound and a closed operation namespace. There is no
negotiation, no capability upgrade message, and no way for a request to say
who it is: identity comes from the kernel (:func:`peer_credentials`), never
from the request body.

Why a Unix socket rather than a port: an ``AF_UNIX`` connection carries the
peer's real uid/gid, verified by the kernel, and the socket's own filesystem
permissions decide who may connect at all. Both are properties the desktop UID
cannot forge (docs/SECURITY.md §3, ``principal``).
"""

import ctypes
import ctypes.util
import json
import os
import socket
import struct

#: Frame bound. A request larger than this is refused before parsing, so a
#: hostile client cannot exhaust the daemon by streaming an unbounded line.
MAX_FRAME = 4 * 1024 * 1024

PROTOCOL_VERSION = 1

#: Capability tiers. A connection is assigned exactly one at accept time and
#: it never changes for the life of that connection.
TIER_MODEL = "model"
TIER_OPERATOR = "operator"
TIERS = (TIER_MODEL, TIER_OPERATOR)


class RpcError(RuntimeError):
    """A request was refused, or the daemon could not be reached."""

    def __init__(self, message: str, code: str = "refused"):
        super().__init__(message)
        self.code = code


class ServiceUnavailable(RpcError):
    """No daemon is listening. In hardened mode this fails closed."""

    def __init__(self, message: str):
        super().__init__(message, code="unavailable")


_libc = None


def _load_libc():
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    return _libc


def peer_credentials(sock: socket.socket) -> dict:
    """The kernel's account of who is on the other end of this socket.

    macOS/BSD expose ``getpeereid(2)``; Linux exposes ``SO_PEERCRED``. Neither
    consults anything the peer sent, which is the entire point: a request body
    claiming ``uid: 0`` changes nothing here.

    The returned pid is best-effort (BSD's ``getpeereid`` does not provide one)
    and is diagnostic only — never an authorization input, because pids are
    reused and a pid check is a race by construction.
    """
    if hasattr(socket, "SO_PEERCRED"):                      # Linux
        raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                              struct.calcsize("3i"))
        pid, uid, gid = struct.unpack("3i", raw)
        return {"uid": uid, "gid": gid, "pid": pid}
    uid = ctypes.c_uint32()
    gid = ctypes.c_uint32()
    if _load_libc().getpeereid(sock.fileno(), ctypes.byref(uid),
                               ctypes.byref(gid)) != 0:
        err = ctypes.get_errno()
        raise RpcError(f"cannot read peer credentials: {os.strerror(err)}")
    return {"uid": uid.value, "gid": gid.value, "pid": -1}


def send_frame(sock: socket.socket, payload: dict) -> None:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_FRAME:
        raise RpcError("frame exceeds the protocol bound")
    sock.sendall(raw + b"\n")


def read_frame(reader) -> dict | None:
    """Read one newline-delimited frame, refusing an over-long line.

    ``readline`` with an explicit limit matters: without it a peer can send a
    gigabyte with no newline and the daemon buffers all of it.
    """
    line = reader.readline(MAX_FRAME + 1)
    if not line:
        return None
    if len(line) > MAX_FRAME:
        raise RpcError("frame exceeds the protocol bound")
    try:
        value = json.loads(line)
    except json.JSONDecodeError as exc:
        raise RpcError(f"malformed frame: {exc}") from exc
    if not isinstance(value, dict):
        raise RpcError("frame must be a JSON object")
    return value


class RpcClient:
    """Client-plane handle on the authority plane.

    Holds no database connection, no keys, and no capability of its own — the
    daemon decides everything from the credentials the kernel reports.
    """

    def __init__(self, socket_path, timeout: float = 30.0):
        self.socket_path = str(socket_path)
        self.timeout = timeout
        self._sock = None
        self._reader = None

    def connect(self) -> "RpcClient":
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
        except OSError as exc:
            # EVERY connection failure is unavailability, not just the tidy
            # ones. A socket path over the sun_path limit, a stale socket file,
            # a permission error, a refused connection — each used to surface
            # as a different exception type, and a caller that catches only
            # some of them degrades to whatever it does on an unexpected error.
            # Failing closed means one type covers all of them.
            sock.close()
            raise ServiceUnavailable(
                f"no reachable contextd authority service at "
                f"{self.socket_path}: {type(exc).__name__}: {exc}. Hardened "
                f"mode fails closed — there is no direct-SQLite fallback "
                f"(docs/SECURITY.md, Deployment states)."
            ) from exc
        self._sock = sock
        self._reader = sock.makefile("rb")
        return self

    def call(self, op: str, **args):
        if self._sock is None:
            self.connect()
        send_frame(self._sock, {"v": PROTOCOL_VERSION, "op": op, "args": args})
        response = read_frame(self._reader)
        if response is None:
            raise ServiceUnavailable("authority service closed the connection")
        if not response.get("ok"):
            error = response.get("error") or {}
            raise RpcError(error.get("message", "refused"),
                           code=error.get("code", "refused"))
        return response.get("result")

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()
        if self._sock is not None:
            self._sock.close()
        self._sock = self._reader = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *_exc):
        self.close()
