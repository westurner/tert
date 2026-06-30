#!/usr/bin/env python3
"""
did_agent.py - an ssh-agent-style signing agent for an Ed25519 ``did:key``.

The agent holds the private key (a 32-byte Ed25519 seed) in memory only and
signs requests over a Unix domain socket. The private key is never written to
disk by the agent, which addresses the weakness of leaving a DID key
unprotected on disk: clients sign through the agent instead of reading a key
file.

Wire protocol (newline-delimited UTF-8 over ``AF_UNIX``):

    PING              -> OK pong
    DID               -> OK did:key:z6Mk...
    PUBKEY            -> OK <base64 public key>
    SIGN <base64>     -> OK <base64 signature>   (Ed25519 over the decoded bytes)
    <anything else>   -> ERR <message>

Usage:
    tert did-agent [serve] [--sock PATH] [--seed-file FILE] [--print-env] [--once]
    tert did-agent did    [--sock PATH]
    tert did-agent pubkey [--sock PATH]
    tert did-agent sign   [--sock PATH] [DATA]
    tert did-agent ping   [--sock PATH]
"""

import os
import sys
import base64
import socket
import argparse
import tempfile
import threading
import socketserver
from typing import Optional, Sequence, Tuple

from .crypto import (
    SEED_BYTES,
    ed25519_publickey,
    ed25519_sign,
    ed25519_verify,
    did_key_from_pubkey,
)

DEFAULT_SOCK_ENV = "DID_AGENT_SOCK"
SEED_ENV = "DID_AGENT_SEED"


# ---------------------------------------------------------------------------
# Seed handling
# ---------------------------------------------------------------------------


def generate_seed() -> bytes:
    """Generate a fresh random 32-byte Ed25519 seed."""
    return os.urandom(SEED_BYTES)


def decode_seed(text: str) -> bytes:
    """Decode a seed from base64 or hex text; must be 32 bytes."""
    text = text.strip()
    seed: Optional[bytes] = None
    try:
        seed = base64.b64decode(text, validate=True)
    except (ValueError, base64.binascii.Error):
        seed = None
    if seed is None or len(seed) != SEED_BYTES:
        try:
            candidate = bytes.fromhex(text)
        except ValueError:
            candidate = b""
        if len(candidate) == SEED_BYTES:
            seed = candidate
    if seed is None or len(seed) != SEED_BYTES:
        raise ValueError("seed must decode to %d bytes (base64 or hex)" % SEED_BYTES)
    return seed


def load_seed(
    environ: Optional[dict] = None,
    seed_file: Optional[str] = None,
) -> Tuple[bytes, str]:
    """Resolve the agent seed. Returns ``(seed, source)``.

    Precedence: ``DID_AGENT_SEED`` env var, then ``--seed-file``, then a freshly
    generated ephemeral key.
    """
    env = environ if environ is not None else os.environ
    if env.get(SEED_ENV):
        return decode_seed(env[SEED_ENV]), "env"
    if seed_file:
        with open(seed_file, "r", encoding="utf-8") as fh:
            return decode_seed(fh.read()), "file"
    return generate_seed(), "ephemeral"


# ---------------------------------------------------------------------------
# Agent core
# ---------------------------------------------------------------------------


class DidAgent:
    """Holds an Ed25519 seed in memory and signs with it."""

    def __init__(self, seed: bytes) -> None:
        if len(seed) != SEED_BYTES:
            raise ValueError("seed must be %d bytes" % SEED_BYTES)
        self._seed = seed
        self._pubkey = ed25519_publickey(seed)
        self.did = did_key_from_pubkey(self._pubkey)

    @property
    def pubkey(self) -> bytes:
        return self._pubkey

    def sign(self, data: bytes) -> bytes:
        return ed25519_sign(self._seed, data, self._pubkey)

    def verify(self, data: bytes, sig: bytes) -> bool:
        return ed25519_verify(self._pubkey, data, sig)


def handle_line(agent: DidAgent, line: str) -> str:
    """Process a single protocol request line and return the response line."""
    line = line.strip()
    if not line:
        return "ERR empty request"
    parts = line.split(" ", 1)
    cmd = parts[0].upper()
    arg = parts[1] if len(parts) > 1 else ""

    if cmd == "PING":
        return "OK pong"
    if cmd == "DID":
        return "OK " + agent.did
    if cmd == "PUBKEY":
        return "OK " + base64.b64encode(agent.pubkey).decode("ascii")
    if cmd == "SIGN":
        if not arg:
            return "ERR SIGN requires base64 data"
        try:
            data = base64.b64decode(arg, validate=True)
        except (ValueError, base64.binascii.Error):
            return "ERR invalid base64"
        sig = agent.sign(data)
        return "OK " + base64.b64encode(sig).decode("ascii")
    return "ERR unknown command: " + cmd


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        agent: DidAgent = self.server.agent  # type: ignore[attr-defined]
        for raw in self.rfile:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if not line:
                continue
            response = handle_line(agent, line)
            self.wfile.write((response + "\n").encode("utf-8"))
            self.wfile.flush()
            if getattr(self.server, "once", False):
                break


class DidAgentServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """Threaded Unix-socket server that signs with an in-memory key."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, sock_path: str, agent: DidAgent, once: bool = False) -> None:
        self.agent = agent
        self.once = once
        self.sock_path = sock_path
        if os.path.exists(sock_path):
            os.unlink(sock_path)
        # Create the socket with owner-only permissions.
        old_umask = os.umask(0o077)
        try:
            super().__init__(sock_path, _Handler)
        finally:
            os.umask(old_umask)

    def server_close(self) -> None:
        super().server_close()
        try:
            if os.path.exists(self.sock_path):
                os.unlink(self.sock_path)
        except OSError:
            pass


def default_sock_path() -> str:
    """Default agent socket path, in a per-user runtime directory."""
    runtime = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
    return os.path.join(runtime, "tert-did-agent-%d.sock" % os.getpid())


def serve(
    sock_path: str,
    agent: DidAgent,
    once: bool = False,
    ready: Optional[threading.Event] = None,
) -> DidAgentServer:
    """Create and run a :class:`DidAgentServer` (blocking)."""
    server = DidAgentServer(sock_path, agent, once=once)
    if ready is not None:
        ready.set()
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return server


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class DidAgentError(Exception):
    pass


class DidAgentClient:
    """Client for a running :class:`DidAgentServer`."""

    def __init__(self, sock_path: Optional[str] = None) -> None:
        self.sock_path = sock_path or os.environ.get(DEFAULT_SOCK_ENV)
        if not self.sock_path:
            raise DidAgentError(
                "no agent socket (set %s or pass sock_path)" % DEFAULT_SOCK_ENV
            )

    def _request(self, line: str, timeout: float = 10.0) -> str:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(self.sock_path)
            sock.sendall((line + "\n").encode("utf-8"))
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        response = buf.split(b"\n", 1)[0].decode("utf-8", "replace")
        if not response.startswith("OK"):
            raise DidAgentError(
                response[4:] if response.startswith("ERR ") else response
            )
        return response[3:] if len(response) > 2 else ""

    def ping(self) -> str:
        return self._request("PING")

    def did(self) -> str:
        return self._request("DID")

    def pubkey(self) -> bytes:
        return base64.b64decode(self._request("PUBKEY"))

    def sign(self, data: bytes) -> bytes:
        encoded = base64.b64encode(data).decode("ascii")
        return base64.b64decode(self._request("SIGN " + encoded))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _print_env(sock_path: str, did: str) -> None:
    print("%s=%s; export %s;" % (DEFAULT_SOCK_ENV, sock_path, DEFAULT_SOCK_ENV))
    print("# did: %s" % did)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tert did-agent",
        description="ssh-agent-style Ed25519 did:key signing agent (key held in memory)",
    )
    parser.add_argument(
        "action",
        nargs="?",
        default="serve",
        choices=["serve", "did", "pubkey", "sign", "ping"],
        help="serve the agent (default), or act as a client",
    )
    parser.add_argument("data", nargs="?", help="data to sign (for the sign action)")
    parser.add_argument("--sock", help="agent socket path")
    parser.add_argument("--seed-file", help="file containing a base64/hex 32-byte seed")
    parser.add_argument(
        "--print-env",
        action="store_true",
        help="print the DID_AGENT_SOCK export line on startup",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="handle a single request then exit (for testing)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.action == "serve":
        seed, source = load_seed(seed_file=args.seed_file)
        agent = DidAgent(seed)
        sock_path = args.sock or os.environ.get(DEFAULT_SOCK_ENV) or default_sock_path()
        if args.print_env:
            _print_env(sock_path, agent.did)
        else:
            print("did-agent listening on %s" % sock_path, file=sys.stderr)
            print("did: %s (seed source: %s)" % (agent.did, source), file=sys.stderr)
        try:
            serve(sock_path, agent, once=args.once)
        except KeyboardInterrupt:
            return 0
        return 0

    # Client actions.
    try:
        client = DidAgentClient(args.sock)
        if args.action == "ping":
            print(client.ping())
        elif args.action == "did":
            print(client.did())
        elif args.action == "pubkey":
            print(base64.b64encode(client.pubkey()).decode("ascii"))
        elif args.action == "sign":
            data = (args.data or "").encode("utf-8")
            print(base64.b64encode(client.sign(data)).decode("ascii"))
    except DidAgentError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
