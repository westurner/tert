"""Pytest tests for tert.did_agent."""

import base64
import os
import socket
import threading
import time

import pytest

from tert.crypto import ed25519_verify, pubkey_from_did_key
from tert.did_agent import (
    DEFAULT_SOCK_ENV,
    DidAgent,
    DidAgentClient,
    DidAgentError,
    DidAgentServer,
    decode_seed,
    generate_seed,
    handle_line,
    load_seed,
)

FIXED_SEED = bytes(range(1, 33))


class TestSeed:
    def test_generate_seed_length(self):
        assert len(generate_seed()) == 32

    def test_decode_seed_base64(self):
        text = base64.b64encode(FIXED_SEED).decode()
        assert decode_seed(text) == FIXED_SEED

    def test_decode_seed_hex(self):
        assert decode_seed(FIXED_SEED.hex()) == FIXED_SEED

    def test_decode_seed_invalid(self):
        with pytest.raises(ValueError):
            decode_seed("not-a-seed")

    def test_load_seed_env(self):
        env = {"DID_AGENT_SEED": base64.b64encode(FIXED_SEED).decode()}
        seed, source = load_seed(environ=env)
        assert seed == FIXED_SEED
        assert source == "env"

    def test_load_seed_file(self, tmp_path):
        f = tmp_path / "seed.txt"
        f.write_text(FIXED_SEED.hex())
        seed, source = load_seed(environ={}, seed_file=str(f))
        assert seed == FIXED_SEED
        assert source == "file"

    def test_load_seed_ephemeral(self):
        seed, source = load_seed(environ={})
        assert len(seed) == 32
        assert source == "ephemeral"


class TestAgentCore:
    def test_did_and_pubkey_consistent(self):
        agent = DidAgent(FIXED_SEED)
        assert agent.did.startswith("did:key:z6Mk")
        assert pubkey_from_did_key(agent.did) == agent.pubkey

    def test_sign_verify(self):
        agent = DidAgent(FIXED_SEED)
        sig = agent.sign(b"data")
        assert agent.verify(b"data", sig)
        assert ed25519_verify(agent.pubkey, b"data", sig)

    def test_bad_seed(self):
        with pytest.raises(ValueError):
            DidAgent(b"short")


class TestHandleLine:
    def setup_method(self):
        self.agent = DidAgent(FIXED_SEED)

    def test_ping(self):
        assert handle_line(self.agent, "PING") == "OK pong"

    def test_did(self):
        assert handle_line(self.agent, "DID") == "OK " + self.agent.did

    def test_pubkey(self):
        resp = handle_line(self.agent, "PUBKEY")
        assert base64.b64decode(resp[3:]) == self.agent.pubkey

    def test_sign(self):
        data = b"hello agent"
        encoded = base64.b64encode(data).decode()
        resp = handle_line(self.agent, "SIGN " + encoded)
        assert resp.startswith("OK ")
        sig = base64.b64decode(resp[3:])
        assert ed25519_verify(self.agent.pubkey, data, sig)

    def test_sign_missing_arg(self):
        assert handle_line(self.agent, "SIGN").startswith("ERR")

    def test_sign_bad_base64(self):
        assert handle_line(self.agent, "SIGN @@@@").startswith("ERR")

    def test_unknown(self):
        assert handle_line(self.agent, "FROBNICATE").startswith("ERR unknown command")

    def test_empty(self):
        assert handle_line(self.agent, "   ").startswith("ERR")

    def test_case_insensitive_command(self):
        assert handle_line(self.agent, "ping") == "OK pong"


@pytest.fixture
def running_agent(tmp_path):
    """Start a DidAgentServer in a background thread; yield (client, agent)."""
    sock_path = str(tmp_path / "agent.sock")
    agent = DidAgent(FIXED_SEED)
    server = DidAgentServer(sock_path, agent)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Wait for the socket to be accepting connections.
    for _ in range(100):
        if os.path.exists(sock_path):
            break
        time.sleep(0.01)
    client = DidAgentClient(sock_path)
    try:
        yield client, agent
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class TestClientServer:
    def test_ping(self, running_agent):
        client, _ = running_agent
        assert client.ping() == "pong"

    def test_did(self, running_agent):
        client, agent = running_agent
        assert client.did() == agent.did

    def test_pubkey(self, running_agent):
        client, agent = running_agent
        assert client.pubkey() == agent.pubkey

    def test_sign_roundtrip(self, running_agent):
        client, agent = running_agent
        data = b"sign me over the socket"
        sig = client.sign(data)
        assert ed25519_verify(agent.pubkey, data, sig)

    def test_socket_permissions(self, running_agent, tmp_path):
        client, _ = running_agent
        mode = os.stat(client.sock_path).st_mode & 0o777
        # Owner-only (no group/other) access.
        assert mode & 0o077 == 0

    def test_private_key_not_on_disk(self, running_agent, tmp_path):
        # The agent must not write any key material into the socket directory.
        client, _ = running_agent
        for name in os.listdir(tmp_path):
            assert "seed" not in name and "key" not in name


class TestClientErrors:
    def test_no_socket_configured(self, monkeypatch):
        monkeypatch.delenv(DEFAULT_SOCK_ENV, raising=False)
        with pytest.raises(DidAgentError):
            DidAgentClient()

    def test_client_reads_env_sock(self, monkeypatch):
        monkeypatch.setenv(DEFAULT_SOCK_ENV, "/tmp/whatever.sock")
        client = DidAgentClient()
        assert client.sock_path == "/tmp/whatever.sock"


class TestCli:
    def test_client_actions_via_running_agent(self, running_agent, capsys):
        from tert.did_agent import main

        client, agent = running_agent
        rc = main(["did", "--sock", client.sock_path])
        out = capsys.readouterr().out.strip()
        assert rc == 0
        assert out == agent.did

    def test_sign_action(self, running_agent, capsys):
        from tert.did_agent import main

        client, agent = running_agent
        rc = main(["sign", "hello", "--sock", client.sock_path])
        out = capsys.readouterr().out.strip()
        assert rc == 0
        sig = base64.b64decode(out)
        assert ed25519_verify(agent.pubkey, b"hello", sig)
