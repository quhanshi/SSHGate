"""Real loopback handshakes plus request-event retention and failure cases."""
from __future__ import annotations

import errno
import json
import shutil
import socket
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import paramiko

from ssh_gate.config import Config, Server
from ssh_gate.core import ApprovalManager
from ssh_gate.credentials import CredentialStore
from ssh_gate.prompts import PromptCancelled
from ssh_gate.ssh import SSHRunner, SSHSettings, RunResult
from ssh_gate.ssh_trace import MAX_CONNECTION_EVENTS, ObservedTransport, host_key_info, protocol_text
from test_ssh_login import SSHFixture, FixturePrompts


class SSHTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = SSHFixture()

    @classmethod
    def tearDownClass(cls):
        cls.fixture.close()

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.known = self.root / "known_hosts"
        self.settings = SSHSettings("127.0.0.1", "fixture", self.fixture.port, (),
                                    (str(self.known),), identities_only=True,
                                    connection_id="trace", host_alias="test-host")

    def runner(self, prompts=None, credentials=None):
        runner = SSHRunner(prompts or FixturePrompts(host_answer="once"), credentials)
        self.addCleanup(runner.close)
        return runner

    def run_connection(self, runner, settings=None, stop=None):
        events = []
        payload = SimpleNamespace(ssh_settings=settings or self.settings,
                                  remote_command="pwd", timeout_seconds=3)
        result = runner.execute(payload, lambda *args: None, stop or threading.Event(),
                                lambda **values: events.append(values))
        trace = [{**e["connection_event"], "context": e["connection_context"]}
                 for e in events if "connection_event" in e]
        return result, trace

    def save_key(self, key=None):
        key = key or self.fixture.key
        self.known.write_text(f"{self.settings.verification_name} {key.get_name()} {key.get_base64()}\n")

    def test_real_events_match_negotiated_transport_and_have_ordered_clocks(self):
        self.save_key()
        runner = self.runner()
        result, events = self.run_connection(runner)
        self.assertEqual(0, result.exit_code, result.error)
        final = events[-1]
        self.assertEqual("connected", final["event"])
        self.assertEqual("password", final["data"]["auth_method"])
        transport = runner._clients[self.settings].get_transport()
        self.assertEqual(transport.local_cipher, final["data"]["cipher_out"])
        self.assertEqual(transport.remote_cipher, final["data"]["cipher_in"])
        self.assertIn(final["data"]["kex"], transport.preferred_kex)
        self.assertEqual(transport.host_key_type, final["data"]["host_key_algorithm"])
        self.assertEqual(host_key_info(self.fixture.key)["fingerprint"], final["data"]["fingerprint"])
        current = [e["event"] for e in events if e["attempt"] == final["attempt"]]
        expected = ["dns_started", "dns_resolved", "tcp_started", "tcp_connected",
                    "ssh_handshake_started", "banner_received", "key_exchange_started",
                    "algorithms_negotiated", "host_key_received", "host_key_verified",
                    "authentication_started", "authentication_method_started", "authenticated", "connected"]
        self.assertEqual(sorted(current.index(e) for e in expected), [current.index(e) for e in expected])
        self.assertEqual(sorted(e["elapsed_ms"] for e in events), [e["elapsed_ms"] for e in events])
        self.assertTrue(all(e["context"]["role"] == "target" and e["context"]["hop_index"] == 1 for e in events))
        self.assertNotIn("fixture-only-password", json.dumps(events))

    def test_unknown_host_requires_confirmation_and_reuse_does_not_replay(self):
        prompts = FixturePrompts(host_answer="once")
        runner = self.runner(prompts)
        result, first = self.run_connection(runner)
        self.assertEqual(0, result.exit_code, result.error)
        names = [e["event"] for e in first]
        self.assertLess(names.index("host_key_confirmation_required"), names.index("host_key_verified"))
        self.assertEqual("user_once", next(e for e in first if e["event"] == "host_key_verified")["data"]["source"])
        self.assertFalse(self.known.exists())
        result, second = self.run_connection(runner)
        self.assertEqual(0, result.exit_code, result.error)
        self.assertEqual(["connection_started", "connection_reused"], [e["event"] for e in second])
        self.assertEqual(0, second[-1]["attempt"])
        self.assertEqual(first[-1]["data"]["fingerprint"], second[-1]["data"]["fingerprint"])
        transport = runner._clients[self.settings].get_transport()
        self.assertIsNone(transport.connection_trace)
        # A retained connection can rekey after the originating request ended.
        # Its old request callback must stay detached.
        transport.renegotiate_keys()
        self.assertTrue(transport.is_authenticated())

    def test_wrong_known_host_key_stops_before_authentication(self):
        self.save_key(paramiko.RSAKey.generate(2048))
        result, events = self.run_connection(self.runner())
        self.assertIsNone(result.exit_code)
        self.assertEqual("host_key_mismatch", events[-1]["data"]["code"])
        self.assertEqual(host_key_info(self.fixture.key)["fingerprint"], events[-1]["data"]["fingerprint"])
        self.assertNotIn("authentication_started", [e["event"] for e in events])
        self.assertNotIn("connected", [e["event"] for e in events])

    def test_rejected_host_key_is_a_distinct_failure(self):
        result, events = self.run_connection(self.runner(FixturePrompts(host_answer="reject")))
        self.assertTrue(result.disconnected)
        self.assertEqual("host_key_rejected", events[-1]["data"]["code"])
        self.assertNotIn("host_key_verified", [e["event"] for e in events])

    def test_local_prompt_cancel_has_no_authenticated_or_connected_event(self):
        prompts = FixturePrompts()
        prompts.ask = Mock(side_effect=PromptCancelled("fixture cancellation"))
        result, events = self.run_connection(self.runner(prompts))
        self.assertTrue(result.disconnected)
        self.assertEqual("connection_cancelled", events[-1]["event"])
        self.assertEqual("cancelled", events[-1]["data"]["code"])
        self.assertNotIn("authenticated", [e["event"] for e in events])

    def test_password_retry_exhaustion_keeps_attempts_and_never_emits_secrets(self):
        self.save_key()
        secret = "wrong-fixture-secret-not-for-events"
        result, events = self.run_connection(self.runner(FixturePrompts(password=secret)))
        self.assertIsNone(result.exit_code)
        self.assertEqual("authentication_failed", events[-1]["data"]["code"])
        attempts = [e["attempt"] for e in events if e["event"] == "attempt_started"]
        self.assertEqual([1, 2, 3, 4], attempts)
        self.assertEqual(3, sum(e["event"] == "credentials_required" for e in events))
        self.assertNotIn(secret, json.dumps(events))
        self.assertNotIn("authenticated", [e["event"] for e in events])

    def test_stale_saved_password_retries_then_reports_actual_authentication(self):
        self.save_key()
        store = CredentialStore(self.root / "credentials")
        ref = store.reference("trace", "fixture", self.settings.hostname, self.settings.port)
        store.save(ref, "password", "stale-secret-not-for-events")
        result, events = self.run_connection(self.runner(credentials=store))
        self.assertEqual(0, result.exit_code, result.error)
        self.assertIn("saved_credential_selected", [e["event"] for e in events])
        self.assertTrue(any(e["event"] == "authentication_retry" and e["data"]["source"] == "saved" for e in events))
        self.assertFalse(store.has(ref))
        self.assertNotIn("stale-secret-not-for-events", json.dumps(events))
        self.assertEqual(3, events[-1]["attempt"])

    def test_real_tcp_refusal_is_not_reported_as_timeout(self):
        sock = socket.socket()
        self.addCleanup(sock.close)
        sock.bind(("127.0.0.1", 0))  # no listen: an actual refused TCP connection
        result, events = self.run_connection(self.runner(), replace(self.settings, port=sock.getsockname()[1]))
        self.assertFalse(result.timed_out)
        self.assertEqual("connection_refused", events[-1]["data"]["code"])
        self.assertEqual("tcp", events[-1]["stage"])
        self.assertNotIn("ssh_handshake_started", [e["event"] for e in events])

    def test_dns_failure_stops_at_dns(self):
        with patch("ssh_gate.ssh.socket.getaddrinfo", side_effect=socket.gaierror(-2, "fixture DNS failure")):
            result, events = self.run_connection(self.runner())
        self.assertIsNone(result.exit_code)
        self.assertEqual("dns_failed", events[-1]["data"]["code"])
        self.assertEqual("dns", events[-1]["stage"])

    def test_tcp_timeout_and_nonblocking_deadline_preserve_timeout_kind(self):
        for code in (errno.ETIMEDOUT, errno.EINPROGRESS):
            with self.subTest(code=code):
                network = Mock()
                network.connect_ex.return_value = code
                clock = [0]
                def advance():
                    clock[0] += 20
                    return clock[0]
                with patch("ssh_gate.ssh.socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 22))]), \
                     patch("ssh_gate.ssh.socket.socket", return_value=network), \
                     patch("ssh_gate.ssh.time.monotonic", side_effect=advance):
                    result, events = self.run_connection(self.runner())
                self.assertTrue(result.timed_out)
                self.assertEqual("timeout", events[-1]["data"]["code"])
                self.assertEqual("tcp", events[-1]["stage"])
                network.close.assert_called()

    def test_real_algorithm_mismatch_has_no_host_verification_or_authentication(self):
        class LimitedTransport(paramiko.Transport):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.get_security_options().kex = ("diffie-hellman-group14-sha256",)
        fixture = SSHFixture(transport_factory=LimitedTransport)
        self.addCleanup(fixture.close)
        settings = replace(self.settings, port=fixture.port)
        with patch.object(ObservedTransport, "_preferred_kex", ("curve25519-sha256@libssh.org",)):
            result, events = self.run_connection(self.runner(), settings)
        self.assertIsNone(result.exit_code)
        self.assertEqual("algorithm_mismatch", events[-1]["data"]["code"])
        self.assertEqual("key_exchange", events[-1]["stage"])
        self.assertFalse(fixture.authentications)
        self.assertNotIn("algorithms_negotiated", [e["event"] for e in events])

    def test_silent_server_times_out_at_banner_without_fake_handshake_events(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(2)
        release = threading.Event()
        def silent_server():
            try:
                connection, _ = listener.accept()
                with connection:
                    release.wait(3)
            except OSError:
                pass
        server = threading.Thread(target=silent_server, daemon=True)
        server.start()
        original = ObservedTransport._check_banner
        def short_banner_timeout(transport):
            transport.banner_timeout = 0.05
            return original(transport)
        try:
            with patch.object(ObservedTransport, "_check_banner", short_banner_timeout):
                result, events = self.run_connection(self.runner(), replace(self.settings, port=listener.getsockname()[1]))
        finally:
            release.set()
            listener.close()
            server.join(2)
        self.assertTrue(result.timed_out, result.error)
        self.assertEqual("timeout", events[-1]["data"]["code"])
        self.assertEqual("ssh_banner", events[-1]["stage"])
        self.assertNotIn("banner_received", [e["event"] for e in events])
        self.assertNotIn("algorithms_negotiated", [e["event"] for e in events])

    def test_version_token_excludes_free_text_and_controls(self):
        self.assertEqual("SSH-2.0-fixture", protocol_text("SSH-2.0-fixture secret=private-comment"))
        self.assertNotIn("\x1b", protocol_text("SSH-2.0-fixture\x1b[31m"))
        self.assertLessEqual(len(protocol_text("x" * 1000)), 255)


class TraceRetentionTests(unittest.TestCase):
    def test_request_events_are_bounded_sequenced_copied_and_absent_from_summaries(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        config = Config(root, 18765, 10, 3600, 4096, shutil.which("ssh") or "ssh.exe",
                        (Server("server", "Fixture", "user@127.0.0.1"),))
        callbacks = []
        class Runner:
            def execute(self, payload, emit, stop, progress):
                callbacks.append(progress)
                event = {"event": "tcp_started", "data": {"port": 22}}
                for _ in range(MAX_CONNECTION_EVENTS + 7):
                    progress(connection_event=event, connection_context={"role": "target", "hop_index": 1})
                event["data"]["port"] = 0
                return RunResult(0)
        manager = ApprovalManager(config, runner=Runner())
        self.addCleanup(manager.close)
        manager.local_gui_heartbeat()
        view = manager.submit("server", "pwd", "trace fixture", "trace-test")
        manager.local_approve(view["request_id"], view["digest"])
        for worker in manager._workers:
            worker.join(3)
        detail = manager.get(view["request_id"])
        self.assertEqual("succeeded", detail["status"])
        self.assertEqual(MAX_CONNECTION_EVENTS + 7, detail["connection_event_seq"])
        self.assertEqual(MAX_CONNECTION_EVENTS, len(detail["connection_events"]))
        self.assertEqual(7, detail["connection_events_dropped"])
        self.assertEqual(8, detail["connection_events"][0]["seq"])
        self.assertEqual(22, detail["connection_events"][0]["data"]["port"])
        detail["connection_events"][0]["data"]["port"] = 0
        self.assertEqual(22, manager.get(view["request_id"])["connection_events"][0]["data"]["port"])
        summary = manager.list_summaries()[0]
        self.assertEqual(detail["connection_event_seq"], summary["connection_event_seq"])
        self.assertNotIn("connection_events", summary)
        callbacks[0](connection_event={"event": "late", "data": {}})
        self.assertEqual(detail["connection_event_seq"], manager.get(view["request_id"])["connection_event_seq"])


if __name__ == "__main__":
    unittest.main()
