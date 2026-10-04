from __future__ import annotations

import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

import paramiko

from ssh_gate.config import Config, Server
from ssh_gate.credentials import CredentialStore
from ssh_gate.prompts import PromptCancelled
from ssh_gate.ssh import SSHRunner, SSHSettings, known_host_candidates, load_preferred_host_keys, resolve_settings


class FixturePrompts:
    def __init__(self, host_answer="save", password="fixture-only-password", remember=False):
        self.calls = []
        self.host_answer = host_answer
        self.password = password
        self.remember = remember

    def ask(self, kind, data, _stop, timeout=120):
        self.calls.append((kind, data))
        return self.host_answer if kind == "host_key" else {"secret": self.password, "mode": "password", "remember": self.remember}

    def close(self):
        pass


class PasswordServer(paramiko.ServerInterface):
    def __init__(self, fixture):
        self.fixture = fixture

    def get_allowed_auths(self, _username):
        return "password"

    def check_auth_password(self, username, password):
        if username == "fixture" and password == "fixture-only-password":
            self.fixture.authentications += 1
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, _chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        self.fixture.commands.append(command.decode())
        def respond():
            time.sleep(0.03)
            try:
                channel.send("完成\n".encode())
                channel.send_stderr(b"fixture stderr\n")
                if command == b"wait":
                    self.fixture.stop.wait(10)
                channel.send_exit_status(0)
                channel.close()
            except (OSError, EOFError):
                pass
        threading.Thread(target=respond, daemon=True).start()
        return True


class SSHFixture:
    def __init__(self, server_factory=PasswordServer, transport_factory=paramiko.Transport):
        self.server_factory = server_factory
        self.transport_factory = transport_factory
        self.key = paramiko.RSAKey.generate(2048)
        self.commands = []
        self.authentications = 0
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(10)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.transports = []
        self.channels = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                connection, _address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            transport = self.transport_factory(connection)
            transport.add_server_key(self.key)
            self.transports.append(transport)
            def handshake(transport=transport):
                try:
                    server = self.server_factory(self)
                    transport.start_server(server=server)
                    while transport.is_active() and not self.stop.is_set():
                        channel = transport.accept(0.2)
                        if channel:
                            self.channels.append(channel)
                            if hasattr(server, "forward"): server.forward(channel)
                except (OSError, EOFError, paramiko.SSHException):
                    pass
                finally:
                    transport.close()
            threading.Thread(target=handshake, daemon=True).start()

    def close(self):
        self.stop.set()
        self.listener.close()
        for transport in self.transports:
            transport.close()
        self.thread.join(timeout=2)


class SSHLoginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = SSHFixture()

    @classmethod
    def tearDownClass(cls):
        cls.fixture.close()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "known_hosts"
        self.settings = SSHSettings("127.0.0.1", "fixture", self.fixture.port, (), (str(self.path),))
        self.initial_commands = len(self.fixture.commands)
        self.output = {"stdout": bytearray(), "stderr": bytearray()}

    def emit(self, name, data):
        self.output[name].extend(data)

    def payload(self, command="pwd"):
        return SimpleNamespace(ssh_settings=self.settings, remote_command=command, timeout_seconds=3)

    def save_key(self, key=None, hashed=False):
        key = key or self.fixture.key
        name = self.settings.verification_name
        if hashed:
            name = paramiko.HostKeys.hash_host(name)
        self.path.write_text(f"{name} {key.get_name()} {key.get_base64()}\n")

    def test_password_login_reuses_authenticated_connection_and_executes_once(self):
        self.save_key()
        prompts = FixturePrompts()
        runner = SSHRunner(prompts)
        self.addCleanup(runner.close)
        one = runner(self.payload(), self.emit, threading.Event())
        two = runner(self.payload("ls"), self.emit, threading.Event())
        self.assertEqual(0, one.exit_code, one.error)
        self.assertEqual(0, two.exit_code, two.error)
        self.assertEqual(["credentials"], [kind for kind, _data in prompts.calls])
        self.assertEqual(["pwd", "ls"], self.fixture.commands[self.initial_commands:])
        self.assertIn("完成".encode(), self.output["stdout"])
        self.assertIn(b"fixture stderr", self.output["stderr"])
        self.assertNotIn(b"fixture-only-password", self.path.read_bytes())

    def test_remembered_password_is_reused_without_prompt_and_not_stored_plaintext(self):
        self.save_key()
        settings = replace(self.settings, connection_id="server-a")
        store = CredentialStore(Path(self.temp.name) / "credentials")
        prompts = FixturePrompts(remember=True)
        first = SSHRunner(prompts, store)
        result = first(SimpleNamespace(ssh_settings=settings, remote_command="pwd", timeout_seconds=3), self.emit, threading.Event())
        first.close()
        self.assertEqual(0, result.exit_code, result.error)
        self.assertEqual(["credentials"], [kind for kind, _ in prompts.calls])
        self.assertNotIn("fixture-only-password", store.path.read_text(encoding="utf-8"))

        second_prompts = FixturePrompts()
        second = SSHRunner(second_prompts, store)
        self.addCleanup(second.close)
        result = second(SimpleNamespace(ssh_settings=settings, remote_command="ls", timeout_seconds=3), self.emit, threading.Event())
        self.assertEqual(0, result.exit_code, result.error)
        self.assertEqual([], second_prompts.calls)

    def test_stale_saved_password_is_removed_before_local_prompt(self):
        self.save_key()
        settings = replace(self.settings, connection_id="server-a")
        store = CredentialStore(Path(self.temp.name) / "credentials")
        ref = store.reference(settings.connection_id, settings.username, settings.hostname, settings.port)
        store.save(ref, "password", "stale-fixture-password")
        prompts = FixturePrompts()
        runner = SSHRunner(prompts, store)
        self.addCleanup(runner.close)
        result = runner(SimpleNamespace(ssh_settings=settings, remote_command="pwd", timeout_seconds=3), self.emit, threading.Event())
        self.assertEqual(0, result.exit_code, result.error)
        self.assertEqual(["credentials"], [kind for kind, _ in prompts.calls])
        self.assertFalse(store.has(ref))

    def test_new_host_key_is_confirmed_locally_and_saved(self):
        prompts = FixturePrompts()
        runner = SSHRunner(prompts)
        self.addCleanup(runner.close)
        result = runner(self.payload(), self.emit, threading.Event())
        self.assertEqual(0, result.exit_code, result.error)
        self.assertEqual(["host_key", "credentials"], [kind for kind, _data in prompts.calls])
        self.assertTrue(paramiko.HostKeys(str(self.path)).check(self.settings.verification_name, self.fixture.key))

    def test_unknown_host_can_be_trusted_for_session_without_writing(self):
        prompts = FixturePrompts(host_answer="once")
        runner = SSHRunner(prompts)
        self.addCleanup(runner.close)
        result = runner(self.payload(), self.emit, threading.Event())
        self.assertEqual(0, result.exit_code, result.error)
        self.assertFalse(self.path.exists())
        self.assertEqual(1, sum(kind == "host_key" for kind, _ in prompts.calls))

    def test_wrong_known_key_rejects_without_password_prompt_or_execution(self):
        self.save_key(paramiko.RSAKey.generate(2048))
        prompts = FixturePrompts()
        runner = SSHRunner(prompts)
        self.addCleanup(runner.close)
        result = runner(self.payload(), self.emit, threading.Event())
        self.assertIsNone(result.exit_code)
        self.assertIn("指纹", result.error)
        self.assertFalse(prompts.calls)
        self.assertEqual(self.initial_commands, len(self.fixture.commands))

    def test_hashed_known_hosts_entry_is_recognized(self):
        self.save_key(hashed=True)
        prompts = FixturePrompts()
        runner = SSHRunner(prompts)
        self.addCleanup(runner.close)
        result = runner(self.payload(), self.emit, threading.Event())
        self.assertEqual(0, result.exit_code, result.error)
        self.assertEqual(["credentials"], [kind for kind, _ in prompts.calls])

    def test_first_known_hosts_file_takes_precedence(self):
        self.save_key()
        extra = self.path.with_name("extra_known_hosts")
        other = paramiko.RSAKey.generate(2048)
        extra.write_text(f"{self.settings.verification_name} {other.get_name()} {other.get_base64()}\n")
        client = paramiko.SSHClient()
        settings = SSHSettings("127.0.0.1", "fixture", self.fixture.port, (), (str(self.path), str(extra)))
        load_preferred_host_keys(client, settings)
        self.assertTrue(client.get_host_keys().check(self.settings.verification_name, self.fixture.key))
        client.close()

    def test_rejected_new_host_never_executes(self):
        prompts = FixturePrompts(host_answer="reject")
        runner = SSHRunner(prompts)
        self.addCleanup(runner.close)
        result = runner(self.payload(), self.emit, threading.Event())
        self.assertTrue(result.disconnected)
        self.assertEqual(self.initial_commands, len(self.fixture.commands))
        self.assertFalse(self.path.exists())


    def test_wrong_password_never_executes(self):
        self.save_key()
        prompts = FixturePrompts(password="wrong-fixture-password")
        runner = SSHRunner(prompts)
        self.addCleanup(runner.close)
        result = runner(self.payload(), self.emit, threading.Event())
        self.assertIn("认证失败", result.error)
        self.assertEqual(3, len(prompts.calls))
        self.assertEqual(self.initial_commands, len(self.fixture.commands))
        self.assertNotIn("wrong-fixture-password", result.error)

    def test_cancelled_password_prompt_never_executes(self):
        self.save_key()
        class CancelPrompts(FixturePrompts):
            def ask(self, *args, **kwargs):
                raise PromptCancelled("fixture cancellation")
        runner = SSHRunner(CancelPrompts())
        self.addCleanup(runner.close)
        result = runner(self.payload(), self.emit, threading.Event())
        self.assertTrue(result.disconnected)
        self.assertEqual(self.initial_commands, len(self.fixture.commands))

    def test_closed_runner_never_connects(self):
        prompts = FixturePrompts()
        runner = SSHRunner(prompts)
        runner.close()
        result = runner(self.payload(), self.emit, threading.Event())
        self.assertTrue(result.disconnected)
        self.assertFalse(prompts.calls)
        self.assertEqual(self.initial_commands, len(self.fixture.commands))


class LocalSSHDiscoveryTests(unittest.TestCase):
    def test_candidates_keep_plain_addresses_ports_and_skip_hashed_names(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "known_hosts"
            path.write_text("# comment\nserver.example,10.0.0.2 ssh-ed25519 fixture\n"
                            "[other.example]:2222 ssh-ed25519 fixture\n"
                            "[2001:db8::1]:2200 ssh-ed25519 fixture\n"
                            "server.example ssh-rsa fixture\n"
                            "|1|fixture|fixture ssh-ed25519 fixture\n"
                            "@revoked blocked.example ssh-ed25519 fixture\n"
                            "*.example ssh-ed25519 fixture\n")
            self.assertEqual((("server.example", None), ("10.0.0.2", None),
                              ("other.example", 2222), ("2001:db8::1", 2200)), known_host_candidates(path))

    def test_alias_resolution_prefers_default_known_hosts_and_never_logs_in(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / ".ssh").mkdir()
            (home / ".ssh/config").write_text("Host fixture-alias\n HostName fixture.example\n"
                                             " User fixture\n Port 2222\n UserKnownHostsFile ~/extra_known_hosts\n")
            config = Config(home, 18765, 10, 60, 4096, "", ())
            with patch("ssh_gate.ssh.Path.home", return_value=home):
                settings = resolve_settings(config, Server("s", "Fixture", "fixture-alias"))
            self.assertEqual("fixture.example", settings.hostname)
            self.assertEqual("fixture", settings.username)
            self.assertEqual(2222, settings.port)
            self.assertEqual(str(home / ".ssh/known_hosts"), settings.known_hosts_files[0])


if __name__ == "__main__":
    unittest.main()
