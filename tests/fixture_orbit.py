"""Manually stepped SSH telemetry fixture. Never contacts a real SSH server."""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
from pathlib import Path

from fixture_desktop import FixtureRunner, make_fixture, frontend_html, PromptCancelled
from ssh_gate.ssh import RunResult
from ssh_gate.ssh_trace import ConnectionTrace


class OrbitRunner(FixtureRunner):
    def execute(self, payload, emit, stop, progress):
        self.finished = threading.Event()
        self.outcome = "succeeded"
        self.server_id = payload.server_id
        self.context = {"host_alias": payload.server_id, "hostname": payload.ssh_settings.hostname,
                        "port": payload.ssh_settings.port, "role": "target", "hop_index": 1, "hop_count": 1}
        self.trace = ConnectionTrace(lambda **values: progress(connection_context=dict(self.context), **values), time.monotonic())
        self.trace.emit("connection_started", stage="connecting")
        self.trace.attempt = 1
        self.trace.emit("attempt_started", stage="connecting")
        self.trace.emit("dns_started", stage="dns")
        while not self.finished.wait(.02):
            if stop.is_set():
                self.trace.emit("connection_cancelled", code="cancelled")
                return RunResult(None, disconnected=True)
        self.trace.close()
        if self.outcome == "succeeded":
            return RunResult(0, result={"hostname": payload.ssh_settings.hostname, "default_cwd_exists": True})
        return RunResult(None, error="Fixture: " + self.outcome, timed_out=self.outcome == "timeout")

    def advance(self, event, stage=None, data=None, context=None, attempt=None, finish=None):
        if context is not None:
            self.context.update(context)
        if attempt is not None:
            self.trace.attempt = attempt
        self.trace.emit(event, stage=stage, **(data or {}))
        if event in {"connected", "connection_reused"} and self.context["role"] == "target":
            self.connected[self.server_id] = True
        if finish:
            self.outcome = finish
            self.finished.set()
        return {"ok": True}

    def ask_key(self, fingerprint):
        def ask():
            try:
                self.prompts.ask("host_key", {**self.context, "key_type": "ssh-ed25519",
                    "fingerprint": fingerprint, "known_hosts_file": "~/.ssh/known_hosts"}, self.finished)
                self.trace.emit("host_key_verified", stage="host_key", source="user_once")
            except PromptCancelled:
                self.advance("connection_failed", "host_key", {"code": "host_key_rejected"}, finish="rejected")
        threading.Thread(target=ask, daemon=True).start()
        return {"ok": True}


def main():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        api, _manager, runner, _host, _tunnel = make_fixture(root, runner_factory=OrbitRunner)
        html = Path(sys.argv[1])
        html.write_text(frontend_html(Path(__file__).resolve().parents[1], api._token), encoding="utf-8")
        print(json.dumps({"ready": True, "html": str(html)}), flush=True)
        try:
            for line in sys.stdin:
                request = json.loads(line)
                method = request["method"]
                if method == "fixture_advance":
                    result = runner.advance(**request["args"][0])
                elif method == "fixture_ask_key":
                    result = runner.ask_key(request["args"][0])
                elif method.startswith("_") or not callable(getattr(api, method, None)):
                    raise ValueError("fixture method rejected")
                else:
                    result = getattr(api, method)(api._token, *request.get("args", []))
                print(json.dumps({"id": request["id"], "result": result}, ensure_ascii=False), flush=True)
        finally:
            api._close()


if __name__ == "__main__":
    main()
