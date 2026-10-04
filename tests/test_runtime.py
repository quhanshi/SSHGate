from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from dataclasses import replace
from unittest.mock import patch

from ssh_gate.config import load_config
from ssh_gate.runtime import TunnelRuntime, redact_log


class FakeProcess:
    def __init__(self):
        self.stdout=io.StringIO("runtime / fixture-secret-key\n")
        self.code=None

    def poll(self):return self.code
    def wait(self,timeout=None):self.code=0;return 0
    def terminate(self):self.code=0
    def kill(self):self.code=-9


class TunnelRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.binary=self.root/"fixture-client.exe";self.binary.write_bytes(b"fixture")
        values={"servers":[],"tunnel":{"id":"tunnel_"+"a"*32,"client_path":str(self.binary),"health_port":18766}}
        (self.root/"config.json").write_text(json.dumps(values))
        self.config=load_config(self.root/"config.json")
        self.runtime=TunnelRuntime(self.root,self.root);self.addCleanup(self.runtime.close)

    def test_runtime_uses_private_env_never_command_argv(self):
        captured={}
        def launch(argv,**kwargs):
            captured.update(argv=argv,env=kwargs["env"].copy(),shell=kwargs["shell"])
            return FakeProcess()
        with patch("ssh_gate.runtime.subprocess.Popen",side_effect=launch),patch("ssh_gate.runtime.threading.Thread"):
            self.runtime.start(self.config,8765,"fixture-secret-key")
        self.assertEqual([str(self.binary),"run"],captured["argv"])
        self.assertEqual("fixture-secret-key",captured["env"]["CONTROL_PLANE_API_KEY"])
        self.assertEqual("http://127.0.0.1:8765/mcp",captured["env"]["MCP_SERVER_URL"])
        self.assertEqual("false",captured["env"]["ALLOW_REMOTE_UI"])
        self.assertFalse(captured["shell"])
        self.assertNotIn("fixture-secret-key",json.dumps(self.runtime.status(self.config)))

    def test_empty_key_missing_client_and_duplicate_start_are_rejected(self):
        with self.assertRaises(ValueError):self.runtime.start(self.config,8765,"")
        self.binary.unlink()
        with self.assertRaises(ValueError):self.runtime.start(self.config,8765,"fixture-key")
        self.binary.write_bytes(b"fixture")
        with patch("ssh_gate.runtime.subprocess.Popen",return_value=FakeProcess()),patch("ssh_gate.runtime.threading.Thread"):
            self.runtime.start(self.config,8765,"fixture-key")
            with self.assertRaises(ValueError):self.runtime.start(self.config,8765,"fixture-key")

    def test_credentials_in_logs_are_redacted_before_display(self):
        value=redact_log("fixture-secret-key sk-fixture-abcdef Authorization: Bearer test-token","fixture-secret-key")
        self.assertNotIn("fixture-secret-key",value)
        self.assertNotIn("sk-fixture-abcdef",value)
        self.assertNotIn("test-token",value)
        self.assertNotIn("private-proxy-secret",redact_log("proxy=http://fixture:private-proxy-secret@127.0.0.1:7890"))

    def test_manual_proxy_in_private_child_env_overrides_inherited_mcp_and_no_proxy(self):
        self.config=replace(self.config,tunnel=replace(self.config.tunnel,proxy_mode="manual",proxy_url="http://127.0.0.1:7890"))
        captured={}
        def launch(argv,**kwargs):
            captured.update(argv=argv,env=kwargs["env"].copy());return FakeProcess()
        with patch.dict(os.environ,{"TUNNEL_CLIENT_HTTP_PROXY":"http://wrong:8080","MCP_HTTP_PROXY":"http://wrong:8080","NO_PROXY":"*"}),patch("ssh_gate.runtime.subprocess.Popen",side_effect=launch),patch("ssh_gate.runtime.threading.Thread"):
            self.runtime.start(self.config,8765,"fixture-key")
        self.assertEqual("http://127.0.0.1:7890",captured["env"]["CONTROL_PLANE_HTTP_PROXY"])
        self.assertNotIn("MCP_HTTP_PROXY",captured["env"])
        self.assertNotIn("TUNNEL_CLIENT_HTTP_PROXY",captured["env"])
        self.assertEqual("127.0.0.1,localhost,::1",captured["env"]["NO_PROXY"])
        self.assertEqual([str(self.binary),"run"],captured["argv"])
        self.assertEqual("手动指定",self.runtime.status(self.config)["proxy_route"]["source"])

    def test_authenticated_environment_proxy_remains_out_of_snapshot_logs_and_config(self):
        secret="private-proxy-secret"
        with patch.dict(os.environ,{"CONTROL_PLANE_HTTP_PROXY":"http://fixture:"+secret+"@127.0.0.1:7890"}),patch("ssh_gate.runtime.subprocess.Popen",return_value=FakeProcess()),patch("ssh_gate.runtime.threading.Thread"):
            self.runtime.start(self.config,8765,"fixture-key")
        self.assertNotIn(secret,json.dumps(self.runtime.status(self.config)))
        self.assertNotIn(secret,(self.root/"config.json").read_text())

    def test_stop_terminates_child_and_clears_ready_state(self):
        process=FakeProcess()
        with patch("ssh_gate.runtime.subprocess.Popen",return_value=process),patch("ssh_gate.runtime.threading.Thread"):
            self.runtime.start(self.config,8765,"fixture-key")
        self.runtime._ready=True
        self.runtime.stop()
        self.assertEqual(0,process.poll())
        self.assertFalse(self.runtime.status(self.config)["running"])
        self.assertFalse(self.runtime.status(self.config)["ready"])

    def test_closed_runtime_cannot_start(self):
        self.runtime.close()
        with self.assertRaises(ValueError):self.runtime.start(self.config,8765,"fixture-key")
