from __future__ import annotations

import asyncio
import shutil
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

import httpx
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from ssh_gate.config import Config, Server
from ssh_gate.core import ApprovalManager
from ssh_gate.mcp_server import create_mcp
from ssh_gate.runtime import MCPHost
from ssh_gate.ssh import RunResult


class MCPHTTPTests(unittest.TestCase):
    def test_real_http_protocol_approval_status_retry_and_no_approval_tool(self):
        with tempfile.TemporaryDirectory() as temp:
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(32)
            port = listener.getsockname()[1]
            calls = []
            def runner(payload, emit, _stop):
                calls.append(payload.command)
                emit("stdout", b"/home/test\n")
                return RunResult(0)
            cfg = Config(Path(temp), port, 600, 3600, 4096, shutil.which("ssh") or "ssh.exe",
                         (Server("server", "Test", "test-host"),))
            manager = ApprovalManager(cfg, runner=runner)
            manager.local_gui_heartbeat()
            mcp = create_mcp(manager)
            server = uvicorn.Server(uvicorn.Config(mcp.streamable_http_app(), log_level="critical", access_log=False))
            thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
            thread.start()
            deadline = time.monotonic() + 5
            while not server.started and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(server.started)
            url = f"http://127.0.0.1:{port}"
            try:
                async def exercise():
                    async with httpx.AsyncClient(trust_env=False) as http:
                      async with streamable_http_client(url + "/mcp", http_client=http) as (read, write, _session_id):
                        async with ClientSession(read, write) as session:
                            init = await session.initialize()
                            self.assertIn("No tool can approve", init.instructions)
                            tools = await session.list_tools()
                            names = {tool.name for tool in tools.tools}
                            self.assertEqual({"list_servers", "request_command", "get_command_status", "cancel_pending_request", "terminate_command", "read_command_output", "list_directory", "stat_path", "read_file", "find_files", "test_connection", "download_file", "download_directory", "read_download_chunk", "begin_upload", "append_upload_chunk", "upload_file", "upload_directory", "create_session", "update_session", "exec_in_session", "list_sessions", "close_session"}, names)
                            servers = await session.call_tool("list_servers", {})
                            self.assertFalse(servers.isError)
                            self.assertTrue(servers.structuredContent["approval_required_for_all_commands"])
                            args = {"server_id": "server", "command": "pwd", "reason": "Verify SSH", "client_request_id": "http-test"}
                            proposal = await session.call_tool("request_command", args)
                            self.assertFalse(proposal.isError)
                            view = proposal.structuredContent
                            self.assertEqual("pending_approval", view["status"])
                            self.assertFalse(calls)
                            retry = await session.call_tool("request_command", args)
                            self.assertEqual(view["request_id"], retry.structuredContent["request_id"])
                            replaced = await session.call_tool("request_command", {**args, "command": "ls"})
                            self.assertTrue(replaced.isError)
                            bypass = await session.call_tool("approve_command", {"request_id": view["request_id"]})
                            self.assertTrue(bypass.isError)
                            self.assertFalse(calls)
                            # Simulate the trusted local Windows GUI click; never an MCP tool call.
                            manager.local_approve(view["request_id"], view["digest"])
                            done = await session.call_tool("get_command_status", {"request_id": view["request_id"], "wait_seconds": 2})
                            self.assertEqual("succeeded", done.structuredContent["status"])
                            self.assertEqual("/home/test\n", done.structuredContent["stdout"])
                            self.assertEqual(["pwd"], calls)
                            manager.local_gui_heartbeat()
                            denied = await session.call_tool("request_command", {**args, "client_request_id": "http-denied"})
                            manager.reject(denied.structuredContent["request_id"])
                            result = await session.call_tool("get_command_status", {"request_id": denied.structuredContent["request_id"]})
                            self.assertEqual("denied", result.structuredContent["status"])
                            self.assertEqual(["pwd"], calls)
                    async with httpx.AsyncClient(trust_env=False) as client:
                        health = await client.get(url + "/healthz")
                        self.assertEqual("ssh-gate", health.json()["service"])
                        hostile = await client.post(url + "/mcp", headers={"Host": "evil.example", "Content-Type": "application/json"}, json={})
                        self.assertEqual(421, hostile.status_code)
                        origin = await client.post(url + "/mcp", headers={"Origin": "https://evil.example", "Content-Type": "application/json"}, json={})
                        self.assertEqual(403, origin.status_code)
                asyncio.run(exercise())
            finally:
                manager.close()
                server.should_exit = True
                thread.join(timeout=5)
                listener.close()

    def test_host_counts_mcp_posts_only_for_link_animation(self):
        with tempfile.TemporaryDirectory() as temp:
            probe = socket.socket()
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
            probe.close()
            cfg = Config(Path(temp), port, 600, 3600, 4096, shutil.which("ssh") or "ssh.exe", ())
            manager = ApprovalManager(cfg, runner=lambda *_: RunResult(0))
            host = MCPHost(manager)
            host.start()
            try:
                deadline = time.monotonic() + 5
                while not host.status()["running"] and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(host.status()["running"])
                self.assertEqual((0, 0), (host.status()["calls_received"], host.status()["calls_answered"]))
                url = f"http://127.0.0.1:{port}"
                with httpx.Client(trust_env=False) as client:
                    self.assertEqual(200, client.get(url + "/healthz").status_code)
                    client.post(url + "/mcp", headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
                                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
                    client.post(url + "/mcp", headers={"Host": "evil.example", "Content-Type": "application/json"}, json={})
                status = host.status()
                self.assertEqual(2, status["calls_received"])
                self.assertEqual(2, status["calls_answered"])
            finally:
                host.stop()
                manager.close()


if __name__ == "__main__":
    unittest.main()
