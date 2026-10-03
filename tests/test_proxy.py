from __future__ import annotations

import base64
import datetime
import http.server
import ipaddress
import json
import os
import select
import socket
import socketserver
import ssl
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ssh_gate.config import load_config, write_config
from ssh_gate.proxy import (ProxyRoute, ProxyDiagnostics, apply_route, configured_routes,
                               local_routes, probe_proxy, resolve_route, test_route, validate_proxy_url)
from ssh_gate.proxy import windows_proxy_settings


class ProxyConfigTests(unittest.TestCase):
    def test_url_validation_rejects_socks_credentials_commands_and_invisible_input(self):
        for value in ["socks5://127.0.0.1:1080", "127.0.0.1:7890", "http://u:secret@127.0.0.1:7890",
                      "http://127.0.0.1:0", "http://127.0.0.1:99999", "http://127.0.0.1/path",
                      "http://127.0.0.1?x=secret", "http://127.0.0.1#secret", "http://127.0.0.1\r\nX:1"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_proxy_url(value)
        self.assertEqual("https://[::1]:7890", validate_proxy_url("https://[::1]:7890/"))

    def test_windows_https_rule_takes_precedence_and_disabled_proxy_is_ignored(self):
        routes, warnings = configured_routes({}, {"enabled":True,"server":"http=127.0.0.1:80;https=127.0.0.1:7897;socks=127.0.0.1:1080"})
        self.assertEqual("http://127.0.0.1:7897", routes[0].url)
        self.assertEqual([], warnings)
        self.assertEqual([], configured_routes({}, {"enabled":False,"server":"127.0.0.1:7890"})[0])

    def test_windows_registry_reader_uses_current_user_and_never_writes_settings(self):
        registry = MagicMock()
        registry.QueryValueEx.side_effect = lambda key,name:({"ProxyEnable":1,"ProxyServer":"127.0.0.1:7890","AutoConfigURL":""}[name],1)
        with patch("ssh_gate.proxy.os.name","nt"),patch.dict(sys.modules,{"winreg":registry}):
            value = windows_proxy_settings()
        self.assertEqual({"enabled":True,"server":"127.0.0.1:7890","pac":False},value)
        self.assertEqual(registry.HKEY_CURRENT_USER,registry.OpenKey.call_args.args[0])
        registry.SetValueEx.assert_not_called()

    def test_environment_priority_reference_and_credential_redaction(self):
        routes, warnings = configured_routes({"CONTROL_PLANE_HTTP_PROXY":"env:MY_PRIVATE_PROXY", "MY_PRIVATE_PROXY":"http://user:secret@127.0.0.1:7890",
                                               "HTTPS_PROXY":"http://127.0.0.1:7897"}, {"enabled":True,"server":"127.0.0.1:8080"})
        self.assertEqual(3, len(routes))
        self.assertEqual("http://127.0.0.1:7890", routes[0].public()["url"])
        self.assertTrue(routes[0].public()["authenticated"])
        self.assertNotIn("secret", json.dumps([r.public() for r in routes]))
        self.assertEqual([], warnings)

    def test_pac_and_unsupported_environment_are_reported_without_executing_script(self):
        routes, warnings = configured_routes({"ALL_PROXY":"socks5://127.0.0.1:1080"}, {"pac":True})
        self.assertFalse(routes)
        self.assertEqual(2, len(warnings))
        with patch("ssh_gate.proxy.local_routes", return_value=[]), self.assertRaises(ValueError):
            resolve_route("auto", env={"HTTPS_PROXY":"socks5://127.0.0.1:1080"}, settings={})

    def test_configured_broken_proxy_does_not_silently_change_exit(self):
        with patch("ssh_gate.proxy.local_routes") as scan:
            route = resolve_route("auto", env={"HTTPS_PROXY":"http://127.0.0.1:1"}, settings={})
            self.assertEqual("http://127.0.0.1:1", route.url)
            scan.assert_not_called()

    def test_auto_common_ports_only_uses_verified_connect_and_reports_direct_fallback(self):
        with patch("ssh_gate.proxy.local_routes", return_value=[{"url":"http://127.0.0.1:1080","usable":False},
                                                                   {"url":"http://127.0.0.1:7890","usable":True,"source":"常见本地端口"}]):
            self.assertEqual("http://127.0.0.1:7890", resolve_route("auto", env={}, settings={}).url)
        with patch("ssh_gate.proxy.local_routes", return_value=[]):
            route = resolve_route("auto", env={}, settings={})
            self.assertEqual("", route.url)
            self.assertIn("未找到", route.source)

    def test_apply_route_overrides_inherited_global_proxy_and_localhost_exclusions(self):
        original = {"NO_PROXY":"*", "no_proxy":"api.openai.com", "HTTPS_PROXY":"http://old:8080", "MCP_HTTP_PROXY":"http://old:8080",
                    "TUNNEL_CLIENT_HTTP_PROXY":"http://old:8080", "HARPOON_HTTP_PROXY":"http://old:8080", "ALL_PROXY":"socks5://old:1080", "PATH":"fixture"}
        result = apply_route(original, ProxyRoute("http://127.0.0.1:7890", "手动指定"))
        self.assertEqual("http://127.0.0.1:7890", result["CONTROL_PLANE_HTTP_PROXY"])
        self.assertEqual("127.0.0.1,localhost,::1", result["NO_PROXY"])
        for name in ["MCP_HTTP_PROXY","TUNNEL_CLIENT_HTTP_PROXY","HARPOON_HTTP_PROXY","ALL_PROXY"]:
            self.assertNotIn(name, result)
        self.assertEqual("http://old:8080", original["HTTPS_PROXY"])
        direct = apply_route(original, ProxyRoute())
        self.assertEqual("*", direct["no_proxy"])
        self.assertNotIn("HTTPS_PROXY", direct)

    def test_old_config_defaults_and_manual_proxy_round_trip_no_secret_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)/"config.json";p.write_text('{"servers":[]}')
            config = load_config(p)
            self.assertEqual("auto", config.tunnel.proxy_mode)
            config = write_config(config, settings={"tunnel":{"proxy_mode":"manual","proxy_url":"http://127.0.0.1:7897"}})
            self.assertEqual("http://127.0.0.1:7897", config.tunnel.proxy_url)
            old = p.read_bytes()
            with self.assertRaises(ValueError):
                write_config(config, settings={"tunnel":{"proxy_mode":"manual","proxy_url":"http://user:secret@127.0.0.1:7897"}})
            self.assertEqual(old, p.read_bytes())


class ThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ProxyProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"api.openai.com")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1))
                .not_valid_after(now+datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("api.openai.com"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                .sign(key,hashes.SHA256()))
        cls.cert_path = root/"cert.pem";cls.cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path = root/"key.pem";key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        cls.api_requests = []
        class API(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                cls.api_requests.append(dict(self.headers))
                body = b'{"error":{"message":"fixture authentication required"}}'
                self.send_response(401);self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
            def log_message(self,*args):
                pass
        cls.api = http.server.ThreadingHTTPServer(("127.0.0.1",0),API)
        ssl_server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ssl_server.load_cert_chain(cls.cert_path,key_path)
        cls.api.socket = ssl_server.wrap_socket(cls.api.socket,server_side=True)
        threading.Thread(target=cls.api.serve_forever,daemon=True).start()
        cls.connect_requests = []
        class Proxy(socketserver.StreamRequestHandler):
            def handle(self):
                request = self.rfile.readline(4096).decode("ascii", "replace")
                headers = {}
                while True:
                    line = self.rfile.readline(4096)
                    if line in {b"\r\n", b""}:break
                    name,value = line.decode("ascii", "replace").split(":",1);headers[name.lower()] = value.strip()
                cls.connect_requests.append((request.strip(),headers))
                code = self.server.response_code
                self.wfile.write(f"HTTP/1.1 {code} Fixture\r\nContent-Length: 0\r\n\r\n".encode());self.wfile.flush()
                if code != 200:return
                with socket.create_connection(("127.0.0.1",cls.api.server_port),timeout=2) as upstream:
                    sockets = [self.connection,upstream]
                    while True:
                        readable,_,_ = select.select(sockets,[],[],2)
                        if not readable:return
                        for source in readable:
                            try:
                                data = source.recv(16384)
                                if not data:return
                                (upstream if source is self.connection else self.connection).sendall(data)
                            except OSError:
                                return
        cls.proxy = ThreadingServer(("127.0.0.1",0),Proxy);cls.proxy.response_code = 200
        threading.Thread(target=cls.proxy.serve_forever,daemon=True).start()
        cls.https_proxy = ThreadingServer(("127.0.0.1",0),Proxy);cls.https_proxy.response_code = 200
        cls.https_proxy.socket = ssl_server.wrap_socket(cls.https_proxy.socket,server_side=True)
        threading.Thread(target=cls.https_proxy.serve_forever,daemon=True).start()
        cls.route = ProxyRoute(f"http://127.0.0.1:{cls.proxy.server_address[1]}","隔离协议测试")
        cls.context = ssl.create_default_context(cafile=str(cls.cert_path))

    @classmethod
    def tearDownClass(cls):
        cls.proxy.shutdown();cls.proxy.server_close();cls.https_proxy.shutdown();cls.https_proxy.server_close()
        cls.api.shutdown();cls.api.server_close();cls.directory.cleanup()

    def setUp(self):
        self.proxy.response_code = 200
        self.api_requests.clear();self.connect_requests.clear()

    def test_real_connect_tls_and_401_no_api_key_or_target_dns_on_local_machine(self):
        lookup = socket.getaddrinfo
        def guard(host,*args,**kwargs):
            if host in {"api.openai.com",b"api.openai.com"}:
                raise AssertionError("目标域名不得在本机解析")
            return lookup(host,*args,**kwargs)
        with patch.dict(os.environ, {"CONTROL_PLANE_API_KEY":"never-send-key","HTTPS_PROXY":"http://127.0.0.1:1","NO_PROXY":"*"}),patch("socket.getaddrinfo",side_effect=guard):
            result = test_route(self.route,context=self.context)
        self.assertTrue(result["ok"],result)
        self.assertTrue(result["tcp"] and result["connect"] and result["tls"])
        self.assertEqual(401,result["http_status"])
        self.assertEqual("CONNECT api.openai.com:443 HTTP/1.1",self.connect_requests[0][0])
        self.assertNotIn("Authorization",self.api_requests[0])
        self.assertNotIn("never-send-key",json.dumps(self.connect_requests+self.api_requests))

    def test_real_proxy_rejection_does_not_report_tls_or_api_success(self):
        self.proxy.response_code = 407
        result = test_route(self.route,context=self.context)
        self.assertFalse(result["ok"] or result["tls"])
        self.assertTrue(result["tcp"])
        self.assertEqual("proxy_connect", result["phase"])
        self.assertIn("407", result["error"])
        self.assertFalse(self.api_requests)

    def test_https_proxy_uses_validated_outer_and_inner_tls(self):
        route = ProxyRoute(f"https://127.0.0.1:{self.https_proxy.server_address[1]}", "隔离 HTTPS 代理测试")
        phases = []
        result = test_route(route, phases.append, context=self.context)
        self.assertTrue(result["ok"] and result["connect"] and result["tls"], result)
        self.assertIn("tls_proxy", phases)
        self.assertIn("tls_api", phases)

    def test_untrusted_tls_is_rejected_without_disabling_certificate_verification(self):
        result = test_route(self.route)
        self.assertFalse(result["ok"] or result["tls"])
        self.assertEqual("tls_api",result["phase"])
        self.assertIn("证书",result["error"])

    def test_tcp_open_is_not_enough_and_scan_only_returns_verified_local_proxy(self):
        result = probe_proxy(self.route)
        self.assertTrue(result["tcp"] and result["usable"])
        self.proxy.response_code = 407
        result = probe_proxy(self.route)
        self.assertTrue(result["tcp"])
        self.assertFalse(result["usable"])
        self.assertEqual(407,result["connect_status"])
        found = local_routes((self.proxy.server_address[1],))
        self.assertEqual(1,len(found));self.assertFalse(found[0]["usable"])

    def test_authenticated_environment_credentials_only_go_to_connect_proxy(self):
        route = ProxyRoute(self.route.url.replace("http://","http://fixture:private-proxy-secret@"),"环境变量 HTTPS_PROXY")
        result = test_route(route,context=self.context)
        self.assertTrue(result["ok"],result)
        expected = "Basic " + base64.b64encode(b"fixture:private-proxy-secret").decode()
        self.assertEqual(expected,self.connect_requests[0][1]["proxy-authorization"])
        self.assertNotIn("Proxy-Authorization",self.api_requests[0])
        self.assertNotIn("private-proxy-secret",json.dumps(result))

    def test_direct_local_health_ignores_inherited_proxy(self):
        class Health(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200);self.send_header("Content-Length","0");self.end_headers()
            def log_message(self,*args):pass
        health = http.server.ThreadingHTTPServer(("127.0.0.1",0),Health)
        threading.Thread(target=health.serve_forever,daemon=True).start()
        try:
            env = apply_route(dict(os.environ),self.route)
            with patch.dict(os.environ,env,clear=True), httpx.Client(trust_env=True) as client:
                self.assertEqual(200, client.get(f"http://127.0.0.1:{health.server_port}/readyz").status_code)
            self.assertFalse(self.connect_requests)
        finally:
            health.shutdown();health.server_close()


class AsyncProxyTests(unittest.TestCase):
    def test_background_diagnostic_allows_polling_and_rejects_duplicate_job(self):
        done, entered = threading.Event(), threading.Event()
        job = ProxyDiagnostics();self.addCleanup(job.close)
        def blocked(*args, **kwargs):
            entered.set();done.wait(2);return {"ok":True,"route":{"url":"","source":"直连"}}
        with patch("ssh_gate.proxy.test_route",side_effect=blocked):
            started = time.monotonic();job.start("test","direct")
            self.assertLess(time.monotonic()-started,.2)
            self.assertTrue(entered.wait(1))
            self.assertEqual("running",job.status()["state"])
            with self.assertRaises(ValueError):job.start("detect")
            done.set()
            deadline = time.monotonic()+1
            while job.status()["state"] == "running" and time.monotonic() < deadline:time.sleep(.01)
        self.assertEqual("finished", job.status()["state"])

    def test_detection_snapshot_never_contains_environment_proxy_credentials(self):
        job = ProxyDiagnostics();self.addCleanup(job.close)
        secret = ProxyRoute("http://u:private-proxy-secret@127.0.0.1:7890","环境变量 HTTPS_PROXY")
        with patch("ssh_gate.proxy.configured_routes",return_value=([secret],[])), patch("ssh_gate.proxy.probe_proxy",side_effect=lambda route:{**route.public(),"tcp":True,"usable":True}),patch("ssh_gate.proxy.local_routes",return_value=[]):
            job.start("detect")
            deadline = time.monotonic()+1
            while job.status()["state"] == "running" and time.monotonic() < deadline:time.sleep(.01)
        self.assertNotIn("private-proxy-secret",json.dumps(job.status()))

    def test_errors_with_credentials_are_not_displayed_and_closed_job_rejects_start(self):
        job = ProxyDiagnostics()
        with patch("ssh_gate.proxy.resolve_route",side_effect=ValueError("http://user:private-secret@localhost")):
            job.start("test")
            deadline = time.monotonic()+1
            while job.status()["state"] == "running" and time.monotonic() < deadline:time.sleep(.01)
        self.assertEqual("failed",job.status()["state"])
        self.assertNotIn("private-secret", json.dumps(job.status()))
        job.close()
        with self.assertRaises(ValueError):job.start("detect")
