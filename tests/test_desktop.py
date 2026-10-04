from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from fixture_desktop import make_fixture


class DesktopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.api, self.manager, self.runner, self.host, self.tunnel = make_fixture(self.root)
        self.token = self.api._token
        self.addCleanup(self.api._close)

    def submit_manual(self, command="printf manual"):
        return self.api.submit_local(self.token, "dev", command, "test")["data"]

    def wait(self, rid):
        deadline = time.monotonic() + 3
        while self.manager.get(rid)["status"] == "running" and time.monotonic() < deadline:
            time.sleep(.02)
        return self.manager.get(rid)

    def test_invalid_capability_cannot_snapshot_submit_or_approve(self):
        view = self.submit_manual()
        for method, args in [(self.api.snapshot, ()), (self.api.submit_local,("dev","ls","test")),
                             (self.api.begin_review,(view["request_id"],)),
                             (self.api.ssh_profiles,()), (self.api.preview_connection,({"ssh_target":"alias"},)),
                             (self.api.proxy_action,("detect",)),
                             (self.api.approve,(view["request_id"],"fake",True))]:
            self.assertFalse(method("wrong-capability",*args)["ok"])
        self.assertFalse(self.runner.calls)

    def test_local_ssh_profile_preview_resolves_without_connecting(self):
        path=self.root/'ssh_config'
        path.write_text('Host hop\n HostName jump.fixture\n User jumper\n Port 2222\nHost alias\n HostName target.fixture\n User targetuser\n Port 3333\n ProxyJump hop\n')
        profiles=self.api.ssh_profiles(self.token,str(path))
        self.assertEqual(['hop','alias'],[p['alias'] for p in profiles['data']['profiles']])
        result=self.api.preview_connection(self.token,{'ssh_target':'alias','ssh_config_file':str(path)})
        self.assertTrue(result['ok'],result)
        self.assertEqual(['jump.fixture','target.fixture'],[n['hostname'] for n in result['data']['route']])
        self.assertEqual([2222,3333],[n['port'] for n in result['data']['route']])
        self.assertFalse(self.runner.calls)
        self.assertFalse(self.api.preview_connection(self.token,{'ssh_target':'alias','command':'ignored'})['ok'])

    def test_review_ticket_confirmation_and_once_only_execution(self):
        view = self.submit_manual()
        rid = view["request_id"]
        review = self.api.begin_review(self.token,rid)["data"]
        self.assertFalse(self.api.approve(self.token,rid,review["ticket"],False)["ok"])
        self.assertFalse(self.runner.calls)
        review = self.api.begin_review(self.token,rid)["data"]
        self.assertTrue(self.api.approve(self.token,rid,review["ticket"],True)["ok"])
        self.wait(rid)
        self.assertFalse(self.api.approve(self.token,rid,review["ticket"],True)["ok"])
        self.assertEqual(1,len(self.runner.calls))

    def test_review_ticket_cannot_approve_a_different_request(self):
        first = self.submit_manual()
        second = self.submit_manual("printf second")
        review = self.api.begin_review(self.token,first["request_id"])["data"]
        self.assertFalse(self.api.approve(self.token,second["request_id"],review["ticket"],True)["ok"])
        self.assertFalse(self.runner.calls)

    def test_expired_review_ticket_cannot_execute(self):
        view = self.submit_manual()
        ticket = self.api.begin_review(self.token,view["request_id"])["data"]["ticket"]
        rid,digest,_ = self.api._reviews[ticket]
        self.api._reviews[ticket] = (rid,digest,time.monotonic()-1)
        self.assertFalse(self.api.approve(self.token,rid,ticket,True)["ok"])
        self.assertFalse(self.runner.calls)

    def test_connection_edit_and_delete_are_blocked_while_requests_unfinished(self):
        view = self.submit_manual()
        values = {"id":"dev","label":"changed","ssh_target":"fixture@new.fixture"}
        self.assertFalse(self.api.save_connection(self.token,values,True)["ok"])
        self.assertFalse(self.api.remove_connection(self.token,"dev")["ok"])
        self.assertTrue(self.api.reject(self.token,view["request_id"])["ok"])
        self.assertTrue(self.api.save_connection(self.token,values,True)["ok"])
        self.assertEqual("changed",self.manager.config.server("dev").label)
        self.assertTrue(self.api.remove_connection(self.token,"dev")["ok"])

    def test_prompt_password_never_appears_in_snapshot_config_or_audit(self):
        result = []
        thread = threading.Thread(target=lambda: result.append(self.runner.prompts.ask("credentials",
            {"hostname":"fixture","username":"u","port":22,"attempt":1},threading.Event())),daemon=True)
        thread.start()
        snapshot = self.api.snapshot(self.token)["data"]
        prompt = snapshot["prompt"]
        self.assertEqual("credentials",prompt["kind"])
        secret = "fixture-private-password"
        self.assertTrue(self.api.answer_prompt(self.token,prompt["id"],{"secret":secret,"mode":"password"})["ok"])
        thread.join(timeout=1)
        self.assertEqual(secret,result[0]["secret"])
        snapshot = json.dumps(self.api.snapshot(self.token))
        self.assertNotIn(secret,snapshot)
        self.assertNotIn(secret,(self.root/"config.json").read_text())
        self.assertFalse(self.api.answer_prompt(self.token,prompt["id"],{"secret":secret,"mode":"password"})["ok"])
        result[0].clear()

    def test_prompt_cancellation_finishes_waiter_without_execution(self):
        errors=[]
        def wait():
            try:self.runner.prompts.ask("host_key",{"hostname":"fixture"},threading.Event())
            except Exception as exc:errors.append(type(exc).__name__)
        thread=threading.Thread(target=wait,daemon=True);thread.start()
        prompt=self.api.snapshot(self.token)["data"]["prompt"]
        self.assertTrue(self.api.answer_prompt(self.token,prompt["id"],None)["ok"])
        thread.join(timeout=1)
        self.assertEqual(["PromptCancelled"],errors)
        self.assertFalse(self.runner.calls)

    def test_closed_app_rejects_capability_and_pending_work(self):
        view=self.submit_manual()
        self.api._close()
        self.assertFalse(self.api.snapshot(self.token)["ok"])
        self.assertEqual("denied",self.manager.get(view["request_id"])["status"])

    def test_settings_validate_and_port_change_restarts_host(self):
        self.assertFalse(self.api.save_settings(self.token,{"listen_port":0})["ok"])
        self.assertFalse(self.api.save_settings(self.token,{"tunnel":{"api_key":"not-allowed"}})["ok"])
        self.assertTrue(self.api.save_settings(self.token,{"listen_port":18767,"ui":{"motion_enabled":False,"scale_percent":125}})["ok"])
        self.assertEqual((1,1),(self.host.starts,self.host.stops))
        self.assertFalse(self.manager.config.motion_enabled)
        self.assertEqual(125,self.manager.config.ui_scale_percent)

    def test_settings_cannot_change_port_while_tunnel_or_request_active(self):
        self.tunnel.running=True
        self.assertFalse(self.api.save_settings(self.token,{"listen_port":18767})["ok"])
        self.tunnel.running=False
        self.submit_manual()
        self.assertFalse(self.api.save_settings(self.token,{"listen_port":18767})["ok"])

    def test_tunnel_key_is_encrypted_reused_and_never_in_config_or_snapshot(self):
        profile={"id":"tunnel_"+"a"*32,"client_path":"fixture.exe","health_port":18766}
        secret="fixture-private-runtime-key"
        self.assertTrue(self.api.save_tunnel(self.token,profile)["ok"])
        self.assertTrue(self.api.start_tunnel(self.token,secret,True)["ok"])
        snapshot=self.api.snapshot(self.token)["data"]
        self.assertTrue(snapshot["tunnel"]["api_key_saved"])
        self.assertNotIn(secret,json.dumps(snapshot))
        self.assertNotIn(secret,(self.root/"config.json").read_text())
        self.assertNotIn(secret,(self.root/"credentials"/"credentials.json").read_text())
        self.api.stop_tunnel(self.token)
        self.tunnel.last_key=""
        self.assertTrue(self.api.start_tunnel(self.token,"",True)["ok"])
        self.assertEqual(secret,self.tunnel.last_key)
        self.assertTrue(self.api.clear_tunnel_api_key(self.token)["ok"])
        self.assertFalse(self.api.snapshot(self.token)["data"]["tunnel"]["api_key_saved"])
        self.api.stop_tunnel(self.token)
        self.assertFalse(self.api.start_tunnel(self.token,"",True)["ok"])

    def test_tunnel_key_can_be_used_without_remembering_and_clears_old_saved_key(self):
        profile={"id":"tunnel_"+"a"*32,"client_path":"fixture.exe","health_port":18766}
        self.assertTrue(self.api.save_tunnel(self.token,profile)["ok"])
        self.assertTrue(self.api.start_tunnel(self.token,"first-key",True)["ok"])
        self.api.stop_tunnel(self.token)
        self.assertTrue(self.api.start_tunnel(self.token,"temporary-key",False)["ok"])
        self.assertFalse(self.api.snapshot(self.token)["data"]["tunnel"]["api_key_saved"])

    def test_proxy_configuration_validation_round_trip_and_active_tunnel_guard(self):
        profile={"id":"","client_path":"fixture.exe","health_port":18766,"proxy_mode":"manual","proxy_url":"http://127.0.0.1:7897"}
        self.assertTrue(self.api.save_tunnel(self.token,profile)["ok"])
        self.assertEqual("http://127.0.0.1:7897",self.manager.config.tunnel.proxy_url)
        before=(self.root/"config.json").read_bytes()
        self.assertFalse(self.api.save_tunnel(self.token,{**profile,"proxy_url":"http://u:secret@localhost:7897"})["ok"])
        self.assertEqual(before,(self.root/"config.json").read_bytes())
        self.tunnel.running=True
        self.assertFalse(self.api.save_tunnel(self.token,{**profile,"proxy_mode":"direct"})["ok"])

    def test_output_export_reads_every_page(self):
        view=self.submit_manual("printf long-output")
        rid=view["request_id"]
        review=self.api.begin_review(self.token,rid)["data"]
        self.api.approve(self.token,rid,review["ticket"],True)
        done=self.wait(rid)
        result=self.api.export_output(self.token,rid)
        self.assertTrue(result["ok"],result)
        saved=Path(result["data"]).read_text()
        self.assertEqual(1200,saved.count("line /"))
        self.assertIn("fixture stderr",saved)
        self.assertTrue(done["has_more_output"])

    def test_summary_poll_does_not_send_full_commands_or_output(self):
        view=self.submit_manual("printf "+"a"*2000)
        snapshot=self.api.snapshot(self.token)["data"]
        row=snapshot["requests"][0]
        self.assertLessEqual(len(row["command_preview"]),240)
        self.assertNotIn("stdout",row)
        self.assertNotIn("command",row)
        detail=self.api.request_detail(self.token,view["request_id"])["data"]
        self.assertEqual(view["command"],detail["command"])
