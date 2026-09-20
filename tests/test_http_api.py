"""HTTP API 端到端测试（真实 socket + 标准库客户端）。"""

import json
import os
import threading
import unittest
import urllib.error
import urllib.request

from icuproxy.clock import FrozenClock
from icuproxy.httpapi import build_server
from icuproxy.service import ICUProxyService


class ApiClient:
    def __init__(self, base: str):
        self.base = base

    def call(self, method, path, actor=None, body=None,
             idempotency_key=None, bootstrap_token=None):
        req = urllib.request.Request(self.base + path, method=method)
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            req.add_header("Content-Type", "application/json; charset=utf-8")
        if actor:
            req.add_header("X-Actor", actor)
        if idempotency_key:
            req.add_header("Idempotency-Key", idempotency_key)
        if bootstrap_token:
            req.add_header("X-Bootstrap-Token", bootstrap_token)
        try:
            with urllib.request.urlopen(req, data=data) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))


class HttpApiTest(unittest.TestCase):
    def setUp(self):
        os.environ["BOOTSTRAP_TOKEN"] = "unit-test-token"
        self.clock = FrozenClock()
        self.service = ICUProxyService(self.clock)
        self.server = build_server(self.service, host="127.0.0.1", port=0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.api = ApiClient(f"http://127.0.0.1:{self.port}")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_health(self):
        status, body = self.api.call("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["service"], "icu-proxy")

    def test_bootstrap_then_locks(self):
        status, _ = self.api.call(
            "POST", "/v1/bootstrap",
            body={"actor_id": "ma1", "name": "医务处",
                  "role": "medical_affairs"},
            bootstrap_token="wrong",
        )
        self.assertEqual(status, 401)
        status, actor = self.api.call(
            "POST", "/v1/bootstrap",
            body={"actor_id": "ma1", "name": "医务处",
                  "role": "medical_affairs"},
            bootstrap_token="unit-test-token",
        )
        self.assertEqual(status, 201)
        status, _ = self.api.call(
            "POST", "/v1/bootstrap",
            body={"actor_id": "ma2", "name": "二处",
                  "role": "medical_affairs"},
            bootstrap_token="unit-test-token",
        )
        self.assertEqual(status, 409)

    def test_requests_without_actor_are_unauthorized(self):
        status, body = self.api.call("GET", "/v1/matters")
        self.assertEqual(status, 401)

    def test_full_flow_over_http(self):
        api = self.api
        # 引导并建档
        api.call("POST", "/v1/bootstrap",
                 body={"actor_id": "ma1", "name": "医务处",
                       "role": "medical_affairs"},
                 bootstrap_token="unit-test-token")
        api.call("POST", "/v1/actors", "ma1",
                 {"actor_id": "staff1", "name": "护士", "role": "staff"})
        api.call("POST", "/v1/actors", "ma1",
                 {"actor_id": "att1", "name": "主治", "role": "attending"})
        api.call("POST", "/v1/actors", "ma1",
                 {"actor_id": "eth1", "name": "伦理", "role": "ethics"})
        status, _ = api.call(
            "POST", "/v1/actors", "staff1",
            {"actor_id": "fam", "name": "配偶", "role": "family",
             "relation": "spouse", "phone": "110"},
        )
        self.assertEqual(status, 201)
        status, _ = api.call("POST", "/v1/patients", "staff1",
                             {"patient_id": "p1", "name": "患者", "mrn": "M1"})
        self.assertEqual(status, 201)

        # 资格 + 核验
        status, grant = api.call(
            "POST", "/v1/patients/p1/grants", "staff1",
            {"actor_id": "fam", "basis": "legal", "relation": "spouse"},
        )
        self.assertEqual(status, 201)
        status, body = api.call(
            "POST", f"/v1/grants/{grant['id']}/verification", "staff1",
            {"approved": True},
        )
        self.assertEqual(status, 403)
        status, grant = api.call(
            "POST", f"/v1/grants/{grant['id']}/verification", "ma1",
            {"approved": True, "note": "证件齐全"},
        )
        self.assertEqual(grant["verification_status"], "verified")

        # 事项幂等
        status, m1 = api.call(
            "POST", "/v1/matters", "staff1",
            {"patient_id": "p1", "type": "exam_consent", "title": "同意"},
            idempotency_key="NK-1",
        )
        self.assertEqual(status, 201)
        status, m2 = api.call(
            "POST", "/v1/matters", "staff1",
            {"patient_id": "p1", "type": "exam_consent", "title": "重复"},
            idempotency_key="NK-1",
        )
        self.assertEqual(m1["id"], m2["id"])
        mid = m1["id"]

        # 文书 / 送达 / 确认 / 形成决定
        status, doc = api.call(
            "POST", f"/v1/matters/{mid}/documents", "att1",
            {"kind": "consent_form", "title": "同意书v1", "content": "正文"},
        )
        self.assertEqual(doc["version"], 1)
        status, body = api.call(
            "POST", f"/v1/matters/{mid}/attempts", "staff1",
            {"grant_id": grant["id"], "channel": "phone", "outcome": "delivered",
             "minimal_summary": "拟行穿刺", "fields": ["procedure"]},
        )
        self.assertEqual(status, 201)
        status, body = api.call(
            "POST", f"/v1/matters/{mid}/confirmations", "staff1",
            {"grant_id": grant["id"], "stance": "consent",
             "identity_method": "callback_verified_phone",
             "identity_evidence": "回拨尾号110"},
        )
        self.assertEqual(status, 201)
        status, matter = api.call("POST", f"/v1/matters/{mid}/resolve",
                                  "att1", {"note": "按同意执行"})
        self.assertEqual(matter["status"], "resolved")

        # 家属视图与审查视图
        status, fv = api.call("GET", f"/v1/matters/{mid}/family-view", "fam")
        self.assertEqual(status, 200)
        self.assertEqual(len(fv["your_confirmations"]), 1)
        status, replay = api.call("GET", f"/v1/matters/{mid}/replay", "ma1")
        self.assertEqual(status, 200)
        self.assertTrue(replay["audit_verified"])
        status, audit = api.call("GET", "/v1/audit", "ma1")
        self.assertEqual(status, 200)
        self.assertGreater(len(audit["entries"]), 5)

    def test_unknown_route_404(self):
        status, body = self.api.call("GET", "/nope")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "not_found")

    def test_bad_json_rejected(self):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/v1/bootstrap",
            data=b"{not-json", method="POST",
        )
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Bootstrap-Token", "unit-test-token")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
