"""HTTP API：把领域服务暴露为 JSON 接口。

鉴权约定：每个业务请求携带 `X-Actor: <actor_id>` 头标识操作者；
具体角色权限由领域服务裁定。`Idempotency-Key` 头用于事项防重。
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, is_dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlparse

from .errors import DomainError
from .service import ICUProxyService

SERVICE_ID = "icu-proxy"


def to_jsonable(obj: Any) -> Any:
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    return obj


class _Handler(BaseHTTPRequestHandler):
    service: ICUProxyService = None  # 由工厂注入

    # ---- 基础收发 ------------------------------------------------------

    def log_message(self, *_args):
        return

    def _send(self, status: int, payload: Any, extra_headers: Optional[dict] = None):
        body = json.dumps(to_jsonable(payload), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise _BadRequest(f"请求体不是合法 JSON：{exc}") from exc
        if not isinstance(data, dict):
            raise _BadRequest("请求体必须是 JSON 对象")
        return data

    def _actor_id(self) -> str:
        actor_id = self.headers.get("X-Actor")
        if not actor_id:
            raise _Unauthorized("缺少 X-Actor 头")
        return actor_id

    def _query(self) -> dict[str, str]:
        return {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}

    # ---- 路由 ----------------------------------------------------------

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        try:
            if method == "GET" and path == "/health":
                self._send(200, {"status": "ok", "service": SERVICE_ID})
                return
            if path == "/v1/audit" and method == "GET":
                actor_id = self._actor_id()
                self._send(200, {"entries": self.service.export_audit(),
                                 "actor_id": actor_id})
                return
            handler = self._match(method, path)
            if handler is None:
                self._send(404, {"error": "not_found", "message": f"无此路由：{method} {path}"})
                return
            # 引导接口用一次性令牌鉴权，不要求 X-Actor；其余业务请求都要有效身份
            if path != "/v1/bootstrap":
                actor_id = self._actor_id()
                if actor_id not in self.service.actors:
                    raise _Unauthorized("X-Actor 身份不存在或已停用")
            handler()
        except DomainError as exc:
            self._send(exc.status, {"error": type(exc).__name__, "message": str(exc)})
        except _HttpError as exc:
            self._send(exc.status, {"error": exc.error, "message": str(exc)})

    def _match(self, method: str, path: str) -> Optional[Callable[[], None]]:
        # (method, 段数, 前缀段...) -> 处理函数闭包
        segs = [s for s in path.split("/") if s]
        routes = self._routes()
        for m, pattern, fn in routes:
            if m != method or len(segs) != len(pattern):
                continue
            params: dict[str, str] = {}
            ok = True
            for seg, pat in zip(segs, pattern):
                if pat.startswith(":"):
                    params[pat[1:]] = seg
                elif seg != pat:
                    ok = False
                    break
            if ok:
                return lambda: fn(**params)
        return None

    def _routes(self):
        return [
            ("POST", ["v1", "bootstrap"], self._bootstrap),
            ("POST", ["v1", "actors"], self._create_actor),
            ("POST", ["v1", "patients"], self._create_patient),
            ("POST", ["v1", "patients", ":pid", "grants"], self._create_grant),
            ("GET", ["v1", "patients", ":pid", "grants"], self._list_effective_grants),
            ("POST", ["v1", "grants", ":gid", "verification"], self._verify_grant),
            ("POST", ["v1", "patients", ":pid", "terminations"], self._terminate),
            ("POST", ["v1", "matters"], self._open_matter),
            ("GET", ["v1", "matters"], self._list_matters),
            ("GET", ["v1", "matters", ":mid"], self._get_matter),
            ("GET", ["v1", "matters", ":mid", "next-contact"], self._next_contact),
            ("POST", ["v1", "matters", ":mid", "documents"], self._publish_document),
            ("POST", ["v1", "matters", ":mid", "attempts"], self._record_attempt),
            ("POST", ["v1", "matters", ":mid", "confirmations"], self._confirm),
            ("POST", ["v1", "matters", ":mid", "resolve"], self._resolve_matter),
            ("GET", ["v1", "matters", ":mid", "replay"], self._replay),
            ("GET", ["v1", "matters", ":mid", "family-view"], self._family_view),
            ("POST", ["v1", "matters", ":mid", "emergency-exceptions"],
             self._open_exception),
            ("POST", ["v1", "referrals", ":rid", "conclude"], self._conclude_referral),
            ("POST", ["v1", "exceptions", ":eid", "basis"], self._provide_basis),
            ("POST", ["v1", "exceptions", ":eid", "review"], self._review_basis),
            ("GET", ["v1", "exceptions", "overdue"], self._overdue),
        ]

    # ---- 处理函数 ------------------------------------------------------

    def _bootstrap(self):
        token = os.environ.get("BOOTSTRAP_TOKEN")
        if not token:
            raise _HttpError(403, "bootstrap_disabled",
                             "未配置 BOOTSTRAP_TOKEN，引导接口关闭")
        if self.headers.get("X-Bootstrap-Token") != token:
            raise _HttpError(401, "unauthorized", "引导令牌缺失或不匹配")
        data = self._read_json()
        actor = self.service.bootstrap_actor(
            data["actor_id"], data["name"], data["role"],
            relation=data.get("relation"), phone=data.get("phone"),
            secure_link_id=data.get("secure_link_id"),
        )
        self._send(201, actor)

    def _create_actor(self):
        actor_id = self._actor_id()
        data = self._read_json()
        actor = self.service.register_actor(
            actor_id, data["actor_id"], data["name"], data["role"],
            relation=data.get("relation"), phone=data.get("phone"),
            secure_link_id=data.get("secure_link_id"),
        )
        self._send(201, actor)

    def _create_patient(self):
        data = self._read_json()
        patient = self.service.register_patient(
            self._actor_id(), data["patient_id"], data["name"], data["mrn"]
        )
        self._send(201, patient)

    def _create_grant(self, pid: str):
        data = self._read_json()
        grant = self.service.create_grant(
            self._actor_id(), pid, data["actor_id"], data["basis"],
            relation=data.get("relation"), rank=data.get("rank"),
            matters=data.get("matters"), valid_from=data.get("valid_from"),
            valid_to=data.get("valid_to"),
        )
        self._send(201, grant)

    def _list_effective_grants(self, pid: str):
        q = self._query()
        matter_type = q.get("matter_type")
        if not matter_type:
            raise _BadRequest("查询参数 matter_type 必填")
        at = None
        if q.get("at"):
            from datetime import datetime
            at = datetime.fromisoformat(q["at"])
        grants = self.service.effective_grants(pid, matter_type, at=at)
        self._send(200, {"grants": grants})

    def _verify_grant(self, gid: str):
        data = self._read_json()
        grant = self.service.verify_grant(
            self._actor_id(), gid, bool(data.get("approved")),
            note=data.get("note"),
        )
        self._send(200, grant)

    def _terminate(self, pid: str):
        data = self._read_json()
        event = self.service.terminate_proxy(
            self._actor_id(), pid, data["reason"],
            grant_id=data.get("grant_id"), note=data.get("note"),
        )
        self._send(201, event)

    def _open_matter(self):
        data = self._read_json()
        idem = self.headers.get("Idempotency-Key") or data.get("idempotency_key")
        if not idem:
            raise _BadRequest("Idempotency-Key 头或 idempotency_key 字段必填")
        matter = self.service.open_matter(
            self._actor_id(), data["patient_id"], data["type"],
            data.get("title", ""), idem,
        )
        headers = {"X-Matter-Id": matter.id}
        self._send(201, matter, extra_headers=headers)

    def _list_matters(self):
        q = self._query()
        matters = self.service.list_matters(patient_id=q.get("patient_id"))
        self._send(200, {"matters": matters})

    def _get_matter(self, mid: str):
        self._send(200, self.service.get_matter(mid))

    def _next_contact(self, mid: str):
        grant = self.service.next_contact(mid)
        self._send(200, {"next": grant})

    def _publish_document(self, mid: str):
        data = self._read_json()
        doc = self.service.publish_document(
            self._actor_id(), mid, data["kind"], data["title"], data["content"]
        )
        self._send(201, doc)

    def _record_attempt(self, mid: str):
        data = self._read_json()
        result = self.service.record_attempt(
            self._actor_id(), mid, data["grant_id"], data["channel"],
            data["outcome"], detail=data.get("detail"),
            minimal_summary=data.get("minimal_summary"),
            fields=data.get("fields"),
        )
        self._send(201, result)

    def _confirm(self, mid: str):
        data = self._read_json()
        result = self.service.record_confirmation(
            self._actor_id(), mid, data["grant_id"], data["stance"],
            data["identity_method"], data["identity_evidence"],
        )
        self._send(201, result)

    def _resolve_matter(self, mid: str):
        data = self._read_json()
        matter = self.service.resolve_matter(
            self._actor_id(), mid, note=data.get("note")
        )
        self._send(200, matter)

    def _replay(self, mid: str):
        self._send(200, self.service.replay(self._actor_id(), mid))

    def _family_view(self, mid: str):
        self._send(200, self.service.family_view(self._actor_id(), mid))

    def _open_exception(self, mid: str):
        data = self._read_json()
        exception = self.service.open_emergency_exception(
            self._actor_id(), mid, data["urgency_statement"],
            basis_due_hours=int(data.get("basis_due_hours", 24)),
        )
        self._send(201, exception)

    def _conclude_referral(self, rid: str):
        data = self._read_json()
        referral = self.service.conclude_referral(
            self._actor_id(), rid,
            decision_stance=data.get("decision_stance"),
            rationale=data["rationale"],
        )
        self._send(200, referral)

    def _provide_basis(self, eid: str):
        data = self._read_json()
        exception = self.service.provide_exception_basis(
            self._actor_id(), eid, data["basis_documents"],
            note=data.get("note"),
        )
        self._send(200, exception)

    def _review_basis(self, eid: str):
        data = self._read_json()
        exception = self.service.review_exception_basis(
            self._actor_id(), eid, data["note"]
        )
        self._send(200, exception)

    def _overdue(self):
        self._actor_id()
        self._send(200, {"exceptions": self.service.overdue_exceptions()})


class _HttpError(Exception):
    def __init__(self, status: int, error: str, message: str):
        super().__init__(message)
        self.status = status
        self.error = error


class _BadRequest(_HttpError):
    def __init__(self, message: str):
        super().__init__(400, "bad_request", message)


class _Unauthorized(_HttpError):
    def __init__(self, message: str):
        super().__init__(401, "unauthorized", message)


def build_server(service: ICUProxyService, host: str = "0.0.0.0",
                 port: int = 8000) -> ThreadingHTTPServer:
    handler = type("Handler", (_Handler,), {"service": service})
    return ThreadingHTTPServer((host, port), handler)
