"""重症紧急代理协作服务入口。

- `python3 service.py --check`：检查项目身份与核心组件完整性
- `python3 service.py --port 8000`：启动 HTTP 服务，`/health` 返回项目标识

服务状态默认保存在进程内存（审计哈希链同样在内存中校验）；
生产部署应在其外增加持久化与传输加密，本仓库不包含真实个人资料。
"""

import argparse
import json
from http.server import BaseHTTPRequestHandler

from icuproxy.clock import SystemClock
from icuproxy.httpapi import SERVICE_ID, build_server
from icuproxy.service import ICUProxyService

SERVICE_NAME = "重症紧急代理协作"


def health_payload():
    """返回稳定的服务身份信息。"""
    return {"status": "ok", "service": SERVICE_ID, "name": SERVICE_NAME}


def self_check() -> None:
    """构建一次空服务并验证审计链与身份常量。"""
    svc = ICUProxyService(clock=SystemClock())
    assert health_payload()["service"] == SERVICE_ID
    assert svc.audit.verify() is True


# 兼容旧的直接引用（根测试使用 service.SERVICE_ID / health_payload）
class Handler(BaseHTTPRequestHandler):
    """已弃用：HTTP 路由由 icuproxy.httpapi 提供，此处仅保留最小健康检查。"""

    def do_GET(self):
        if self.path != "/health":
            self.send_error(404)
            return
        body = json.dumps(health_payload(), ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def main():
    parser = argparse.ArgumentParser(description=SERVICE_NAME)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        self_check()
        print("基础检查通过")
        return
    service = ICUProxyService(clock=SystemClock())
    server = build_server(service, host=args.host, port=args.port)
    print(f"{SERVICE_NAME} 监听 http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
