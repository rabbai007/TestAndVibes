"""Benchmark target for --api-spec: a tiny API with three planted bugs.

    python3 -I server.py PORT METHODS_LOG

Serves its own OpenAPI spec at /openapi.json. Every request's method and path
is appended to METHODS_LOG, so the benchmark can prove the pass sent nothing
but GET, HEAD and OPTIONS. Binds to 127.0.0.1 only.

Planted bugs (tests/benchmark/expected-api.json):
  - GET /items/{id} crashes (500) on an id that is not an integer
  - GET /items/{id} returns a body that breaks its own schema for id > 1000
  - GET /admin/stats is secured in the spec but ignores the API key
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

PORT, LOG = int(sys.argv[1]), sys.argv[2]

ITEM = {"type": "object", "required": ["id", "name"],
        "properties": {"id": {"type": "integer"}, "name": {"type": "string"}}}
SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "vibecheck-benchmark-api", "version": "1"},
    "components": {"securitySchemes": {"key": {"type": "apiKey", "in": "header", "name": "X-API-Key"}}},
    "paths": {
        "/items/{id}": {"get": {
            "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
            "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": ITEM}}},
                          "404": {"description": "not found"}}}},
        "/admin/stats": {"get": {"security": [{"key": []}],
                                 "responses": {"200": {"description": "ok"}, "401": {"description": "no key"}}}},
        "/health": {"get": {"responses": {"200": {"description": "ok"}}}},
        # A write operation: must be reported as not sent, and never called.
        "/items": {"post": {"responses": {"201": {"description": "created"}}}},
    },
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def parse_request(self):
        ok = super().parse_request()
        if ok:
            with open(LOG, "a") as f:
                f.write(f"{self.command} {self.path.split('?')[0]}\n")
        return ok

    def send(self, code, body=None):
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/openapi.json":
            return self.send(200, SPEC)
        if path == "/health":
            return self.send(200, {"ok": True})
        if path == "/admin/stats":
            return self.send(200, {"users": 3})               # BUG: ignores X-API-Key
        if path.startswith("/items/"):
            n = int(path.split("/")[2])                        # BUG: 500 on a non-integer
            if n > 1000:
                return self.send(200, {"id": "oops"})          # BUG: breaks the schema
            return self.send(200, {"id": n, "name": "x"})
        return self.send(404, {"error": "not found"})

    def do_POST(self):
        self.send(201, {})

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except Exception:
            try:
                self.send(500, {"error": "internal"})
            except Exception:
                pass


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
