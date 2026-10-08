"""Tiny stdlib HTTP helpers shared by both servers (bound to 127.0.0.1 only)."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class BaseHandler(BaseHTTPRequestHandler):
    index_file = None
    app = None

    def log_message(self, *args):  # keep terminals clean
        pass

    def send_bytes(self, code, body, ctype, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, obj, code=200):
        self.send_bytes(code, json.dumps(obj).encode("utf-8"), "application/json")

    def read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 1000000:
            raise ValueError("body too large")
        raw = self.rfile.read(n) if n else b"{}"
        return json.loads(raw or b"{}")

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self.send_bytes(200, self.index_file.read_bytes(), "text/html; charset=utf-8")
        self.handle_get(u.path, parse_qs(u.query))

    def do_POST(self):
        u = urlparse(self.path)
        try:
            body = self.read_json()
        except Exception:
            return self.send_json({"error": "invalid JSON body"}, 400)
        self.handle_post(u.path, body)

    def handle_get(self, path, query):
        self.send_json({"error": "not found"}, 404)

    def handle_post(self, path, body):
        self.send_json({"error": "not found"}, 404)


def run_server(handler_cls, host, port, name):
    srv = ThreadingHTTPServer((host, port), handler_cls)
    print("%s running at http://%s:%d  (Ctrl+C to stop)" % (name, host, port))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        srv.server_close()
