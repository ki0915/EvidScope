"""Small mTLS boundary. Fixed loopback targets; no generic proxy/tool routes."""
import http.client
import json
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PRIMARY = "fdtn-ai/Foundation-Sec-1.1-8B-Instruct"
MODE = os.environ.get("MODEL_KIND", "foundation-sec")
PORT = 8080 if MODE == "foundation-sec" else 8091
MAX_BODY = 65536 if MODE == "cipherguard" else 24000
TIMEOUT = 10 if MODE == "cipherguard" else 120
LOCK = threading.Lock()

def valid_request(path, value):
    if not isinstance(value, dict):
        return False
    if MODE == "cipherguard":
        return path == "/screen" and not set(value) - {"textFields", "maxTokens", "maxChunks", "overlapTokens", "timeoutMs"}
    if path == "/apply-template":
        return not set(value) - {"messages", "add_generation_prompt"} and valid_messages(value.get("messages"))
    if path == "/tokenize":
        return not set(value) - {"content", "add_special", "parse_special", "with_pieces"} and isinstance(value.get("content"), str)
    if path == "/v1/chat/completions":
        allowed = {"model", "messages", "stream", "max_tokens", "temperature", "top_p", "top_k", "response_format", "seed", "cache_prompt"}
        return not set(value) - allowed and value.get("model") == PRIMARY and value.get("stream") is False and type(value.get("max_tokens")) is int and value["max_tokens"] == 512 and value.get("temperature") == 0.1 and value.get("top_p") == 0.9 and value.get("top_k") == 20 and value.get("seed") == 0 and value.get("cache_prompt") is False and valid_messages(value.get("messages"))
    return False

def valid_messages(messages):
    return isinstance(messages, list) and 0 < len(messages) <= 12 and all(isinstance(m, dict) and set(m) == {"role", "content"} and m["role"] in {"system", "user", "assistant"} and isinstance(m["content"], str) for m in messages)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass
    def emit(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.path != "/health":
            return self.emit(404, b'{"error":"route_unavailable"}')
        self.proxy(None)
    def do_POST(self):
        try:
            self.connection.settimeout(TIMEOUT)
            n = int(self.headers.get("Content-Length", "0"))
            if not 0 < n <= MAX_BODY or self.headers.get("Transfer-Encoding"):
                raise ValueError("request_invalid")
            raw = self.rfile.read(n)
            if len(raw) != n or not valid_request(self.path, json.loads(raw)):
                raise ValueError("request_invalid")
        except Exception:
            return self.emit(400, b'{"error":"request_invalid"}')
        self.proxy(raw)
    def proxy(self, body):
        if not LOCK.acquire(blocking=False):
            return self.emit(429, b'{"error":"concurrency_limit"}')
        connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=TIMEOUT)
        try:
            connection.request("POST" if body is not None else "GET", self.path, body=body, headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            if response.status != 200:
                return self.emit(503, b'{"error":"model_unavailable"}')
            payload = response.read(1048577)
            if len(payload) > 1048576:
                raise ValueError("response_limit")
            self.emit(200, payload or b'{"status":"ok"}')
        except Exception:
            self.emit(503, b'{"error":"model_unavailable"}')
        finally:
            connection.close()
            LOCK.release()

def main():
    if os.name != "posix" or os.environ.get("EVIDSCOPE_ISOLATED") != "1":
        raise SystemExit("isolated_pod_required")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
    context.load_verify_locations("/tls/ca.crt")
    context.verify_mode = ssl.CERT_REQUIRED
    server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()

if __name__ == "__main__":
    main()
