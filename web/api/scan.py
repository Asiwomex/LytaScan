"""Vercel Python function for the temporary AWS session scan runner."""
from http.server import BaseHTTPRequestHandler
import json
from pathlib import Path
import sys

_runtime = Path(__file__).resolve().parents[1] / "scan-runtime.zip"
if _runtime.is_file():
    sys.path.insert(0, str(_runtime))
    from lytascan_session import MAX_BODY_BYTES, public_info, request_json
else:
    # Direct source imports support in-process tests; no local server is needed.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from api.ephemeral import MAX_BODY_BYTES, public_info, request_json


class handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        # Never log request bodies, credentials, or AWS exception text.
        pass

    def _json(self, status, payload):
        response = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store, private, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def do_GET(self):
        self._json(200, public_info())

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY_BYTES:
            self._json(413, {"error": {"code": "request_too_large", "message": "The connection request is too large or incomplete."}})
            return
        body = self.rfile.read(length)
        status, payload = request_json(body, self.headers.get("Origin"), self.headers.get("Host"),
                                       self.headers.get("Content-Type"))
        self._json(status, payload)

    def do_OPTIONS(self):
        self._json(405, {"error": {"code": "method_not_allowed", "message": "Use the scan runner on the LytaScan site."}})
