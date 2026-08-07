"""
SHADOW·RAIL demo server — serves the console + LLM input classify API.

Usage (from repo root, venv on):
  $env:PYTHONPATH = "src"
  $env:PYTHONIOENCODING = "utf-8"
  python ui/serve.py

Then open http://127.0.0.1:8765/
"""
from __future__ import annotations

import asyncio
import json
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI_DIR = Path(__file__).resolve().parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env", override=True)

from core.config import setup_api_key  # noqa: E402
from guardrails.input_guardrails import classify_input  # noqa: E402

HOST = "127.0.0.1"
PORT = 8765


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(UI_DIR), **kwargs)

    def log_message(self, fmt, *args):
        sys.stderr.write("[demo] " + (fmt % args) + "\n")

    def do_GET(self):
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path in ("/", "/index.html"):
            self.path = "/secops_console.html"
            return super().do_GET()
        if path == "/api/attack-log":
            return self._serve_outputs_json("attack_results.json")
        if path == "/api/metrics":
            return self._serve_outputs_json("metrics.json")
        return super().do_GET()

    def _serve_outputs_json(self, filename: str):
        fp = ROOT / "outputs" / filename
        if not fp.is_file():
            self._json(404, {"error": f"missing {filename}"})
            return
        try:
            payload = json.loads(fp.read_text(encoding="utf-8"))
        except Exception as exc:
            self._json(500, {"error": str(exc)})
            return
        self._json(200, payload)

    def do_POST(self):
        if self.path.rstrip("/") != "/api/classify":
            self.send_error(404, "not found")
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
            text = (body.get("text") or "").strip()
        except Exception:
            self._json(400, {"error": "invalid json"})
            return
        if not text:
            self._json(400, {"error": "empty text"})
            return

        use_llm = body.get("use_llm", True)
        try:
            result = asyncio.run(classify_input(text, use_llm=bool(use_llm)))
        except Exception as exc:
            # Fail closed to regex path on judge errors.
            result = asyncio.run(classify_input(text, use_llm=False))
            result["verdict"] = f"llm_error_fallback: {exc}"

        self._json(
            200,
            {
                "blocked": not result["allowed"],
                "layer": result.get("layer"),
                "reason": result.get("reason"),
                "mode": result.get("mode"),
                "msg": result.get("msg_vi") or result.get("msg_en"),
                "verdict": result.get("verdict"),
            },
        )

    def _json(self, code: int, payload: dict):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    setup_api_key()
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"SHADOW·RAIL demo → http://{HOST}:{PORT}/")
    print("POST /api/classify  {\"text\": \"...\", \"use_llm\": true}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
