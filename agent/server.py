"""Local HTTP wrapper so scanners such as Garak can attack the agent.

    POST /chat   {"message": "..."}   ->   {"reply": "...", "session_id": "..."}
    GET  /health

Every request is a fresh session, so one attack cannot leak into the next, and all
events go through the normal logging, so Kibana and your rules see the attacks.
Requests are handled one at a time on purpose, which keeps API usage gentle.

Run from the project folder:  python -m agent.server
It listens on 127.0.0.1 only. The agent is vulnerable by design, so do not expose it."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

from . import config
from .agent import HelpdeskAgent
from .providers import make_client
from .telemetry import SessionContext, Telemetry
from .tools import ToolBox


def make_handler(agent: HelpdeskAgent, user_id: str, user_role: str):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                self._send(200, {"status": "ok", "provider": config.PROVIDER, "model": config.MODEL})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            if self.path != "/chat":
                return self._send(404, {"error": "not found"})
            try:
                length = int(self.headers.get("Content-Length", 0))
                message = json.loads(self.rfile.read(length) or b"{}").get("message", "")
            except (ValueError, AttributeError):
                return self._send(400, {"error": 'send JSON like {"message": "..."}'})
            if not isinstance(message, str) or not message.strip():
                return self._send(400, {"error": "message must be a non-empty string"})

            ctx = SessionContext(user_id=user_id, user_role=user_role)
            try:
                reply = agent.chat(ctx, message)
            except Exception as exc:
                # 429 makes Garak back off and retry instead of counting an error as a pass
                limited = "RateLimit" in type(exc).__name__ or "429" in str(exc)
                return self._send(429 if limited else 500,
                                  {"error": f"{type(exc).__name__}: {exc}"[:300]})
            finally:
                agent.end_session(ctx)
            self._send(200, {"reply": reply, "session_id": ctx.session_id})

        def log_message(self, fmt, *args):  # keep the console quiet
            pass

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--user", default="u_scan_01")
    parser.add_argument("--role", default="employee")
    args = parser.parse_args()

    telemetry = Telemetry()
    agent = HelpdeskAgent(make_client(config.PROVIDER), telemetry, ToolBox(telemetry))
    server = HTTPServer((args.host, args.port), make_handler(agent, args.user, args.role))
    print(f"Agent API on http://{args.host}:{args.port}/chat using {config.PROVIDER}/{config.MODEL}, "
          f"prompt mode {config.PROMPT_MODE}. Press Ctrl and C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
