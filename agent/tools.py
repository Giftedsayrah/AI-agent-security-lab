"""The three tools, plus ToolBox.run, the wrapper that logs every call.
Vulnerable by design: no result limits, no recipient checks."""
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import config, containment
from .telemetry import SessionContext, Telemetry

TOOL_SCHEMAS = [
    {"name": "search_kb",
     "description": "Search the internal IT knowledge base and return the best matching article.",
     "input_schema": {"type": "object",
                      "properties": {"query": {"type": "string"}},
                      "required": ["query"]}},
    {"name": "lookup_employee",
     "description": "Look up employee contact records by name or department.",
     "input_schema": {"type": "object",
                      "properties": {"query": {"type": "string"}},
                      "required": ["query"]}},
    {"name": "send_email",
     "description": "Send an email on the user's behalf.",
     "input_schema": {"type": "object",
                      "properties": {"to": {"type": "string"},
                                     "subject": {"type": "string"},
                                     "body": {"type": "string"}},
                      "required": ["to", "subject", "body"]}},
]


class ToolBox:
    def __init__(self, telemetry: Telemetry, kb_dir=config.KB_DIR,
                 employees_path=config.EMPLOYEES_PATH, outbox_dir=config.OUTBOX_DIR):
        self.t = telemetry
        self.outbox = Path(outbox_dir)
        self.outbox.mkdir(parents=True, exist_ok=True)
        self.employees = json.loads(Path(employees_path).read_text())
        self.docs = self._load_docs(Path(kb_dir))
        self.handlers = {"search_kb": self.search_kb,
                         "lookup_employee": self.lookup_employee,
                         "send_email": self.send_email}

    @staticmethod
    def _load_docs(kb_dir: Path) -> list:
        docs = []
        for folder, trust in (("trusted", "trusted"), ("shared", "untrusted")):
            for path in sorted((kb_dir / folder).glob("*.md")):
                docs.append({"id": f"{folder}/{path.name}", "source": folder,
                             "trust": trust, "text": path.read_text()})
        return docs

    def run(self, ctx: SessionContext, name: str, args: dict) -> str:
        """Wrapper: log the call, run the tool, log the result."""
        args = args or {}
        destination = self.t.destination_for(args.get("to", "")) if name == "send_email" else {}
        self.t.emit(ctx, "tool_call",
                    tool={"name": name,
                          "arguments": {k: (v[:500] if isinstance(v, str) else v) for k, v in args.items()},
                          "triggered_by": self.t.triggered_by(ctx, name),
                          "untrusted_content_in_context": ctx.untrusted_in_context},
                    destination=destination)
        reason = containment.check(ctx.user_id, name, bool(destination.get("external")), args=args)
        if reason:  # the responder has contained this user or action
            message = f"Blocked by security policy: {reason}"
            self.t.emit(ctx, "tool_result", outcome="blocked",
                        tool={"name": name, "status": "denied", "duration_ms": 0,
                              "result_size_bytes": len(message.encode())},
                        content=self.t.content("tool_output", message))
            return message
        start, status, outcome = time.perf_counter(), "success", "success"
        try:
            handler = self.handlers.get(name)
            if handler is None:
                raise ValueError(f"unknown tool {name}")
            result = handler(ctx, args)
        except Exception as exc:
            result, status, outcome = f"Tool error: {exc}", "error", "failure"
        self.t.emit(ctx, "tool_result", outcome=outcome,
                    tool={"name": name, "status": status,
                          "duration_ms": int((time.perf_counter() - start) * 1000),
                          "result_size_bytes": len(result.encode())},
                    content=self.t.content("tool_output", result),
                    flags=self.t.flags(result))
        return result

    def search_kb(self, ctx: SessionContext, args: dict) -> str:
        terms = args["query"].lower().split()
        scored = sorted(((sum(d["text"].lower().count(t) for t in terms), d) for d in self.docs),
                        key=lambda pair: pair[0], reverse=True)
        hits = [d for score, d in scored if score > 0][:1]
        if not hits:
            return "No matching article found."
        for doc in hits:
            self.t.emit(ctx, "retrieval",
                        retrieval={"source": doc["source"], "document_id": doc["id"],
                                   "chunk_id": "0", "trust": doc["trust"]},
                        content=self.t.content("retrieved_document", doc["text"]),
                        flags=self.t.flags(doc["text"]))
            if doc["trust"] == "untrusted":
                ctx.untrusted_in_context = True
        return "\n\n".join(d["text"] for d in hits)

    def lookup_employee(self, ctx: SessionContext, args: dict) -> str:
        q = args["query"].lower()
        matches = [e for e in self.employees
                   if q in e["name"].lower() or q in e["department"].lower()]
        if containment.hardening_on():  # share only what staff need: no phone numbers or ID numbers
            matches = [{k: e.get(k) for k in ("name", "department", "email")} for e in matches]
        return json.dumps(matches) if matches else "No matching employee."

    def send_email(self, ctx: SessionContext, args: dict) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        path = self.outbox / f"{stamp}-{uuid.uuid4().hex[:6]}.json"
        path.write_text(json.dumps({"to": args["to"], "subject": args["subject"],
                                    "body": args["body"]}, indent=2))
        return f"Email queued to {args['to']}"
