"""Logging wrapper: every step of an agent session becomes one JSON line
that follows schema/event_schema.json."""
import hashlib
import json
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import config

INJECTION_PATTERNS = {
    # "ignore previous instructions", "ignore any previous and following instructions", ...
    "override_instructions": re.compile(
        r"(ignore|disregard|forget|override|bypass)\W+(?:\w+\W+){0,4}?"
        r"(previous|prior|above|preceding|earlier|following|original|system)\W+(?:\w+\W+){0,3}?"
        r"(instructions?|rules?|prompts?|directions?|guidelines?|context)", re.I),
    "forget_everything": re.compile(
        r"(ignore|disregard|forget)\W+(everything|all)\W+(above|before|previously|you were told)", re.I),
    # "just say ...", "JUST PRINT ..." as used by PromptInject and many jailbreaks
    "forced_output": re.compile(
        r"\b(just|only|simply)\W+(say|print|output|write|repeat|respond with|type)\W", re.I),
    "stop_everything": re.compile(r"stop everything", re.I),
    "reveal_prompt": re.compile(
        r"(repeat|print|reveal|show|output|display|tell me|what (is|are))\W+.{0,40}"
        r"(system prompt|(your|these|hidden|initial|original|system) (instructions|prompt|rules)"
        r"|everything above|text above|words above)", re.I),
    "role_reassign": re.compile(
        r"you are now|act as (an? )?(admin|developer|root)|pretend (to be|you are)"
        r"|from now on,? you|developer mode|do anything now", re.I),
    "new_instructions": re.compile(r"\b(new|updated|additional) (instructions|task|rules)\W{0,3}:", re.I),
    "tool_coercion": re.compile(
        r"(when you read this|before answering).{0,80}(email|send|look ?up)", re.I),
}

PII_PATTERNS = {
    "email": re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
    "phone": re.compile(r"\+?\d[\d\s().-]{8,}\d"),
    "national_id": re.compile(r"\b\d{11}\b"),
}

# Crude intent check for the computed triggered_by field. Refine it later.
TOOL_INTENT_WORDS = {
    "send_email": ("email", "mail", "send", "message"),
    "lookup_employee": ("employee", "staff", "who", "phone", "contact",
                        "directory", "department", "extension"),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class SessionContext:
    user_id: str
    user_role: str = "employee"
    session_id: str = field(default_factory=lambda: "sess_" + uuid.uuid4().hex[:8])
    turn_id: str = ""
    sequence: int = 0
    latest_user_prompt: str = ""
    untrusted_in_context: bool = False
    messages: list = field(default_factory=list)

    def new_turn(self, prompt: str) -> None:
        self.turn_id = "turn_" + uuid.uuid4().hex[:6]
        self.latest_user_prompt = prompt
        self.untrusted_in_context = False


class Telemetry:
    def __init__(self, path=config.LOG_PATH, system_prompt=config.SYSTEM_PROMPT,
                 canary=config.CANARY, corporate_domains=config.CORPORATE_DOMAINS):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.system_prompt = system_prompt
        self.canary = canary
        self.corporate_domains = corporate_domains
        self._lock = threading.Lock()

    def emit(self, ctx: SessionContext, event_type: str, outcome: str = "success", **sections) -> dict:
        ctx.sequence += 1
        event = {
            "@timestamp": _now(),
            "event": {"id": "evt_" + uuid.uuid4().hex[:8], "type": event_type,
                      "sequence": ctx.sequence, "outcome": outcome},
            "session": {"id": ctx.session_id, "turn_id": ctx.turn_id},
            "user": {"id": ctx.user_id, "role": ctx.user_role},
            "agent": {"name": config.AGENT_NAME, "version": config.AGENT_VERSION,
                      "environment": config.ENVIRONMENT, "prompt_mode": config.PROMPT_MODE},
        }
        event.update({k: v for k, v in sections.items() if v})
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
        return event

    def content(self, origin: str, text: str) -> dict:
        text = text or ""
        limit = config.MAX_LOGGED_CHARS
        return {"origin": origin, "text": text[:limit], "length_chars": len(text),
                "sha256": hashlib.sha256(text.encode()).hexdigest(),
                "truncated": len(text) > limit}

    def flags(self, text: str, check_leak: bool = False, ignore: str = "") -> dict:
        """Cheap pattern checks. Personal data the user typed themselves (in `ignore`) does
        not count, so a reply that repeats the user's own address is not a disclosure."""
        text = text or ""
        known = (ignore or "").lower()
        pii = [name for name, pattern in PII_PATTERNS.items()
               if any(m.group(0).lower() not in known for m in pattern.finditer(text))]
        found = {
            "injection_patterns": [n for n, p in INJECTION_PATTERNS.items() if p.search(text)],
            "pii_types": pii,
        }
        if check_leak and self.leak_suspected(text):
            found["system_prompt_leak_suspected"] = True
        return {k: v for k, v in found.items() if v}

    def leak_suspected(self, text: str, window: int = 8) -> bool:
        if self.canary in text:
            return True
        words = self.system_prompt.lower().split()
        haystack = " ".join(text.lower().split())
        return any(" ".join(words[i:i + window]) in haystack
                   for i in range(len(words) - window + 1))

    def destination_for(self, address: str) -> dict:
        domain = address.rsplit("@", 1)[-1].lower() if address and "@" in address else ""
        if not domain:
            return {}
        return {"domain": domain, "external": domain not in self.corporate_domains}

    def triggered_by(self, ctx: SessionContext, tool_name: str) -> str:
        words = TOOL_INTENT_WORDS.get(tool_name)
        if not words:
            return "user_request"
        prompt = ctx.latest_user_prompt.lower()
        return "user_request" if any(w in prompt for w in words) else "model_initiative"
