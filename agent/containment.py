"""Containment state and security policy, shared by the responder and the agent.

Containment: the responder (responder.py) writes a state file when an alert fires, and
the agent reads it before every tool call and refuses the call if the user or the action
is contained. Every block expires on its own, so a wrong alert can never lock anyone out.

Hardening: with the environment variable HARDENING=on, the agent also enforces rules in
code, whatever the model or the prompt says. Email to addresses outside the company is
refused, and employee lookups must name one person, not a whole department."""
import json
import os
import re
import time
from pathlib import Path

from . import config

DEFAULT_DEPARTMENTS = {"finance", "engineering", "hr", "executive"}


def _path(path=None) -> Path:
    return Path(path or config.CONTAINMENT_PATH)


def load(path=None) -> dict:
    try:
        state = json.loads(_path(path).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        state = {}
    now = time.time()
    users = state.get("blocked_users") or {}
    external = state.get("external_email")
    return {
        "blocked_users": {u: v for u, v in users.items() if v.get("until", 0) > now},
        "external_email": external if external and external.get("until", 0) > now else None,
    }


def save(state: dict, path=None) -> None:
    target = _path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(state, indent=2), encoding="utf-8")


def block_user(user_id: str, reason: str, minutes: int = 30, path=None) -> None:
    state = load(path)
    now = time.time()
    state["blocked_users"][user_id] = {"reason": reason, "since": now, "until": now + minutes * 60}
    save(state, path)


def block_external_email(reason: str, minutes: int = 30, path=None) -> None:
    state = load(path)
    now = time.time()
    state["external_email"] = {"reason": reason, "since": now, "until": now + minutes * 60}
    save(state, path)


def release_all(path=None) -> None:
    save({"blocked_users": {}, "external_email": None}, path)


def hardening_on() -> bool:
    return os.getenv("HARDENING", "off").strip().lower() in ("on", "1", "true", "yes")


def _departments() -> set:
    try:
        records = json.loads(Path(config.EMPLOYEES_PATH).read_text(encoding="utf-8"))
        found = {str(r.get("department", "")).strip().lower() for r in records}
    except Exception:
        found = set()
    return {d for d in found | DEFAULT_DEPARTMENTS if d}


def policy_denial(tool_name: str, external_destination: bool = False, args=None):
    """The reason a tool call breaks the hardening policy, or None. Does nothing unless HARDENING=on."""
    if not hardening_on():
        return None
    if tool_name == "send_email" and external_destination:
        return "hardening policy: email to addresses outside the company is not allowed"
    if tool_name == "lookup_employee":
        query = str((args or {}).get("query", "")).lower()
        if any(re.search(rf"\b{re.escape(d)}\b", query) for d in _departments()):
            return "hardening policy: department-wide lookups are not allowed, ask about one person by name"
    return None


def check(user_id: str, tool_name: str, external_destination: bool = False, path=None, args=None):
    """Returns the reason a tool call must be refused, or None if it may go ahead."""
    state = load(path)
    if user_id in state["blocked_users"]:
        return f"user {user_id} is contained ({state['blocked_users'][user_id]['reason']})"
    if tool_name == "send_email" and external_destination and state["external_email"]:
        return f"email to external addresses is blocked ({state['external_email']['reason']})"
    return policy_denial(tool_name, external_destination, args)
