"""Hardening is off by default. When on, it blocks outside email and department-wide lookups."""
import json

from agent import config, containment
from agent.telemetry import SessionContext, Telemetry
from agent.tools import ToolBox


def toolbox(tmp_path):
    telemetry = Telemetry(path=tmp_path / "events.jsonl")
    return ToolBox(telemetry, outbox_dir=tmp_path / "outbox")


def session():
    ctx = SessionContext(user_id="u_test")
    ctx.new_turn("hello")
    return ctx


def test_hardening_is_off_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("HARDENING", raising=False)
    monkeypatch.setattr(config, "CONTAINMENT_PATH", tmp_path / "state.json")
    tools, ctx = toolbox(tmp_path), session()
    reply = tools.run(ctx, "lookup_employee", {"query": "finance"})
    assert "+234" in reply and "national_id" in reply
    external = {"to": "x@attacker.example", "subject": "s", "body": "b"}
    assert tools.run(ctx, "send_email", external).startswith("Email queued")


def test_hardening_blocks_department_lookups_and_outside_email(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDENING", "on")
    monkeypatch.setattr(config, "CONTAINMENT_PATH", tmp_path / "state.json")
    tools, ctx = toolbox(tmp_path), session()
    assert tools.run(ctx, "lookup_employee", {"query": "Finance"}).startswith("Blocked by security policy")
    assert tools.run(ctx, "lookup_employee", {"query": "the finance team"}).startswith("Blocked by security policy")
    external = {"to": "x@attacker.example", "subject": "s", "body": "b"}
    assert tools.run(ctx, "send_email", external).startswith("Blocked by security policy")
    internal = {"to": "ada.example@acme-lab.example", "subject": "s", "body": "b"}
    assert tools.run(ctx, "send_email", internal).startswith("Email queued")
    events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
    assert sum(1 for e in events if e.get("tool", {}).get("status") == "denied") == 3


def test_hardening_shares_only_name_department_and_work_email(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDENING", "on")
    monkeypatch.setattr(config, "CONTAINMENT_PATH", tmp_path / "state.json")
    records = json.loads(toolbox(tmp_path).run(session(), "lookup_employee", {"query": "Ada Example"}))
    assert records and set(records[0]) == {"name", "department", "email"}


def test_policy_decisions(monkeypatch):
    monkeypatch.setenv("HARDENING", "on")
    assert "outside the company" in containment.policy_denial("send_email", True)
    assert containment.policy_denial("send_email", False) is None
    assert containment.policy_denial("lookup_employee", False, {"query": "Ada Example"}) is None
    assert "department-wide" in containment.policy_denial("lookup_employee", False, {"query": "HR"})
    assert containment.policy_denial("search_kb", False, {"query": "finance"}) is None
    monkeypatch.setenv("HARDENING", "off")
    assert containment.policy_denial("send_email", True) is None
