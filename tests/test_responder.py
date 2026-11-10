"""The responder must turn alerts into containment, and the agent must obey it."""
import json
import time
from pathlib import Path

from jsonschema import Draft202012Validator

import responder
from agent import containment
from agent.telemetry import SessionContext, Telemetry
from agent.tools import ToolBox

ROOT = Path(__file__).resolve().parent.parent


def alert_hit(alert_id, rule, user=None, session=None, severity="high", threshold=False):
    source = {"@timestamp": "2026-11-05T10:00:00.000Z", "kibana.alert.rule.name": rule,
              "kibana.alert.severity": severity}
    if user:
        source["ai"] = {"user": {"id": user}, "session": {"id": session}}
    if threshold:
        source["kibana.alert.threshold_result"] = {"terms": [{"field": "ai.session.id", "value": session}]}
    return {"_id": alert_id, "_source": source}


class FakeSearch:
    """Answers alert queries with the given hits and session lookups with a known user."""
    def __init__(self, hits):
        self.hits, self.calls = hits, []

    def __call__(self, index, body):
        self.calls.append(index)
        if index == responder.ALERT_INDEX:
            return {"hits": {"hits": self.hits}}
        return {"hits": {"hits": [{"_source": {"ai": {"user": {"id": "u_found"}}}}]}}


def make(tmp_path, hits):
    search = FakeSearch(hits)
    return responder.Responder(search, state_path=tmp_path / "state.json",
                               incident_path=tmp_path / "incidents.jsonl"), search


def test_external_email_alert_contains_user_and_blocks_external_email(tmp_path):
    r, _ = make(tmp_path, [alert_hit("a1", "AI agent: email sent to an external address", "u_demo_01", "s1")])
    r.poll("2026-11-05T09:00:00.000Z")
    state = containment.load(tmp_path / "state.json")
    assert "u_demo_01" in state["blocked_users"] and state["external_email"]
    incident = json.loads((tmp_path / "incidents.jsonl").read_text().splitlines()[0])
    assert incident["user"] == "u_demo_01" and "recorded incident" in incident["actions"]


def test_threshold_alert_finds_the_user_from_the_session(tmp_path):
    hit = alert_hit("a2", "AI agent: bulk employee lookups in one session", session="sess_9", threshold=True)
    r, search = make(tmp_path, [hit])
    r.poll("2026-11-05T09:00:00.000Z")
    assert "u_found" in containment.load(tmp_path / "state.json")["blocked_users"]
    assert responder.EVENT_INDEX in search.calls


def test_alerts_are_handled_once_and_personal_data_alert_only_records(tmp_path):
    hit = alert_hit("a3", "AI agent: personal data in model output", "u_demo_01", "s1")
    r, _ = make(tmp_path, [hit])
    r.poll("2026-11-05T09:00:00.000Z")
    r.poll("2026-11-05T09:00:00.000Z")
    assert containment.load(tmp_path / "state.json")["blocked_users"] == {}
    assert len((tmp_path / "incidents.jsonl").read_text().splitlines()) == 1


def test_repeated_injection_alerts_trigger_a_block(tmp_path):
    hits = [alert_hit(f"i{n}", "AI agent: injection phrase in user prompt", "u_scan_01", f"s{n}", "medium")
            for n in range(responder.WATCH_LIMIT)]
    r, _ = make(tmp_path, hits[:-1])
    r.poll("2026-11-05T09:00:00.000Z")
    assert containment.load(tmp_path / "state.json")["blocked_users"] == {}
    r.search.hits = hits
    r.poll("2026-11-05T09:00:00.000Z")
    assert "u_scan_01" in containment.load(tmp_path / "state.json")["blocked_users"]


def test_blocks_expire_and_can_be_released(tmp_path):
    path = tmp_path / "state.json"
    containment.block_user("u_demo_01", "test", minutes=-1, path=path)  # already expired
    assert containment.load(path)["blocked_users"] == {}
    containment.block_user("u_demo_01", "test", path=path)
    containment.release_all(path)
    assert containment.check("u_demo_01", "lookup_employee", path=path) is None


def test_agent_refuses_tools_for_contained_users(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    monkeypatch.setattr("agent.config.CONTAINMENT_PATH", path)
    telemetry = Telemetry(path=tmp_path / "events.jsonl")
    toolbox = ToolBox(telemetry, outbox_dir=tmp_path / "outbox")

    ctx = SessionContext(user_id="u_demo_01")
    ctx.new_turn("Look up the finance team")
    assert "Ada Example" in toolbox.run(ctx, "lookup_employee", {"query": "finance"})  # allowed

    containment.block_user("u_demo_01", "test", path=path)
    reply = toolbox.run(ctx, "lookup_employee", {"query": "finance"})
    assert reply.startswith("Blocked by security policy")

    other = SessionContext(user_id="u_other")
    other.new_turn("email the report")
    args = {"to": "x@attacker.example", "subject": "s", "body": "b"}
    assert toolbox.run(other, "send_email", args).startswith("Email queued")  # not contained yet
    containment.block_external_email("test", path=path)
    assert toolbox.run(other, "send_email", args).startswith("Blocked by security policy")
    internal = {"to": "ada@acme-lab.example", "subject": "s", "body": "b"}
    assert toolbox.run(other, "send_email", internal).startswith("Email queued")  # internal still fine

    validator = Draft202012Validator(json.loads((ROOT / "schema" / "event_schema.json").read_text()))
    events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
    for event in events:
        assert not list(validator.iter_errors(event)), event
    assert any(e["event"]["outcome"] == "blocked" and e["tool"]["status"] == "denied" for e in events)
