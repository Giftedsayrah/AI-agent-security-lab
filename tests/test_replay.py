"""The replay script must leave the signatures the detections will rely on."""
import json
import shutil
from pathlib import Path

from jsonschema import Draft202012Validator

import replay_attacks
from agent import config
from agent.telemetry import Telemetry
from agent.tools import ToolBox

ROOT = Path(__file__).resolve().parent.parent


def run_replay(tmp_path):
    kb = tmp_path / "kb"
    shutil.copytree(ROOT / "data" / "kb", kb)
    shutil.copy(ROOT / "attacks" / "poisoned_vpn_tips.md", kb / "shared")
    log = tmp_path / "events.jsonl"
    telemetry = Telemetry(path=log)
    toolbox = ToolBox(telemetry, kb_dir=kb, outbox_dir=tmp_path / "outbox")
    results = replay_attacks.run(telemetry, toolbox)
    return results, [json.loads(line) for line in log.read_text().splitlines()]


def test_replay_events_are_valid_and_marked_synthetic(tmp_path):
    results, events = run_replay(tmp_path)
    assert len(results) == 7 and config.PROVIDER != "replay"
    validator = Draft202012Validator(json.loads((ROOT / "schema" / "event_schema.json").read_text()))
    for event in events:
        assert not list(validator.iter_errors(event)), event
        assert event["user"]["id"].startswith("u_replay")
    providers = {e["model"]["provider"] for e in events if "provider" in e.get("model", {})}
    assert providers == {"replay"}


def test_replay_leaves_attack_signatures(tmp_path):
    _, events = run_replay(tmp_path)

    emails = [e for e in events if e["event"]["type"] == "tool_call"
              and e["tool"]["name"] == "send_email"]
    assert len(emails) == 1
    assert emails[0]["tool"]["triggered_by"] == "model_initiative"
    assert emails[0]["tool"]["untrusted_content_in_context"] is True
    assert emails[0]["destination"]["external"] is True

    prompts = [e for e in events if e["event"]["type"] == "user_prompt"]
    assert any("override_instructions" in e.get("flags", {}).get("injection_patterns", []) for e in prompts)
    assert any("reveal_prompt" in e.get("flags", {}).get("injection_patterns", []) for e in prompts)

    assert any(e.get("flags", {}).get("system_prompt_leak_suspected") for e in events
               if e["event"]["type"] == "model_response")

    bulk_session = next(e["session"]["id"] for e in events if e["event"]["type"] == "user_prompt"
                        and "finance department" in e["content"]["text"])
    lookups = [e for e in events if e["session"]["id"] == bulk_session
               and e["event"]["type"] == "tool_call" and e["tool"]["name"] == "lookup_employee"]
    assert len(lookups) == 4

    normal_tools = [e for e in events if e["user"]["id"] == "u_replay_normal"
                    and e["event"]["type"] == "tool_call"]
    assert normal_tools and all(e["tool"]["triggered_by"] == "user_request" for e in normal_tools)
