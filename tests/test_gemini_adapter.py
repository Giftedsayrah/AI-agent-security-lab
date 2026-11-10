"""Checks the Gemini adapter against a fake OpenAI-style client."""
import json
import shutil
from pathlib import Path
from types import SimpleNamespace as NS

from jsonschema import Draft202012Validator

from agent import config
from agent.agent import HelpdeskAgent
from agent.providers import GeminiAdapter
from agent.telemetry import SessionContext, Telemetry
from agent.tools import ToolBox, TOOL_SCHEMAS

ROOT = Path(__file__).resolve().parent.parent


class FakeOpenAI:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []
        self.chat = NS(completions=self)

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.replies.pop(0)


def reply(content=None, calls=None):
    tool_calls = [NS(id=i, function=NS(name=n, arguments=json.dumps(a)), extra_content=extra)
                  for i, n, a, extra in (calls or [])]
    return NS(choices=[NS(message=NS(content=content, tool_calls=tool_calls or None))],
              usage=NS(prompt_tokens=50, completion_tokens=10))


def test_tools_are_converted_to_function_format():
    fake = FakeOpenAI([reply("hi")])
    GeminiAdapter(client=fake).create("m", 100, "sys", TOOL_SCHEMAS,
                                      [{"role": "user", "content": "hello"}])
    tools = fake.calls[0]["tools"]
    assert [t["function"]["name"] for t in tools] == ["search_kb", "lookup_employee", "send_email"]
    assert tools[0]["type"] == "function" and "properties" in tools[0]["function"]["parameters"]
    assert fake.calls[0]["messages"][0] == {"role": "system", "content": "sys"}


def test_full_conversation_through_adapter(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "PROVIDER", "gemini")
    # first tool call has an empty id, which Gemini sometimes returns
    fake = FakeOpenAI([
        reply(calls=[("", "search_kb", {"query": "password reset"},
                      {"google": {"thought_signature": "sig-123"}})]),
        reply("Open the self-service portal and choose Forgot password."),
    ])
    log = tmp_path / "events.jsonl"
    telemetry = Telemetry(path=log)
    toolbox = ToolBox(telemetry, kb_dir=ROOT / "data" / "kb", outbox_dir=tmp_path / "outbox")
    agent = HelpdeskAgent(GeminiAdapter(client=fake), telemetry, toolbox, model="gemini-3.8-flash")
    ctx = SessionContext(user_id="u_demo_01")

    answer = agent.chat(ctx, "How do I reset my password?")
    assert "self-service portal" in answer

    second_call = fake.calls[1]["messages"]
    assistant = next(m for m in second_call if m["role"] == "assistant")
    tool_msg = next(m for m in second_call if m["role"] == "tool")
    call_id = assistant["tool_calls"][0]["id"]
    assert call_id and tool_msg["tool_call_id"] == call_id
    # Gemini 3 needs its thought signature echoed back unchanged
    assert assistant["tool_calls"][0]["extra_content"] == {"google": {"thought_signature": "sig-123"}}

    events = [json.loads(line) for line in log.read_text().splitlines()]
    validator = Draft202012Validator(json.loads((ROOT / "schema" / "event_schema.json").read_text()))
    for event in events:
        assert not list(validator.iter_errors(event)), event
    request = next(e for e in events if e["event"]["type"] == "model_request")
    assert request["model"]["provider"] == "gemini"
