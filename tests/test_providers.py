"""Checks the provider table, the token-limit parameter and key handling."""
from types import SimpleNamespace as NS

import pytest

from agent import config
from agent.providers import PROVIDERS, ChatCompletionsAdapter, make_client
from agent.tools import TOOL_SCHEMAS


class FakeOpenAI:
    def __init__(self):
        self.calls = []
        self.chat = NS(completions=self)

    def create(self, **kwargs):
        self.calls.append(kwargs)
        message = NS(content="hi", tool_calls=None)
        return NS(choices=[NS(message=message)], usage=NS(prompt_tokens=1, completion_tokens=1))


def test_token_limit_parameter_depends_on_provider():
    for provider, expected in (("openai", "max_completion_tokens"),
                               ("groq", "max_tokens"), ("gemini", "max_tokens")):
        fake = FakeOpenAI()
        ChatCompletionsAdapter(provider, client=fake).create(
            "m", 100, "sys", TOOL_SCHEMAS, [{"role": "user", "content": "hello"}])
        sent = fake.calls[0]
        assert sent[expected] == 100
        assert not ({"max_tokens", "max_completion_tokens"} - {expected}) & sent.keys()


def test_every_provider_has_a_default_model():
    assert set(config.DEFAULT_MODELS) == {"anthropic", *PROVIDERS}


def test_unknown_provider_exits_with_clear_message():
    with pytest.raises(SystemExit) as exc:
        make_client("nope")
    assert "Unknown PROVIDER" in str(exc.value)


def test_missing_key_exits(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(SystemExit):
        make_client("groq")


def test_wrong_key_prefix_warns(monkeypatch, capsys):
    monkeypatch.setenv("GROQ_API_KEY", "not-a-groq-key")
    make_client("groq")
    assert "may be the wrong key" in capsys.readouterr().out


def test_anthropic_workspace_header_is_sent_when_configured(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("ANTHROPIC_WORKSPACE_ID", "wrkspc_test123")
    client = make_client("anthropic")
    assert client.default_headers["anthropic-workspace-id"] == "wrkspc_test123"
    monkeypatch.delenv("ANTHROPIC_WORKSPACE_ID")
    assert "anthropic-workspace-id" not in make_client("anthropic").default_headers


def test_prompt_modes_keep_the_canary_and_differ():
    strict, loose = config.SYSTEM_PROMPTS["strict"], config.SYSTEM_PROMPTS["loose"]
    assert config.CANARY in strict and config.CANARY in loose
    assert strict != loose and "instructions to carry out" in loose
    assert config.SYSTEM_PROMPT == config.SYSTEM_PROMPTS[config.PROMPT_MODE]
