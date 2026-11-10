"""Model clients. Every client exposes client.messages.create(...) in Anthropic's
shape, so the agent loop and the logging wrapper do not care which model is behind it.

ChatCompletionsAdapter covers Gemini, OpenAI and Groq through their OpenAI-style
chat completions endpoints and translates messages, tool definitions and replies
to and from Anthropic's format."""
import json
import os
import uuid
from dataclasses import dataclass
from types import SimpleNamespace

# Everything that differs between the OpenAI-style providers lives here.
PROVIDERS = {
    "gemini": {
        "key_env": "GEMINI_API_KEY",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "prefixes": ("AQ.", "AIza"),  # AQ. is the current format
        "token_param": "max_tokens",
    },
    "openai": {
        "key_env": "OPENAI_API_KEY",
        "base_url": "https://api.openai.com/v1",
        "prefixes": ("sk-",),
        "token_param": "max_completion_tokens",  # newer OpenAI models reject max_tokens
    },
    "groq": {
        "key_env": "GROQ_API_KEY",
        "base_url": "https://api.groq.com/openai/v1",
        "prefixes": ("gsk_",),
        "token_param": "max_tokens",
    },
}


@dataclass
class TextBlock:
    text: str
    type: str = "text"


@dataclass
class ToolUseBlock:
    id: str
    name: str
    input: dict
    type: str = "tool_use"
    extra: dict = None  # Gemini 3 thought signature, must be sent back unchanged


@dataclass
class Reply:
    content: list
    stop_reason: str
    usage: SimpleNamespace


class ChatCompletionsAdapter:
    def __init__(self, provider: str = "gemini", client=None, api_key=None):
        self.settings = PROVIDERS[provider]
        if client is None:
            from openai import OpenAI  # imported here so tests run without the SDK
            timeout = os.getenv("LLM_TIMEOUT") or os.getenv("GEMINI_TIMEOUT") or "90"
            client = OpenAI(api_key=api_key or os.environ[self.settings["key_env"]],
                            base_url=self.settings["base_url"],
                            timeout=float(timeout), max_retries=1)
        self._client = client
        self.messages = self  # lets the agent call client.messages.create(...)

    def create(self, model, max_tokens, system, tools, messages):
        extra = {}
        effort = os.getenv("REASONING_EFFORT") or os.getenv("GEMINI_REASONING")
        if effort:
            extra["reasoning_effort"] = effort  # lower effort means faster replies
        response = self._client.chat.completions.create(
            model=model,
            messages=[{"role": "system", "content": system}] + self._convert_messages(messages),
            tools=[self._convert_tool(t) for t in tools],
            tool_choice="auto",
            **{self.settings["token_param"]: max_tokens},
            **extra,
        )
        return self._to_reply(response)

    @staticmethod
    def _convert_tool(tool: dict) -> dict:
        return {"type": "function",
                "function": {"name": tool["name"],
                             "description": tool.get("description", ""),
                             "parameters": tool["input_schema"]}}

    @staticmethod
    def _convert_messages(messages: list) -> list:
        out = []
        for m in messages:
            content = m["content"]
            if isinstance(content, str):
                out.append({"role": m["role"], "content": content})
            elif m["role"] == "user":  # a list of tool results
                for item in content:
                    out.append({"role": "tool", "tool_call_id": item["tool_use_id"],
                                "content": item["content"]})
            else:  # assistant turn made of text and tool_use blocks
                text = "".join(b.text for b in content if b.type == "text")
                calls = []
                for b in content:
                    if b.type != "tool_use":
                        continue
                    call = {"id": b.id, "type": "function",
                            "function": {"name": b.name, "arguments": json.dumps(b.input)}}
                    if b.extra:
                        call["extra_content"] = b.extra
                    calls.append(call)
                message = {"role": "assistant", "content": text or None}
                if calls:
                    message["tool_calls"] = calls
                out.append(message)
        return out

    @staticmethod
    def _extra_content(call):
        """Gemini 3 models attach a thought signature to tool calls. It must be
        returned unchanged on the next request or Google rejects it with a 400."""
        extra = getattr(call, "extra_content", None)
        if extra is None:
            extra = (getattr(call, "model_extra", None) or {}).get("extra_content")
        return extra

    @staticmethod
    def _to_reply(response) -> Reply:
        message = response.choices[0].message
        blocks = []
        if message.content:
            blocks.append(TextBlock(message.content))
        for call in message.tool_calls or []:
            try:
                args = json.loads(call.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            blocks.append(ToolUseBlock(id=call.id or "call_" + uuid.uuid4().hex[:8],
                                       name=call.function.name, input=args,
                                       extra=ChatCompletionsAdapter._extra_content(call)))
        stop = "tool_use" if any(b.type == "tool_use" for b in blocks) else "end_turn"
        usage = getattr(response, "usage", None)
        return Reply(blocks, stop, SimpleNamespace(
            input_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            output_tokens=getattr(usage, "completion_tokens", 0) or 0))


GeminiAdapter = ChatCompletionsAdapter  # name used by the earlier tests


def _check_key(key: str, prefixes: tuple, name: str) -> None:
    if not key:
        raise SystemExit(f"{name} is not set. See LAB_SETUP_WINDOWS.md.")
    if not key.startswith(prefixes):
        print(f"Warning: {name} does not start with {' or '.join(prefixes)}, "
              "so it may be the wrong key.")


def make_client(provider: str):
    if provider in PROVIDERS:
        settings = PROVIDERS[provider]
        key = os.environ.get(settings["key_env"], "")
        _check_key(key, settings["prefixes"], settings["key_env"])
        return ChatCompletionsAdapter(provider, api_key=key)
    if provider != "anthropic":
        raise SystemExit(f"Unknown PROVIDER '{provider}'. Use anthropic, gemini, openai or groq.")
    import anthropic
    _check_key(os.environ.get("ANTHROPIC_API_KEY", ""), ("sk-ant-",), "ANTHROPIC_API_KEY")
    headers = {}
    workspace = os.getenv("ANTHROPIC_WORKSPACE_ID")  # only for keys not tied to one workspace
    if workspace:
        headers["anthropic-workspace-id"] = workspace
    return anthropic.Anthropic(default_headers=headers or None)
