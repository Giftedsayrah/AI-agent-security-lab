"""The agent loop. Every model call goes through _call_model so it is logged."""
import time

from . import config
from .telemetry import SessionContext, Telemetry
from .tools import TOOL_SCHEMAS, ToolBox


class HelpdeskAgent:
    def __init__(self, client, telemetry: Telemetry, toolbox: ToolBox, model: str = config.MODEL):
        self.client, self.t, self.tools, self.model = client, telemetry, toolbox, model

    def chat(self, ctx: SessionContext, user_text: str) -> str:
        ctx.new_turn(user_text)
        self.t.emit(ctx, "user_prompt",
                    content=self.t.content("user", user_text),
                    flags=self.t.flags(user_text))
        ctx.messages.append({"role": "user", "content": user_text})

        for _ in range(config.MAX_STEPS):
            response = self._call_model(ctx)
            ctx.messages.append({"role": "assistant", "content": response.content})
            if response.stop_reason != "tool_use":
                return self._text(response)
            results = [{"type": "tool_result", "tool_use_id": block.id,
                        "content": self.tools.run(ctx, block.name, block.input)}
                       for block in response.content if block.type == "tool_use"]
            ctx.messages.append({"role": "user", "content": results})

        self.t.emit(ctx, "model_response", outcome="blocked")
        return "I could not finish that request."

    def end_session(self, ctx: SessionContext) -> None:
        self.t.emit(ctx, "session_end")

    def _call_model(self, ctx: SessionContext):
        self.t.emit(ctx, "model_request", model={"provider": config.PROVIDER, "name": self.model})
        start = time.perf_counter()
        response = self.client.messages.create(
            model=self.model, max_tokens=1024, system=config.SYSTEM_PROMPT,
            tools=TOOL_SCHEMAS, messages=ctx.messages)
        text = self._text(response)
        self.t.emit(ctx, "model_response",
                    model={"provider": config.PROVIDER, "name": self.model,
                           "input_tokens": response.usage.input_tokens,
                           "output_tokens": response.usage.output_tokens,
                           "latency_ms": int((time.perf_counter() - start) * 1000)},
                    content=self.t.content("model", text),
                    flags=self.t.flags(text, check_leak=True, ignore=ctx.latest_user_prompt))
        return response

    @staticmethod
    def _text(response) -> str:
        return "".join(b.text for b in response.content if b.type == "text")
