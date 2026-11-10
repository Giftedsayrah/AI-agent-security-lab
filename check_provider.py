"""Tests your key for the provider chosen with PROVIDER: lists the models the key
can use, then sends one tiny request exactly the way the agent does. Prints status
codes and model names only, never the key."""
import json
import os
import urllib.error
import urllib.request

from agent import config
from agent.providers import PROVIDERS

PROVIDER = config.PROVIDER
MODEL = config.MODEL
TIMEOUT = int(os.getenv("LLM_TIMEOUT") or os.getenv("GEMINI_TIMEOUT") or "90")
SKIP = ("embed", "whisper", "tts", "image", "audio", "moderation", "guard", "transcribe", "dall", "robotics")


def call(url, headers, body=None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        url, data=data, method="POST" if body is not None else "GET",
        headers={"Content-Type": "application/json", "User-Agent": "helpdesk-lab-check", **headers})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.status, response.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")[:300]
    except Exception as exc:  # network problems, timeouts
        return 0, str(exc)


def main() -> None:
    if PROVIDER == "anthropic":
        key_env, base = "ANTHROPIC_API_KEY", "https://api.anthropic.com/v1/"
        headers = {"x-api-key": os.getenv(key_env, ""), "anthropic-version": "2023-06-01"}
        if os.getenv("ANTHROPIC_WORKSPACE_ID"):  # needed only for keys not tied to one workspace
            headers["anthropic-workspace-id"] = os.environ["ANTHROPIC_WORKSPACE_ID"]
        chat_url = base + "messages"
        body = {"model": MODEL, "max_tokens": 20, "messages": [{"role": "user", "content": "Say OK"}]}
    elif PROVIDER in PROVIDERS:
        settings = PROVIDERS[PROVIDER]
        key_env, base = settings["key_env"], settings["base_url"].rstrip("/") + "/"
        headers = {"Authorization": f"Bearer {os.getenv(key_env, '')}"}
        chat_url = base + "chat/completions"
        body = {"model": MODEL, settings["token_param"]: 50,
                "messages": [{"role": "user", "content": "Say OK"}]}
    else:
        raise SystemExit(f"Unknown PROVIDER '{PROVIDER}'. Use anthropic, gemini, openai or groq.")

    key = os.getenv(key_env, "")
    if not key:
        raise SystemExit(f"{key_env} is not set in this PowerShell window.")
    print(f"Provider: {PROVIDER}   model: {MODEL}   key starts with: {key[:3]}   length: {len(key)}   timeout: {TIMEOUT}s")

    status, text = call(base + "models" + ("?limit=100" if PROVIDER == "anthropic" else ""), headers)
    if status == 200:
        items = json.loads(text).get("data") or json.loads(text).get("models") or []
        names = sorted({(m.get("id") or m.get("name", "")).removeprefix("models/") for m in items})
        names = [n for n in names if n and not any(w in n.lower() for w in SKIP)]
        print("Models your key can use:")
        for name in names[:40]:
            print("   ", name)
    else:
        print(f"Model list: {status} FAILED  {text[:200]}")

    status, text = call(chat_url, headers, body)
    print(f"Test request: {status} {'OK' if status == 200 else 'FAILED'}")
    if status != 200:
        print("   ", text.replace("\n", " ")[:300])
        print("\nSend these lines to Claude (not the key).")
    else:
        print("\nThe agent should work. Start it now.")


if __name__ == "__main__":
    main()
