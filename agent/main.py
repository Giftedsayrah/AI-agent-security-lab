"""Interactive CLI: python -m agent.main --user u_demo_01"""
import argparse

from . import config
from .agent import HelpdeskAgent
from .providers import make_client
from .telemetry import SessionContext, Telemetry
from .tools import ToolBox


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", default="u_demo_01")
    parser.add_argument("--role", default="employee")
    args = parser.parse_args()

    telemetry = Telemetry()
    agent = HelpdeskAgent(make_client(config.PROVIDER), telemetry, ToolBox(telemetry))
    ctx = SessionContext(user_id=args.user, user_role=args.role)
    print(f"Session {ctx.session_id} using {config.PROVIDER}/{config.MODEL}. Type 'exit' to quit.")
    try:
        while (text := input("you> ").strip()) != "exit":
            if not text:
                continue
            try:
                print("agent>", agent.chat(ctx, text))
            except Exception as exc:  # keep the session alive on API errors
                print(f"Model call failed ({type(exc).__name__}): {exc}")
    finally:
        agent.end_session(ctx)


if __name__ == "__main__":
    main()
