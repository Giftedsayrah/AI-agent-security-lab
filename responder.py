"""Responder (Weeks 7-8): turns Kibana alerts into automatic containment.

It checks Elasticsearch every few seconds for new alerts from your detection rules.
For each alert it follows the playbook below: it contains the user or the risky action
(the agent refuses tool calls for contained users), and it records an incident.
Every block expires on its own (30 minutes by default).

Run from the project folder, in its own PowerShell window:
    python responder.py                  watch for new alerts
    python responder.py --status         show what is contained right now
    python responder.py --release        lift every block"""
import argparse
import base64
import json
import os
import time
import urllib.request
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import containment

ROOT = Path(__file__).resolve().parent
ALERT_INDEX = ".alerts-security.alerts-default"
EVENT_INDEX = "agent-events*"

# (text found in the rule name, actions). The first match wins.
PLAYBOOK = [
    ("email sent to an external", ["block_external_email", "block_user", "incident"]),
    ("tool call started by model", ["block_user", "incident"]),
    ("bulk employee lookups", ["block_user", "incident"]),
    ("personal data in model output", ["incident"]),
    ("injection phrase", ["watch"]),
]
WATCH_LIMIT = 5        # injection alerts from one user ...
WATCH_WINDOW = 300     # ... within this many seconds trigger a block


def dig(source: dict, dotted: str):
    """Reads a field whether the document stores it flat, nested, or a mix of both."""
    def walk(node, parts):
        if not parts:
            return node
        if not isinstance(node, dict):
            return None
        for n in range(len(parts), 0, -1):
            key = ".".join(parts[:n])
            if key in node:
                found = walk(node[key], parts[n:])
                if found is not None:
                    return found
        return None
    return walk(source, dotted.split("."))


def scalar(source: dict, dotted: str):
    value = dig(source, dotted)
    return value[0] if isinstance(value, list) and value else value


def extract(hit: dict) -> dict:
    source = hit.get("_source", {})
    session = scalar(source, "ai.session.id")
    if not session:  # threshold alerts carry the grouped value instead
        for term in dig(source, "kibana.alert.threshold_result.terms") or []:
            if isinstance(term, dict) and term.get("field") == "ai.session.id":
                session = term.get("value")
    return {"id": hit.get("_id"), "rule": scalar(source, "kibana.alert.rule.name") or "",
            "severity": scalar(source, "kibana.alert.severity") or "", "time": source.get("@timestamp"),
            "user": scalar(source, "ai.user.id"), "session": session}


class Responder:
    def __init__(self, search, state_path=None, incident_path=None, minutes=30, now=time.time):
        self.search, self.state_path, self.minutes, self.now = search, state_path, minutes, now
        self.incident_path = Path(incident_path or ROOT / "containment" / "incidents.jsonl")
        self.seen, self.watch = set(), defaultdict(deque)

    def resolve_user(self, alert: dict):
        if alert["user"] or not alert["session"]:
            return alert["user"]
        reply = self.search(EVENT_INDEX, {"size": 1, "_source": ["ai.user.id"],
                                          "query": {"term": {"ai.session.id": alert["session"]}}})
        hits = reply.get("hits", {}).get("hits", [])
        return scalar(hits[0].get("_source", {}), "ai.user.id") if hits else None

    def handle(self, alert: dict) -> list:
        user = self.resolve_user(alert)
        actions = []
        for text, plan in PLAYBOOK:
            if text not in alert["rule"].lower():
                continue
            for step in plan:
                if step == "block_external_email":
                    containment.block_external_email(alert["rule"], self.minutes, self.state_path)
                    actions.append("blocked email to external addresses")
                elif step == "block_user" and user:
                    containment.block_user(user, alert["rule"], self.minutes, self.state_path)
                    actions.append(f"contained user {user}")
                elif step == "watch" and user and self._watch_tripped(user):
                    containment.block_user(user, f"{WATCH_LIMIT}+ injection alerts in {WATCH_WINDOW}s",
                                           self.minutes, self.state_path)
                    actions.append(f"contained user {user} (repeated injection attempts)")
                elif step == "incident":
                    actions.append("recorded incident")
            break
        if actions or alert["rule"]:
            self._record(alert, user, actions)
        return actions

    def _watch_tripped(self, user: str) -> bool:
        recent, now = self.watch[user], self.now()
        recent.append(now)
        while recent and now - recent[0] > WATCH_WINDOW:
            recent.popleft()
        return len(recent) >= WATCH_LIMIT

    def _record(self, alert: dict, user, actions: list) -> None:
        entry = {"recorded": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "rule": alert["rule"], "severity": alert["severity"], "alert_id": alert["id"],
                 "alert_time": alert["time"], "user": user, "session": alert["session"],
                 "actions": actions}
        self.incident_path.parent.mkdir(parents=True, exist_ok=True)
        with self.incident_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        if actions:
            print(f"[{entry['recorded']}] {alert['severity'] or '-':8} {alert['rule']}\n"
                  f"    user={user} session={alert['session']}\n    -> " + "; ".join(actions))

    def poll(self, since_iso: str):
        """Handles new alerts and returns the timestamp to use next time."""
        body = {"size": 200, "sort": [{"@timestamp": "asc"}],
                "query": {"range": {"@timestamp": {"gt": since_iso}}}}
        hits = self.search(ALERT_INDEX, body).get("hits", {}).get("hits", [])
        latest = since_iso
        for hit in hits:
            alert = extract(hit)
            latest = max(latest, alert["time"] or latest)
            if alert["id"] in self.seen:
                continue
            self.seen.add(alert["id"])
            self.handle(alert)
        return latest


def make_search(url: str, user: str, password: str):
    token = base64.b64encode(f"{user}:{password}".encode()).decode()

    def search(index: str, body: dict) -> dict:
        request = urllib.request.Request(
            f"{url}/{index}/_search", data=json.dumps(body).encode(), method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Basic {token}"})
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read())
    return search


def elastic_password() -> str:
    if os.getenv("ELASTIC_PASSWORD"):
        return os.environ["ELASTIC_PASSWORD"]
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("ELASTIC_PASSWORD="):
                return line.split("=", 1)[1].strip()
    raise SystemExit("ELASTIC_PASSWORD is not set and was not found in .env")


def show_status() -> None:
    state = containment.load()
    print("Contained users:", ", ".join(f"{u} ({v['reason']})" for u, v in state["blocked_users"].items()) or "none")
    external = state["external_email"]
    print("Email to external addresses:", f"blocked ({external['reason']})" if external else "allowed")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:9200")
    parser.add_argument("--interval", type=int, default=10, help="seconds between checks")
    parser.add_argument("--minutes", type=int, default=30, help="how long each block lasts")
    parser.add_argument("--since-minutes", type=int, default=0,
                        help="also handle alerts from this many minutes ago (default: only new ones)")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()

    if args.status:
        return show_status()
    if args.release:
        containment.release_all()
        print("All blocks lifted.")
        return show_status()

    responder = Responder(make_search(args.url, "elastic", elastic_password()), minutes=args.minutes)
    since = (datetime.now(timezone.utc) - timedelta(minutes=args.since_minutes)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    print(f"Watching for new alerts every {args.interval}s. Blocks last {args.minutes} minutes. "
          "Press Ctrl and C to stop.")
    try:
        while True:
            try:
                since = responder.poll(since)
            except Exception as exc:  # keep going if Elasticsearch is briefly unreachable
                print(f"Could not read alerts ({type(exc).__name__}): {exc}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
