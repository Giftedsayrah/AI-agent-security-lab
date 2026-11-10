"""Finds AI services in proxy, DNS or firewall logs, so you can see which tools staff are
using, including ones nobody approved ("shadow AI").

Works on CSV or tab-separated exports that have a domain, host or URL column (and
ideally a user or source column), and falls back to scanning plain text logs.

    python shadow_ai.py proxy_export.csv
    python shadow_ai.py dns.log --allow "Microsoft Copilot,GitHub Copilot" --out shadow_ai_report.md
    python shadow_ai.py export.csv --domain-col cs-host --user-col username"""
import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

AI_SERVICES = {
    "OpenAI / ChatGPT": ["openai.com", "chatgpt.com", "oaiusercontent.com"],
    "Anthropic / Claude": ["anthropic.com", "claude.ai", "claude.com"],
    "Google Gemini": ["gemini.google.com", "generativelanguage.googleapis.com", "aistudio.google.com",
                      "bard.google.com"],
    "Microsoft Copilot": ["copilot.microsoft.com"],
    "GitHub Copilot": ["githubcopilot.com"],
    "Perplexity": ["perplexity.ai"],
    "DeepSeek": ["deepseek.com"],
    "Mistral": ["mistral.ai"],
    "xAI Grok": ["grok.com", "x.ai"],
    "Meta AI": ["meta.ai"],
    "Groq": ["groq.com"],
    "Hugging Face": ["huggingface.co"],
    "Cohere": ["cohere.com", "cohere.ai"],
    "Character.AI": ["character.ai"],
    "Poe": ["poe.com"],
    "Midjourney": ["midjourney.com"],
    "Stability AI": ["stability.ai"],
    "ElevenLabs": ["elevenlabs.io"],
    "Otter.ai": ["otter.ai"],
    "Fireflies": ["fireflies.ai"],
    "Grammarly": ["grammarly.com"],
    "Jasper": ["jasper.ai"],
}
DOMAIN_COLUMNS = ("domain", "host", "hostname", "dest_host", "destination_host", "url", "query", "qname", "fqdn",
                  "cs-host", "cs_host", "dst_host", "server_name", "sni", "request")
USER_COLUMNS = ("user", "username", "user_name", "src_user", "srcuser", "client", "client_ip", "src_ip", "srcip",
                "source_ip", "source", "device", "machine")
HOST_PATTERN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
SUFFIXES = sorted(((d, svc) for svc, ds in AI_SERVICES.items() for d in ds), key=lambda p: -len(p[0]))


def to_host(value: str) -> str:
    value = value.strip().strip('"').lower()
    if "://" in value:
        value = urlparse(value).hostname or ""
    return value.split("/")[0].split(":")[0].rstrip(".")


def match_service(host: str):
    for domain, service in SUFFIXES:
        if host == domain or host.endswith("." + domain):
            return service, domain
    return None


def pick(header: list, wanted: tuple, override: str = ""):
    lowered = [h.strip().lower() for h in header]
    if override:
        return lowered.index(override.lower()) if override.lower() in lowered else None
    for name in wanted:
        if name in lowered:
            return lowered.index(name)
    return None


def read_rows(path: Path, domain_col: str = "", user_col: str = ""):
    """Yields (host, user) pairs from a CSV/TSV export or a plain text log."""
    text = path.read_text(encoding="utf-8", errors="replace")
    first = text.splitlines()[0] if text else ""
    delimiter = "\t" if first.count("\t") > first.count(",") else ","
    header = next(csv.reader([first], delimiter=delimiter), [])
    d_idx = pick(header, DOMAIN_COLUMNS, domain_col)
    if d_idx is None:  # plain text: find host names anywhere in each line
        for line in text.splitlines():
            for found in HOST_PATTERN.findall(line):
                yield found.lower(), ""
        return
    u_idx = pick(header, USER_COLUMNS, user_col)
    for row in csv.reader(text.splitlines()[1:], delimiter=delimiter):
        if len(row) > d_idx:
            yield to_host(row[d_idx]), (row[u_idx].strip() if u_idx is not None and len(row) > u_idx else "")


def analyse(rows, allowed=()) -> dict:
    allow = [a.strip().lower() for a in allowed if a.strip()]
    stats = defaultdict(lambda: {"requests": 0, "users": set(), "domains": set()})
    total = 0
    for host, user in rows:
        total += 1
        found = match_service(host)
        if not found:
            continue
        entry = stats[found[0]]
        entry["requests"] += 1
        entry["domains"].add(host)
        if user:
            entry["users"].add(user)
    for service, entry in stats.items():
        entry["status"] = "allowed" if any(a in service.lower() for a in allow) else "SHADOW AI"
    return {"total": total, "services": dict(stats)}


def build_report(result: dict, source: str) -> str:
    services = sorted(result["services"].items(), key=lambda kv: -kv[1]["requests"])
    shadow = [s for s, e in services if e["status"] == "SHADOW AI"]
    lines = ["# Shadow AI discovery", "",
             f"Source: {source}  \nRecords read: {result['total']}  \nAI services found: {len(services)} "
             f"({len(shadow)} not on the allowed list).", ""]
    if not services:
        lines.append("No known AI services appear in this log.")
    else:
        lines += ["| Service | Requests | Distinct users | Domains seen | Status |", "|---|---|---|---|---|"]
        for service, e in services:
            users = len(e["users"]) if e["users"] else "unknown"
            lines.append(f"| {service} | {e['requests']} | {users} | {', '.join(sorted(e['domains']))[:80]} | "
                         f"{e['status']} |")
    lines += ["", "## What to do with this", "",
              "Decide which services are approved, block or monitor the rest, and tell staff what they may and may "
              "not paste into them. Staff may be sending personal data to these services, and sending personal data "
              "outside Nigeria is covered by sections 41 and 42 of the Nigeria Data Protection Act 2023, so involve "
              "your data protection officer. This is information and not legal advice.", "",
              "A match shows a request to the service, not what was sent. The list of services is a starting point "
              "and new services appear all the time, so extend `AI_SERVICES` in `shadow_ai.py` as needed.", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("log", help="CSV, TSV or text log export")
    parser.add_argument("--allow", default="", help="comma-separated approved services, e.g. 'Microsoft Copilot'")
    parser.add_argument("--domain-col", default="", help="column holding the domain, host or URL")
    parser.add_argument("--user-col", default="", help="column holding the user or source")
    parser.add_argument("--out", default="shadow_ai_report.md")
    args = parser.parse_args()

    path = Path(args.log)
    if not path.exists():
        raise SystemExit(f"File not found: {path}")
    result = analyse(read_rows(path, args.domain_col, args.user_col), args.allow.split(","))
    report = build_report(result, path.name)
    Path(args.out).write_text(report, encoding="utf-8")
    print(report)
    print(f"\nSaved to {args.out}")


if __name__ == "__main__":
    main()
