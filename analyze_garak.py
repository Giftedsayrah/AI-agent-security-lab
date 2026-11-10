"""Compares Garak's results with what the agent's logging flagged.

Reads a Garak report.jsonl, runs every attack prompt through the same injection
patterns the agent uses, and shows for each probe how many prompts your logging
flagged, how many attacks succeeded, and how many successful attacks slipped past
the flags. Then it prints samples of unflagged prompts, so you can see what to fix.

Run from the project folder:
    python analyze_garak.py                      newest report in garak\\reports
    python analyze_garak.py path\\to\\file.report.jsonl --show 8"""
import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

from agent.telemetry import INJECTION_PATTERNS

ROOT = Path(__file__).resolve().parent
PAYLOAD_WORDS = re.compile(
    r"ignore|instead|print|say |output|respond|do not|don't|must|important|system|assistant|instruction", re.I)


def prompt_text(prompt) -> str:
    """Garak stores prompts as plain text or as a conversation; handle both."""
    if isinstance(prompt, str):
        return prompt
    if isinstance(prompt, list):
        return "\n".join(prompt_text(p) for p in prompt)
    if isinstance(prompt, dict):
        if "turns" in prompt:
            return "\n".join(prompt_text(t.get("content", t)) for t in prompt["turns"]
                             if t.get("role", "user") == "user")
        if "text" in prompt:
            return str(prompt["text"])
        if "content" in prompt:
            return prompt_text(prompt["content"])
    return ""


def load_attempts(path) -> list:
    attempts = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("entry_type") == "attempt":
            attempts.append(entry)
    if any(a.get("status") == 2 for a in attempts):  # keep only finished, evaluated attempts
        attempts = [a for a in attempts if a.get("status") == 2]
    return attempts


def attack_succeeded(attempt: dict) -> bool:
    for scores in (attempt.get("detector_results") or {}).values():
        for score in (scores if isinstance(scores, list) else [scores]):
            if isinstance(score, (int, float)) and score >= 0.5:
                return True
    return False


def flags_for(text: str) -> list:
    return [name for name, pattern in INJECTION_PATTERNS.items() if pattern.search(text)]


def summarize(attempts: list) -> dict:
    stats = defaultdict(lambda: {"prompts": 0, "flagged": 0, "success": 0, "success_missed": 0})
    for attempt in attempts:
        row = stats[attempt.get("probe_classname", "unknown")]
        flagged = bool(flags_for(prompt_text(attempt.get("prompt"))))
        success = attack_succeeded(attempt)
        row["prompts"] += 1
        row["flagged"] += flagged
        row["success"] += success
        row["success_missed"] += success and not flagged
    return dict(stats)


def missed_samples(attempts: list, limit: int) -> list:
    samples, per_probe = [], defaultdict(int)
    for attempt in attempts:
        text = prompt_text(attempt.get("prompt"))
        probe = attempt.get("probe_classname", "unknown")
        if flags_for(text) or per_probe[probe] >= 2 or len(samples) >= limit:
            continue
        per_probe[probe] += 1
        lines = [ln.strip()[:220] for ln in text.splitlines() if PAYLOAD_WORDS.search(ln)][:3]
        samples.append((probe, len(text), lines or [text.strip()[-220:]]))
    return samples


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", nargs="?", help="Garak report.jsonl (default: newest)")
    parser.add_argument("--show", type=int, default=5, help="how many missed prompts to print")
    args = parser.parse_args()

    if args.report:
        path = Path(args.report)
    else:
        found = sorted((ROOT / "garak" / "reports").rglob("*.report.jsonl"),
                       key=lambda p: p.stat().st_mtime)
        if not found:
            raise SystemExit("No Garak report found under garak\\reports. Run a scan first.")
        path = found[-1]
    attempts = load_attempts(path)
    print(f"Report: {path.name}   attempts: {len(attempts)}\n")

    stats = summarize(attempts)
    print(f"{'Probe':52} {'Prompts':>7} {'Flagged':>7} {'Attacks worked':>14} {'Worked, not flagged':>19}")
    totals = {"prompts": 0, "flagged": 0, "success": 0, "success_missed": 0}
    for probe, row in sorted(stats.items()):
        print(f"{probe[:52]:52} {row['prompts']:>7} {row['flagged']:>7} {row['success']:>14} {row['success_missed']:>19}")
        for key in totals:
            totals[key] += row[key]
    print(f"{'TOTAL':52} {totals['prompts']:>7} {totals['flagged']:>7} {totals['success']:>14} {totals['success_missed']:>19}")

    samples = missed_samples(attempts, args.show)
    if samples:
        print("\nSamples of prompts your logging did NOT flag (lines that look like instructions):")
        for probe, length, lines in samples:
            print(f"\n  {probe}  ({length} characters)")
            for line in lines:
                print(f"    | {line}")


if __name__ == "__main__":
    main()
