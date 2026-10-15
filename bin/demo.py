#!/usr/bin/env python3
"""End-to-end demo of one supervised improvement cycle, with scripted model replies.

    python3 bin/demo.py

No model is called and nothing leaves this machine. The demo:
  1. builds a throwaway git repo holding the toy domain (agentlib/textstats.py);
  2. writes a throwaway pins file for this checkout's control files (a real
     deployment pins once, as a human, with `evaluator/evaluate.py --pin`);
  3. adds one backlog item to a throwaway ledger;
  4. runs heavy_cycle.cycle with a fake `call`: the "writer" first forgets the test
     (the evaluator rejects it and the writer gets the failed gate back), then sends a
     change with a test; the frozen evaluator runs it in the macOS sandbox; the
     "panel" approves; a local branch and a PR draft are written;
  5. prints the decision, the ledger rows and the chain check.

The evaluator part is real (sandbox-exec, hdiutil), so this needs macOS.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bin"))
import heavy_cycle  # noqa: E402
import ledger_append  # noqa: E402
import review_panel  # noqa: E402

BACKLOG_ITEM = {"id": "textstats-longest-word", "area": "textstats", "title": "Add longest_word",
                "detail": "Add longest_word(text) to agentlib/textstats.py: the first longest word, or '' for none.",
                "weight": 1, "feasibility": 1, "cost": 1, "files": ["agentlib/textstats.py"]}

NEW_MODULE = (ROOT / "agentlib/textstats.py").read_text() + '''

def longest_word(text):
    """The first longest word in `text`, or an empty string when there are none."""
    best = ""
    for word in words(text):
        if len(word) > len(best):
            best = word
    return best
'''
NEW_TEST = '''import unittest

from agentlib.textstats import longest_word


class LongestWordTests(unittest.TestCase):
    def test_first_longest_wins_and_empty_text_gives_empty(self):
        self.assertEqual(longest_word("a bb cc ddd eee"), "ddd")
        self.assertEqual(longest_word(""), "")
'''


def blocks(files):
    return "".join(f"<<<FILE {path}>>>\n{text}<<<END FILE>>>\n" for path, text in files.items())


def scripted_call(writer_family):
    """Stands in for llm_call.run: same signature, canned replies, no network."""
    replies = {
        "heavy_cycle.write.1": blocks({"agentlib/textstats.py": NEW_MODULE}),  # no test: the evaluator refuses
        "heavy_cycle.write.2": blocks({"agentlib/textstats.py": NEW_MODULE, "tests/test_longest_word.py": NEW_TEST}),
    }
    assigned = review_panel.assign(writer_family, review_panel.ROLES)
    for family, roles in assigned.items():
        replies[f"review_panel.{family}"] = json.dumps(
            {"reviews": [{"role": role, "verdict": "approve", "reasons": []} for role in roles]})
    seen = []

    def call(cli, model, job, prompt, out, timeout, ledger_path=None):
        seen.append(job)
        Path(out).write_text(replies[job])
        return "ok"
    return call, seen


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=demo", "-c", "user.email=demo@localhost",
                           *args], check=True, capture_output=True, text=True).stdout


def main():
    with tempfile.TemporaryDirectory(prefix="agent-demo-") as tmp:
        tmp = Path(tmp).resolve()
        repo, ledger, state = tmp / "repo", str(tmp / "ledger.jsonl"), tmp / "state"
        for rel in ("agentlib/__init__.py", "agentlib/textstats.py", "tests/__init__.py", "tests/test_textstats.py"):
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text((ROOT / rel).read_text())
        git(repo, "init", "-q", "-b", "main")
        git(repo, "add", ".")
        git(repo, "commit", "-qm", "toy domain")
        pins = tmp / "pins.json"
        pins.write_text(json.dumps(heavy_cycle.frozen.control_digest()))
        heavy_cycle.frozen.PINS = pins  # demo only: real pins live outside the repo, written by a human
        ledger_append.append("backlog", BACKLOG_ITEM, path=ledger)

        call, seen = scripted_call(heavy_cycle.WRITER[0])
        result = heavy_cycle.cycle(repo, ledger, call=call, run_id="demo-run", state_dir=state)

        print("model calls (scripted):", ", ".join(seen))
        print("outcome:", json.dumps(result))
        print("ledger rows:")
        for row in heavy_cycle.ledger_rows(ledger):
            data = row["data"]
            summary = data.get("outcome") or data.get("role") or data.get("id") or data.get("kind")
            print(f"  {row['seq']:>2} {row['type']:<9} {summary}")
        print("chain:", ledger_append.verify(ledger)[1])
        print("local branches:", git(repo, "branch", "--list", "agent/*").strip() or "(none)")
        for run in sorted((state / "runs" / "demo-run").glob("evaluator-*.json")):
            checks = json.loads(run.read_text())["checks"]
            print(f"{run.name}: " + " ".join(f"{c['gate']}={'ok' if c['ok'] else 'FAIL'}" for c in checks))
        draft = state / "pr-drafts" / "demo-run.md"
        if draft.exists():
            print("PR draft (first lines):")
            print("\n".join("  " + line for line in draft.read_text().splitlines()[:6]))
        return 0 if result.get("outcome") == "drafted" else 1


if __name__ == "__main__":
    sys.exit(main())
