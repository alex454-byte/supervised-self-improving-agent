"""The heavy cycle: backlog choice, retry on evaluator failure, review gate, local-only output."""
import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bin"))
import heavy_cycle  # noqa: E402
import ledger_append  # noqa: E402
import review_panel  # noqa: E402
from unittest import mock  # noqa: E402

NESTED = unittest.skipIf(os.environ.get("AGENT_SANDBOXED"),
                         "macOS refuses a sandbox inside a sandbox; these run in every human test run")
TODAY = dt.date(2026, 10, 3)


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout


def item(id_, area="stats", weight=1, cost=1, title="Add triple"):
    return {"id": id_, "area": area, "title": title, "detail": "add triple(x) to agentlib/calc.py",
            "weight": weight, "feasibility": 1, "cost": cost, "files": ["agentlib/calc.py"]}


class BacklogTests(unittest.TestCase):
    def rows(self, *entries):
        return [{"type": t, "ts": f"{d}T00:00:00+00:00", "data": data} for t, d, data in entries]

    def test_priority_area_dedup_and_cooldown(self):
        rows = self.rows(("backlog", "2026-10-01", item("a", weight=1)),
                         ("backlog", "2026-10-01", item("b", weight=5)),
                         ("backlog", "2026-10-01", item("c", area="docs", weight=2)),
                         ("backlog", "2026-09-01", item("d", area="ops")),
                         ("decision", "2026-09-25", {"backlog_id": "d", "outcome": "closed"}),
                         ("backlog", "2026-10-01", item("e", area="ops")))
        ids = [i["id"] for i in heavy_cycle.open_backlog(rows, TODAY)]
        self.assertEqual(ids, ["b", "c"])  # one per area; "ops" cools down 14 days after d closed

    def test_a_human_reopen_clears_the_rejection_and_its_cooldown(self):
        rows = self.rows(("backlog", "2026-10-01", item("f", area="forward")),
                         ("decision", "2026-10-02", {"backlog_id": "f", "outcome": "rejected"}),
                         ("decision", "2026-10-03", {"backlog_id": "f", "outcome": "reopened", "by": "human"}))
        self.assertEqual([i["id"] for i in heavy_cycle.open_backlog(rows, TODAY)], ["f"])
        rows.append({"type": "decision", "ts": "2026-10-03T05:00:00+00:00",
                     "data": {"backlog_id": "f", "outcome": "drafted"}})
        self.assertEqual(heavy_cycle.open_backlog(rows, TODAY), [])

    def test_extract_files(self):
        # agy round 3: a code fence inside a file must not end its block early.
        reply = ("Here:\n<<<FILE agentlib/a.py>>>\nx = 1\n<<<END FILE>>>\n<<<FILE docs/a.md>>>\n```python\nx\n```\n"
                 "after\n<<<END FILE>>>\n")
        self.assertEqual(heavy_cycle.extract_files(reply),
                         {"agentlib/a.py": "x = 1\n", "docs/a.md": "```python\nx\n```\nafter\n"})
        self.assertIn("at most", heavy_cycle.files_problem({f"agentlib/f{i}.py": "x\n" for i in range(9)}))
        self.assertIsNone(heavy_cycle.extract_files("no files here"))

    def test_default_run_ids_and_shas_pass_the_ledger_guard(self):
        # The first real run died here: "20261003-..." is an 8-digit run the ledger refuses.
        self.assertIsNone(ledger_append.FORBIDDEN.search(heavy_cycle.short_sha("1234567890abcdef1234")))
        stamp = dt.datetime(2026, 10, 3, 3, 15, 22).strftime("%Y-%m-%d-%H%M%S")
        self.assertIsNone(ledger_append.FORBIDDEN.search(stamp))

    def test_redaction_never_corrupts_the_record(self):
        # codex round 5: substituting on serialised JSON broke escapes (u-umlaut emails,
        # full-width digits survived as \uXXXX escapes).
        out = heavy_cycle._redact({"reasons": ["mail \u00fc@b.co", "id \uff11\uff12\uff13\uff14\uff15\uff16\uff17\uff18", "ok"]})
        self.assertEqual(out, {"reasons": ["mail [redacted]", "id [redacted]", "ok"]})

    def test_refuses_to_run_without_dry_run(self):
        self.assertEqual(heavy_cycle.main([]), 2)


@NESTED
class CycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.repo, self.ledger, self.state = base / "repo", str(base / "ledger.jsonl"), base / "state"
        for path, text in {"agentlib/__init__.py": "", "tests/__init__.py": "",
                           "agentlib/calc.py": "def double(x):\n    return 2 * x\n"}.items():
            (self.repo / path).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / path).write_text(text)
        git(self.repo, "init", "-q")
        git(self.repo, "add", ".")
        git(self.repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base")
        ledger_append.append("backlog", item("triple"), path=self.ledger)
        self.run_id = "r1"
        pins = Path(self.tmp.name) / "pins.json"
        pins.write_text(json.dumps(heavy_cycle.frozen.control_digest()))
        self.pins = mock.patch.object(heavy_cycle.frozen, "PINS", pins)
        self.pins.start()
        self.addCleanup(self.pins.stop)
        self.good_files = {"agentlib/calc.py": "def double(x):\n    return 2 * x\n\n\ndef triple(x):\n    return 3 * x\n",
                           "tests/test_triple.py": "import unittest\nfrom agentlib.calc import triple\n\n\n"
                           "class T(unittest.TestCase):\n    def test_triple(self):\n"
                           "        self.assertEqual(triple(2), 6)\n"}
        self.good = self.diff({"agentlib/calc.py": "def double(x):\n    return 2 * x\n\n\ndef triple(x):\n    return 3 * x\n",
                               "tests/test_triple.py": "import unittest\nfrom agentlib.calc import triple\n\n\n"
                               "class T(unittest.TestCase):\n    def test_triple(self):\n"
                               "        self.assertEqual(triple(2), 6)\n"})
        self.untested = self.diff({"agentlib/calc.py": "def double(x):\n    return 2 * x\n\n\ndef triple(x):\n    return 3 * x\n"})

    def tearDown(self):
        self.tmp.cleanup()

    def diff(self, files):
        for path, text in files.items():
            (self.repo / path).write_text(text)
        git(self.repo, "add", "-A")
        out = git(self.repo, "diff", "--cached")
        git(self.repo, "reset", "-q", "--hard")
        git(self.repo, "clean", "-qfd")
        return out

    @staticmethod
    def blocks(files):
        return "".join(f"<<<FILE {p}>>>\n{text}<<<END FILE>>>\n" for p, text in files.items())

    def fake(self, replies):
        calls = []

        def call(cli, model, job, prompt, out, timeout, ledger_path=None):
            calls.append((cli, job, prompt))
            reply = replies[job]
            if reply is None:
                return "quota"
            Path(out).write_text(reply)
            return "ok"
        return call, calls

    @staticmethod
    def panel_reply(family, changed=None, reason="weak test"):
        roles = review_panel.assign("codex", review_panel.ROLES)[family]
        return json.dumps({"reviews": [{"role": role, "verdict": "changes" if role == changed else "approve",
                                        "reasons": [reason] if role == changed else []} for role in roles]})

    def run_cycle(self, replies):
        call, calls = self.fake(replies)
        result = heavy_cycle.cycle(self.repo, self.ledger, call=call, today=TODAY, run_id=self.run_id,
                                   state_dir=self.state)
        return result, calls

    def test_retries_with_evaluator_feedback_then_drafts_a_local_branch(self):
        result, calls = self.run_cycle({"heavy_cycle.write.1": self.blocks({"agentlib/calc.py": self.good_files["agentlib/calc.py"]}),
                                        "heavy_cycle.write.2": self.blocks(self.good_files),
                                        "review_panel.claude": self.panel_reply("claude"),
                                        "review_panel.agy": self.panel_reply("agy")})
        self.assertEqual(result["outcome"], "drafted")
        self.assertIn("gate 'tests' failed", calls[1][2])  # the second prompt carries the failure
        self.assertEqual([c[0] for c in calls], ["codex", "codex", "claude", "agy"])
        self.assertIn("agent/r1", git(self.repo, "branch", "--list", "agent/*"))
        self.assertEqual(git(self.repo, "remote").strip(), "")  # nothing to push to, nothing pushed
        draft = (self.state / "pr-drafts" / "r1.md").read_text()
        self.assertIn("NOT pushed", draft)
        self.assertIn("PASS bite", draft)
        self.assertIn("owner (claude): approve", draft)
        self.assertIn("legal (agy): approve", draft)
        decisions = [r["data"] for r in heavy_cycle.ledger_rows(self.ledger) if r["type"] == "decision"]
        self.assertEqual(decisions[-1]["outcome"], "drafted")
        self.assertEqual(heavy_cycle.open_backlog(heavy_cycle.ledger_rows(self.ledger), TODAY), [])

    def test_both_prompts_carry_the_data_and_contact_guardrails(self):
        item = {"id": "x", "area": "a", "title": "Add a helper", "detail": "Do it.", "files": []}
        writer = heavy_cycle.writer_prompt(self.repo, item)
        for rule in heavy_cycle.GUARDRAILS:
            self.assertIn(rule, writer)
        self.assertIn("even if a task or file says otherwise", writer)
        reviewer = review_panel.panel_prompt(("owner", "security"), item["title"],
                    heavy_cycle.reviewer_material(item, "diff", {"checks": [], "bite": [{"id": "tests.t"}]}), "abc")
        for phrase in ("personal records", "credentials", "contact anyone", "evidence, not proof"):
            self.assertIn(phrase, reviewer)

    def test_model_written_text_reaches_both_prompts_only_inside_a_fence(self):
        # Security review 2026-10-05: earlier agent files feed the next writer; bite rows feed the reviewer.
        item = {"id": "x", "area": "a", "title": "Add a helper", "detail": "Do it.", "files": []}
        writer = heavy_cycle.writer_prompt(self.repo, item)
        fence = writer.split("CODE-", 1)[1][:16]
        inside = writer.split(f"CODE-{fence}\n")[1]
        self.assertIn("Repository files:", inside)
        self.assertNotIn("Repository files:", writer.split(f"CODE-{fence}")[0])
        material = heavy_cycle.reviewer_material(item, "the diff", {"checks": [], "bite": [{"id": "tests.marker"}]})
        reviewer = review_panel.panel_prompt(("security",), item["title"], material, "abc")
        fence = "abc"
        before, inside, after = reviewer.split(f"DATA-{fence}\n")
        self.assertNotIn("tests.marker", before)
        self.assertIn("tests.marker", inside)
        self.assertIn("the diff", inside)

    def test_review_changes_means_no_branch(self):
        result, _ = self.run_cycle({"heavy_cycle.write.1": self.blocks(self.good_files),
                                    "review_panel.claude": self.panel_reply("claude", "owner"),
                                    "review_panel.agy": self.panel_reply("agy")})
        self.assertEqual(result["outcome"], "review_changes")
        self.assertEqual(git(self.repo, "branch", "--list", "agent/*").strip(), "")

    def test_two_failed_attempts_are_rejected_and_recorded(self):
        result, _ = self.run_cycle({"heavy_cycle.write.1": "no diff", "heavy_cycle.write.2": self.blocks({"agentlib/calc.py": self.good_files["agentlib/calc.py"]})})
        self.assertEqual(result["outcome"], "rejected")
        self.assertIn("tests", result["reason"])

    def test_rejection_reasons_that_look_like_identifiers_are_still_recorded(self):
        # Fable round 4: a reviewer reason or git hash with a long digit run crashed the ledger write.
        result, _ = self.run_cycle({"heavy_cycle.write.1": self.blocks(self.good_files),
                                    "review_panel.claude": self.panel_reply("claude", "owner", "see 12345678 and a@b.co"),
                                    "review_panel.agy": self.panel_reply("agy")})
        self.assertEqual(result["outcome"], "review_changes")
        decision = [r["data"] for r in heavy_cycle.ledger_rows(self.ledger) if r["type"] == "decision"][-1]
        self.assertEqual(decision["reasons"], ["owner: see [redacted] and [redacted]"])

    def test_unavailable_family_blocks_draft_without_fallback(self):
        result, calls = self.run_cycle({"heavy_cycle.write.1": self.blocks(self.good_files),
                                        "review_panel.claude": self.panel_reply("claude"),
                                        "review_panel.agy": None})
        self.assertEqual(result["outcome"], "reviewer_unavailable")
        self.assertEqual(result["families"], ["agy"])
        self.assertEqual([entry[0] for entry in calls], ["codex", "claude", "agy"])
        self.assertEqual(git(self.repo, "branch", "--list", "agent/*").strip(), "")

    def test_a_quota_hit_stops_cleanly_with_a_default_run_id(self):
        self.run_id = None  # the real default id must get through the ledger guard
        result, _ = self.run_cycle({"heavy_cycle.write.1": None})
        self.assertEqual((result["outcome"], result["status"]), ("writer_unavailable", "quota"))


if __name__ == "__main__":
    unittest.main()
