"""Tests for the agent's local tools: ledger chain and llm-call classification and hardening."""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

BIN = Path(__file__).resolve().parent.parent / "bin"
sys.path.insert(0, str(BIN))
import ledger_append  # noqa: E402
import llm_call  # noqa: E402

# The evaluator's sandbox bans new processes; these human tests spawn them, so they
# run in every human test run and skip only there. Agent changes cannot add skips.
NEEDS_PROCESSES = unittest.skipIf(os.environ.get("AGENT_SANDBOXED"), "needs processes; runs outside the sandbox")


class Ledger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "ledger.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def test_chain_verifies_and_detects_edits_and_removals(self):
        for i in range(3):
            ledger_append.append("claim", {"id": f"c{i}"}, path=self.path)
        self.assertTrue(ledger_append.verify(self.path)[0])
        lines = Path(self.path).read_text().splitlines()
        edited = json.loads(lines[1]); edited["data"]["id"] = "tampered"
        Path(self.path).write_text("\n".join([lines[0], json.dumps(edited), lines[2]]) + "\n")
        self.assertFalse(ledger_append.verify(self.path)[0])
        Path(self.path).write_text("\n".join([lines[0], lines[2]]) + "\n")
        ok, message = ledger_append.verify(self.path)
        self.assertFalse(ok)
        self.assertIn("sequence", message)

    def test_rejects_raw_identifiers_and_unknown_types(self):
        with self.assertRaises(ValueError):
            ledger_append.append("claim", {"who": "someone@example.com"}, path=self.path)
        with self.assertRaises(ValueError):
            ledger_append.append("claim", {"client": "100004494"}, path=self.path)
        with self.assertRaises(ValueError):
            ledger_append.append("free_text", {}, path=self.path)

    @NEEDS_PROCESSES
    def test_concurrent_writers_never_fork_the_chain(self):
        script = ("import sys; sys.path.insert(0, %r); import ledger_append as l\n"
                  "for i in range(25): l.append('run', {'i': i}, path=%r)") % (str(BIN), self.path)
        procs = [subprocess.Popen([sys.executable, "-c", script]) for _ in range(4)]
        for p in procs:
            self.assertEqual(p.wait(), 0)
        ok, message = ledger_append.verify(self.path)
        self.assertTrue(ok, message)
        self.assertIn("100 rows", message)


class Classify(unittest.TestCase):
    def test_codex_quota_exit_1(self):
        self.assertEqual(llm_call.classify("codex", 1, "", "You've hit your usage limit", "", False)[0], "quota")

    def test_agy_exit_0_with_no_output_is_empty(self):
        self.assertEqual(llm_call.classify("agy", 0, "", "", "", False)[0], "empty")

    def test_claude_exit_0_with_is_error(self):
        self.assertEqual(llm_call.classify("claude", 0, json.dumps({"is_error": True, "result": "x"}), "", "", False)[0], "error")
        self.assertEqual(llm_call.classify("claude", 0, json.dumps({"is_error": True, "result": "Usage limit reached"}), "", "", False)[0], "quota")

    def test_claude_ok_counts_tokens(self):
        status, text, tokens = llm_call.classify("claude", 0, json.dumps(
            {"is_error": False, "result": "answer", "usage": {"input_tokens": 10, "output_tokens": 5}}), "", "", False)
        self.assertEqual((status, text, tokens), ("ok", "answer", 15))

    def test_timeout(self):
        self.assertEqual(llm_call.classify("codex", -1, "", "", "", True)[0], "timeout")


def private_state(test_case, directory):
    """Point llm_call's state at a test folder and put it back afterwards. llm_call reads
    its paths at import time, so setting AGENT_STATE alone leaked a fake codex quota
    cooldown into the real agent state (the first full suite run after it was added)."""
    for name, value in (("STATE", directory), ("COOLDOWNS", os.path.join(directory, "cooldowns.json"))):
        patcher = unittest.mock.patch.object(llm_call, name, value)
        patcher.start()
        test_case.addCleanup(patcher.stop)


def fake_binaries(test_case):
    """Command construction is tested against fixed paths: the evaluator's sandbox has no
    codex or claude on PATH, and the test must not depend on what is installed."""
    patcher = unittest.mock.patch.object(llm_call, "_binary", lambda cli: f"/opt/fake/{cli}")
    patcher.start()
    test_case.addCleanup(patcher.stop)


class Hardening(unittest.TestCase):
    def setUp(self):
        fake_binaries(self)

    def test_commands_disable_user_config_plugins_and_tools(self):
        codex = llm_call.build_command("codex", "m", "p", "/o", "/e.json", work="/w")
        # codex's own tools can read any file in "read-only" mode, so the CLI itself runs in
        # bin/writer.sb: network and ~/.codex only, an empty work folder, no other programs.
        self.assertEqual(codex[:3], ["/usr/bin/sandbox-exec", "-f", str(llm_call.WRITER_PROFILE)])
        self.assertIn("WORK=/w", codex)
        self.assertIn("--ignore-user-config", codex)
        self.assertIn("--ephemeral", codex)
        self.assertEqual(codex[codex.index("-s") + 1], "read-only")
        self.assertEqual(codex[codex.index("-c") + 1], "cli_auth_credentials_store=file")
        claude = llm_call.build_command("claude", "m", "p", "/o", "/e.json")
        for flag in ("--strict-mcp-config", "--setting-sources", "--tools", "--disallowedTools"):
            self.assertIn(flag, claude)
        self.assertEqual(claude[claude.index("--tools") + 1], "")
        self.assertEqual(claude[claude.index("--setting-sources") + 1], "project")
        self.assertNotIn("p", claude)  # prompt travels on stdin, never after a variadic flag
        # And, should a tool ever slip through, the reviewer CLI runs in bin/reviewer.sb.
        self.assertEqual(claude[:3], ["/usr/bin/sandbox-exec", "-f", str(llm_call.REVIEWER_PROFILE)])


@unittest.skipIf(os.environ.get("AGENT_SANDBOXED"), "sandbox-exec cannot nest")
class ReviewerSandbox(unittest.TestCase):
    """bin/reviewer.sb, probed with /bin/cat standing in for the claude CLI."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.work = os.path.realpath(self.tmp.name)
        self.home = os.path.expanduser("~")
        with open(os.path.join(self.work, "f"), "w") as fh:
            fh.write("ok")

    def tearDown(self):
        self.tmp.cleanup()

    def run_in_profile(self, *command):
        home = self.home
        return subprocess.run(
            ["/usr/bin/sandbox-exec", "-f", str(llm_call.REVIEWER_PROFILE), "-D", f"HOME_DIR={home}",
             "-D", f"CLAUDE_DIR={home}/.claude", "-D", f"CLAUDE_JSON=^{re.escape(home)}/\\.claude\\.json",
             "-D", "CLI_DIR=/nonexistent", "-D", f"WORK={self.work}", "-D", "CLI=/bin/cat", *command],
            capture_output=True, timeout=20).returncode

    def test_it_reads_its_work_folder_and_nothing_else_of_the_users(self):
        self.assertEqual(self.run_in_profile("/bin/cat", os.path.join(self.work, "f")), 0)
        for path in (llm_call.__file__, os.path.join(self.home, ".codex"), os.path.join(self.home, ".ssh"),
                     os.path.join(self.home, ".cache"), "/private/tmp", "/Volumes"):
            with self.subTest(path=path):
                self.assertNotEqual(self.run_in_profile("/bin/cat", path), 0)

    def test_it_cannot_start_other_programs_or_write_outside_its_folders(self):
        self.assertNotEqual(self.run_in_profile("/bin/ls", "/"), 0)
        target = os.path.join(self.home, "reviewer-sandbox-probe")
        self.assertNotEqual(subprocess.run(
            ["/usr/bin/sandbox-exec", "-f", str(llm_call.REVIEWER_PROFILE), "-D", f"HOME_DIR={self.home}",
             "-D", f"CLAUDE_DIR={self.home}/.claude", "-D", "CLAUDE_JSON=^$", "-D", "CLI_DIR=/nonexistent",
             "-D", f"WORK={self.work}", "-D", "CLI=/usr/bin/touch", "/usr/bin/touch", target],
            capture_output=True, timeout=20).returncode, 0)
        self.assertFalse(os.path.exists(target))


class RunAndBudget(unittest.TestCase):
    def setUp(self):
        fake_binaries(self)
        self.tmp = tempfile.TemporaryDirectory()
        private_state(self, self.tmp.name)
        llm_call.STATE = self.tmp.name
        self.ledger = os.path.join(self.tmp.name, "ledger.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def fake(self, rc, out="", err=""):
        def runner(cmd, **kw):
            return subprocess.CompletedProcess(cmd, rc, out, err)
        return runner

    def test_quota_sets_cooldown_and_next_call_is_skipped(self):
        out = os.path.join(self.tmp.name, "o.txt")
        s1 = llm_call.run("codex", "m", "j", "p", out, 10, ledger_path=self.ledger,
                          runner=self.fake(1, err="usage limit"))
        s2 = llm_call.run("codex", "m", "j", "p", out, 10, ledger_path=self.ledger,
                          runner=self.fake(0, out="should not run"))
        self.assertEqual((s1, s2), ("quota", "cooldown"))
        rows = [json.loads(l) for l in open(self.ledger)]
        self.assertEqual([r["data"]["status"] for r in rows], ["quota", "cooldown"])
        self.assertNotIn("p", [r["data"].get("prompt") for r in rows])

    def test_weekly_token_cap_blocks_runs(self):
        ledger_append.append("llm_run", {"cli": "agy", "tokens": llm_call.WEEKLY_TOKEN_CAP["agy"]}, path=self.ledger)
        status = llm_call.run("agy", "m", "j", "p", os.path.join(self.tmp.name, "o"), 10,
                              ledger_path=self.ledger, runner=self.fake(0, out="x"))
        self.assertEqual(status, "budget")


class ClaudeToken(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "claude-oauth-token"
        patcher = unittest.mock.patch.object(llm_call, "CLAUDE_TOKEN", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def test_a_private_token_file_is_used_and_anything_else_is_not(self):
        self.assertIsNone(llm_call._claude_token())
        self.path.write_text("tok-123\n")
        self.path.chmod(0o600)
        self.assertEqual(llm_call._claude_token(), "tok-123")
        self.path.chmod(0o644)
        self.assertIsNone(llm_call._claude_token())
        self.path.chmod(0o600)
        link = Path(self.tmp.name) / "link"
        link.symlink_to(self.path)
        with unittest.mock.patch.object(llm_call, "CLAUDE_TOKEN", link):
            self.assertIsNone(llm_call._claude_token())


@unittest.skipIf(os.environ.get("AGENT_SANDBOXED"), "needs a writable /tmp, which the sandbox denies")
class RealPaths(unittest.TestCase):
    def test_every_path_given_to_the_cli_is_a_real_path_even_under_a_symlinked_tmp(self):
        # A background agent user's temp folder is /tmp, a symlink to /private/tmp; the sandbox matches real paths.
        fake_binaries(self)
        seen = {}

        def runner(cmd, **kw):
            seen["cmd"], seen["cwd"] = cmd, kw["cwd"]
            return subprocess.CompletedProcess(cmd, 0, stdout='{"result": "x"}', stderr="")
        with tempfile.TemporaryDirectory() as state:
            private_state(self, state)
            with unittest.mock.patch.dict(os.environ, {"TMPDIR": "/tmp"}), \
                    unittest.mock.patch.object(tempfile, "tempdir", None):
                llm_call.run("claude", "m", "j", "p", os.path.join(state, "o"), 5,
                             ledger_path=os.path.join(state, "l.jsonl"), runner=runner)
        mcp = seen["cmd"][seen["cmd"].index("--mcp-config") + 1]
        self.assertTrue(mcp.startswith("/private/tmp/"), mcp)
        self.assertTrue(seen["cwd"].startswith("/private/tmp/"), seen["cwd"])


@NEEDS_PROCESSES  # shutil.which checks execute permission, which the sandbox refuses
class ResolvedBinaries(unittest.TestCase):
    def test_clis_are_resolved_before_the_environment_is_scrubbed(self):
        # The first real review call ran an old Homebrew claude from the scrubbed PATH
        # ("Not logged in", then "version too old"); the CLI is now resolved up front.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            fake = Path(tmp) / "claude"
            fake.write_text("#!/bin/sh\n")
            fake.chmod(0o755)
            with unittest.mock.patch.dict(os.environ, {"PATH": f"{tmp}:/usr/bin:/bin"}):
                command = llm_call.build_command("claude", "m", "p", "/o", "/e")
                # sandbox-exec starts it, and the profile may start only that resolved binary
                self.assertEqual(command[command.index("-p") - 1], os.path.realpath(fake))
                self.assertIn(f"CLI={os.path.realpath(fake)}", command)


class TestsNeverTouchRealState(unittest.TestCase):
    def test_a_test_quota_hit_leaves_the_real_cooldown_file_alone(self):
        real = llm_call.COOLDOWNS
        before = Path(real).read_bytes() if os.path.exists(real) else None
        fake_binaries(self)
        with tempfile.TemporaryDirectory() as tmp:
            private_state(self, tmp)
            llm_call.run("codex", "m", "j", "p", os.path.join(tmp, "o"), 5, ledger_path=os.path.join(tmp, "l"),
                         runner=lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "usage limit"))
        self.assertEqual(Path(real).read_bytes() if os.path.exists(real) else None, before)


class LedgerSafeHashes(unittest.TestCase):
    def test_prompt_hashes_never_trip_the_identifier_guard(self):
        fake_binaries(self)
        with tempfile.TemporaryDirectory() as tmp:
            private_state(self, tmp)
            ledger = os.path.join(tmp, "l.jsonl")
            for i in range(300):  # codex round 5: 318 of 2,000 raw hashes did
                llm_call.run("codex", "m", "j", f"prompt {i}", os.path.join(tmp, "o"), 5, ledger_path=ledger,
                             runner=lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "usage limit"))
            self.assertTrue(ledger_append.verify(ledger)[0])


class BoundedOutput(unittest.TestCase):
    def test_the_writer_reply_is_never_read_through_a_symlink_and_is_capped(self):
        with tempfile.TemporaryDirectory() as tmp:
            secret, link, big = Path(tmp) / "secret", Path(tmp) / "last.txt", Path(tmp) / "big.txt"
            secret.write_text("secret")
            link.symlink_to(secret)
            self.assertEqual(llm_call._bounded_read(str(link)), "")
            big.write_text("x" * (llm_call.MAX_OUTPUT_BYTES + 10))
            self.assertEqual(len(llm_call._bounded_read(str(big))), llm_call.MAX_OUTPUT_BYTES)


class CodexTokens(unittest.TestCase):
    def test_tokens_on_the_line_after_the_label_are_counted(self):
        # Real codex 0.160 stderr: the count sits on the next line, with a thousands comma.
        # Missing it left every codex run at tokens=None, so the weekly cap never saw codex.
        status, _, tokens = llm_call.classify("codex", 0, "", "work...\ntokens used\n41,768\n", "a diff", False)
        self.assertEqual((status, tokens), ("ok", 41768))

    def test_tokens_on_the_same_line_still_count(self):
        _, _, tokens = llm_call.classify("codex", 0, "", "tokens used: 1,234\n", "a diff", False)
        self.assertEqual(tokens, 1234)


if __name__ == "__main__":
    unittest.main()
