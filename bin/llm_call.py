#!/usr/bin/env python3
"""llm-call — the one way the agent runs a model.

    llm_call.py --cli codex|claude|agy --model M --job NAME --prompt-file P --out O [--timeout S]

What it guarantees:
- Hardened invocation: no user config, no plugins/connectors, no MCP servers, no tools
  for claude, read-only sandbox for codex. A model run cannot send email or post anywhere.
- Every run is CLASSIFIED: ok | quota | timeout | error | empty. Each CLI fails differently:
  codex exits 1 with "usage limit"; agy can exit 0 with no output; `claude -p` can exit 0
  with is_error:true. A quota hit puts that CLI in a 24h cooldown.
- Every run is logged to the single-writer ledger (type llm_run) with tokens when the CLI
  reports them, wall-clock seconds and the prompt's hash. Never the prompt text itself.
- A weekly per-CLI token cap and a per-run wall-clock deadline are enforced.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import shutil
import stat
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger_append  # noqa: E402

STATE = os.environ.get("AGENT_STATE", str(Path(__file__).resolve().parent.parent / "state"))
COOLDOWNS = os.path.join(STATE, "cooldowns.json")
WEEKLY_TOKEN_CAP = {"codex": 3_000_000, "claude": 1_500_000, "agy": 1_000_000}  # per ISO week
QUOTA_MARKERS = ("usage limit", "rate limit", "quota", "too many requests", "429", "limit reached")


WRITER_PROFILE = Path(__file__).resolve().parent / "writer.sb"
REVIEWER_PROFILE = Path(__file__).resolve().parent / "reviewer.sb"


def _binary(cli):
    """The CLI the caller would run, resolved BEFORE the environment is scrubbed: several
    installs can coexist (an old Homebrew claude 2.1.114 beside the current nvm 2.1.287)."""
    found = shutil.which(cli)
    if not found:
        raise FileNotFoundError(f"{cli} is not on PATH")
    return os.path.realpath(found)


CLAUDE_TOKEN = Path.home() / ".config/supervised-agent/claude-oauth-token"


def _claude_token():
    """The reviewer's sign-in for background runs (from `claude setup-token`), which have no
    keychain session. Used only from a regular file private to this account; otherwise the CLI
    falls back to its own keychain login."""
    try:
        fd = os.open(CLAUDE_TOKEN, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            return None
        return os.read(fd, 4096).decode().strip() or None
    finally:
        os.close(fd)


def build_command(cli, model, prompt, out_path, empty_mcp, work=None):
    if cli == "codex":
        # codex's "read-only" sandbox still lets its tools read every file, so the CLI itself
        # runs under bin/writer.sb: its API, its own ~/.codex login, an empty work folder.
        binary = _binary("codex")
        home = os.path.expanduser("~")
        return ["/usr/bin/sandbox-exec", "-f", str(WRITER_PROFILE), "-D", f"HOME_DIR={home}",
                "-D", f"CODEX_HOME={home}/.codex", "-D", f"WORK={work}", "-D", f"CLI={binary}",
                # Its login lives in ~/.codex/auth.json, never the keychain: a background run
                # (launchd, sudo) has no keychain session.
                binary, "exec", "--ignore-user-config", "-c", "cli_auth_credentials_store=file",
                "--ephemeral", "--skip-git-repo-check",
                "-s", "read-only", "-m", model, "-o", out_path, prompt]
    if cli == "claude":
        # The prompt goes on stdin: claude's variadic flags (--tools, --disallowedTools,
        # --mcp-config) would otherwise swallow a trailing prompt argument.
        # It has no tools, and also runs under bin/reviewer.sb: should a tool ever slip through,
        # it still sees only its own install, its own ~/.claude login and an empty work folder.
        binary = _binary("claude")
        home = os.path.expanduser("~")
        return ["/usr/bin/sandbox-exec", "-f", str(REVIEWER_PROFILE), "-D", f"HOME_DIR={home}",
                "-D", f"CLAUDE_DIR={home}/.claude", "-D", f"CLAUDE_JSON=^{re.escape(home)}/\\.claude\\.json",
                "-D", f"CLI_DIR={os.path.dirname(os.path.dirname(binary))}", "-D", f"WORK={work}",
                "-D", f"CLI={binary}",
                binary, "-p", "--model", model, "--output-format", "json",
                "--strict-mcp-config", "--mcp-config", empty_mcp, "--setting-sources", "project",
                "--tools", "", "--disallowedTools", "mcp__*"]
    if cli == "agy":
        return ["agy", "--print", prompt]
    raise ValueError(f"unknown cli: {cli}")


def classify(cli, returncode, stdout, stderr, out_text, timed_out):
    """Returns (status, text, tokens)."""
    if timed_out:
        return "timeout", "", None
    blob = (stdout + "\n" + stderr).lower()
    tokens = None
    text = out_text if cli == "codex" else stdout
    if cli == "claude":
        try:
            payload = json.loads(stdout)
            if payload.get("is_error"):
                status = "quota" if any(m in json.dumps(payload).lower() for m in QUOTA_MARKERS) else "error"
                return status, "", None
            text = payload.get("result") or ""
            usage = payload.get("usage") or {}
            tokens = sum(int(usage.get(k) or 0) for k in
                         ("input_tokens", "output_tokens", "cache_creation_input_tokens",
                          "cache_read_input_tokens")) or None
        except (ValueError, TypeError):
            return "error", "", None
    if returncode != 0:
        return ("quota" if any(m in blob for m in QUOTA_MARKERS) else "error"), "", tokens
    if not text.strip():
        return "empty", "", tokens
    if cli == "codex":
        # codex prints "tokens used" then the count, on the same line or the next one.
        lines = stderr.splitlines()
        for index, line in enumerate(lines):
            if "tokens used" in line.lower():
                for candidate in (line.lower().split("tokens used", 1)[1], *lines[index + 1:index + 2]):
                    digits = "".join(ch for ch in candidate if ch.isdigit())
                    if digits:
                        tokens = int(digits)
                        break
    return "ok", text, tokens


MAX_OUTPUT_BYTES = 400_000


def _bounded_read(path):
    """The writer's reply file: a regular file only (never a symlink), at most MAX_OUTPUT_BYTES."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)  # a FIFO must not block
    except OSError:
        return ""
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return ""
        return os.read(fd, MAX_OUTPUT_BYTES + 1)[:MAX_OUTPUT_BYTES].decode("utf-8", "replace")
    finally:
        os.close(fd)


def _load(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def week_tokens(cli, ledger_path):
    """Tokens this ISO week for one CLI, summed from the ledger."""
    if not os.path.exists(ledger_path):
        return 0
    week = dt.date.today().isocalendar()[:2]
    total = 0
    with open(ledger_path) as fh:
        for line in fh:
            row = json.loads(line)
            if row.get("type") != "llm_run" or row["data"].get("cli") != cli:
                continue
            if dt.date.fromisoformat(row["ts"][:10]).isocalendar()[:2] == week:
                total += int(row["data"].get("tokens") or 0)
    return total


def run(cli, model, job, prompt, out_path, timeout, ledger_path=None, now=time.time, runner=subprocess.run):
    ledger_path = ledger_path or ledger_append.LEDGER
    os.makedirs(STATE, exist_ok=True)
    cooldowns = _load(COOLDOWNS, {})
    if cooldowns.get(cli, 0) > now():
        status, text, tokens, seconds = "cooldown", "", None, 0.0
    elif week_tokens(cli, ledger_path) >= WEEKLY_TOKEN_CAP[cli]:
        status, text, tokens, seconds = "budget", "", None, 0.0
    else:
        with tempfile.TemporaryDirectory() as tmp:
            # The real path first: the sandbox profiles allow WORK by it, and /tmp (agentbot's
            # temp folder under sudo/launchd) is a symlink to /private/tmp.
            tmp = os.path.realpath(tmp)
            empty_mcp = os.path.join(tmp, "empty-mcp.json")
            with open(empty_mcp, "w") as fh:
                json.dump({"mcpServers": {}}, fh)
            codex_out = os.path.join(tmp, "last.txt")
            cmd = build_command(cli, model, prompt, codex_out, empty_mcp, work=tmp)
            # A scrubbed environment: no inherited tokens or keys reach any model CLI.
            # USER/LOGNAME let the CLI find its own login in the keychain; the CLI's own folder
            # comes first on PATH so a node-based install finds its node.
            cli_dir = os.path.dirname(_binary(cli))
            env = {"PATH": f"{cli_dir}:/usr/bin:/bin:/opt/homebrew/bin", "HOME": os.path.expanduser("~"),
                   "LANG": "en_US.UTF-8", "TERM": "dumb", "USER": os.environ.get("USER", ""),
                   "LOGNAME": os.environ.get("LOGNAME", "")}
            if cli == "claude":
                env["CLAUDE_CODE_TMPDIR"] = tmp  # bin/reviewer.sb allows no other temp folder
                token = _claude_token()
                if token:
                    env["CLAUDE_CODE_OAUTH_TOKEN"] = token
            started = now()
            timed_out = False
            try:
                if cli == "claude":
                    proc = runner(cmd, input=prompt, capture_output=True, text=True, timeout=timeout,
                                  cwd=tmp, env=env)
                else:
                    proc = runner(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                  timeout=timeout, cwd=tmp, env=env)
                rc, out, err = proc.returncode, proc.stdout or "", proc.stderr or ""
            except subprocess.TimeoutExpired:
                rc, out, err, timed_out = -1, "", "", True
            seconds = round(now() - started, 1)
            out_text = _bounded_read(codex_out)
            status, text, tokens = classify(cli, rc, out, err, out_text, timed_out)
        if status == "quota":
            cooldowns[cli] = now() + 24 * 3600
            with open(COOLDOWNS, "w") as fh:
                json.dump(cooldowns, fh)
    if text:
        with open(out_path, "w") as fh:
            fh.write(text)
    ledger_append.append("llm_run", {
        "cli": cli, "model": model, "job": job, "status": status, "tokens": tokens, "seconds": seconds,
        # Grouped so a hash never contains the 7+ digit run the ledger refuses (318 of 2,000 did).
        "prompt_sha256": "-".join(hashlib.sha256(prompt.encode()).hexdigest()[i:i + 4] for i in (0, 4, 8, 12))},
        path=ledger_path)
    return status


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--cli", required=True, choices=("codex", "claude", "agy"))
    ap.add_argument("--model", required=True)
    ap.add_argument("--job", required=True)
    ap.add_argument("--prompt-file", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=int, default=1800)
    a = ap.parse_args(argv)
    prompt = open(a.prompt_file).read()
    status = run(a.cli, a.model, a.job, prompt, a.out, a.timeout)
    print(status)
    return 0 if status == "ok" else 3


if __name__ == "__main__":
    sys.exit(main())
