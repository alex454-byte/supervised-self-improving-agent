#!/usr/bin/env python3
"""The frozen evaluator: decides whether one agent-proposed change passes.

Trust root. The expected sha256 of every control file (this file, runner.py,
sandbox.sb, and the agent's launcher and helpers in bin/) lives OUTSIDE the repo,
in /opt/supervised-agent/pins.json, written only by `--pin` (a human step, run as
the operator). The agent account (agentbot) must be unable to change them: the pins and their
folder must not be its own or writable by it, nor writable by group or others, nor symlinks.
The launcher checks the pins before importing anything; this module checks them again.
A change may touch only agentlib/, tests/ and docs/, so it can never reach a pin.

Gates, in order; the first failure stops the run, and nothing from the change is
executed until every static gate has passed:

  integrity    control files match the external pins
  shape        no renames, copies, deletions, mode changes, symlinks, submodules or binary patches
  paths        only agentlib/, tests/, docs/; plain names; .py/.md/.txt; never .gitattributes
  size         <= 300 changed lines and <= 8 files (counted by git, not by parsing the text)
  deps         no dependency or packaging files
  identifiers  no emails or long digit runs in any changed file (whole resulting files)
  code         every changed .py file, parsed whole: imports only from a small pure-computation
               standard-library list or agentlib; no file, process, network, reflection or
               dynamic-execution names; no test skipping; no load_tests
  tests        the change carries at least one tests/test_*.py file
  applies      the patch applies to a clean private clone of the base commit
  baseline     the unmodified base suite runs completely in the sandbox (records the inventory)
  suite        on the candidate every base test still passes, every new test passes, nothing new is skipped
  bite         every NEW test id (absent from the base suite) fails on the base code for a
               behavioural reason: an assertion failure, a built-in runtime error inside the
               test, or an import of exactly a module or name this change adds; never a
               timeout, a killed or unfinished run, a syntax error, an unknown exception
               class, or an import of something the change does not add

Isolation. Git runs on private clones with hooks, attribute filters, fsmonitor,
signing, symlinks and every global/system git config switched off. Model-written
code runs only via evaluator/runner.py under evaluator/sandbox.sb: no network, no
macOS service lookups or POSIX IPC, no new processes, no reading, listing or stat
of home, temp or shared user folders except this run's read-only .git-free source
snapshot and harness, and writes only to a per-run scratch folder. The harness
reports through an inherited file descriptor, not a writable path. CPU time, file
size and open files are limited by rlimit, resident memory is polled (macOS ignores
RLIMIT_AS), and the whole process group is killed on timeout or over 2 GB. What
reaches a model afterwards is a structured summary (test ids and built-in exception
names), never raw output.
"""
import ast
import builtins
import hashlib
import json
import os
import pwd
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
# A fixed place both accounts can read; no environment override (the agent's environment
# must not be able to point the check at pins it wrote itself).
PINS = Path("/opt/supervised-agent/pins.json")
AGENT_USER = "agentbot"
PINNED_FILES = ("evaluator/evaluate.py", "evaluator/runner.py", "evaluator/sandbox.sb",
                "bin/heavy_cycle.py", "bin/llm_call.py", "bin/ledger_append.py", "bin/writer.sb",
                "bin/reviewer.sb", "bin/review_panel.py")
SANDBOX = HERE / "sandbox.sb"
RUNNER = HERE / "runner.py"

ALLOWED = ("agentlib/", "tests/", "docs/")
# The gate's own tests are protected too: a change could otherwise gut the sandbox probes,
# which skip inside the sandbox and so would never be missed by the suite gate (Fable round 4).
FORBIDDEN = ("tests/golden/", "tests/test_evaluator.py", "tests/test_heavy_cycle.py", "tests/test_tools.py",
             "tests/test_ledger_backup.py", "tests/__init__.py")
MAX_PATH_CHARS = 120
# Lower case only: APFS is case-insensitive, so tests/GOLDEN/x would otherwise slip past
# the tests/golden/ rule while writing to the very same folder (Fable round 2).
SAFE_PATH = re.compile(r"^[a-z0-9_][a-z0-9_./-]*\.(py|md|txt)$")
MAX_LINE_CHARS = 400
SHAPE_MARKERS = ("rename from", "rename to", "copy from", "copy to", "old mode", "new mode",
                 "deleted file mode", "similarity index", "dissimilarity index", "GIT binary patch",
                 "Binary files")
DEPENDENCY_FILES = re.compile(r"(^|/)(requirements[^/]*\.txt|pyproject\.toml|setup\.(py|cfg)|Pipfile[^/]*|"
                              r"package(-lock)?\.json|poetry\.lock|uv\.lock)$")
IDENTIFIERS = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|\d{7,}")
# No `operator` (attrgetter/methodcaller reach attributes by string), no `inspect`/`types`, and no
# `string`: string.Formatter().get_field("0.<dunder>init<dunder>.<dunder>globals<dunder>", ...) is getattr
# by text, and the dunders can be built at run time (Opus security review, 2026-10-05).
SAFE_MODULES = {"math", "statistics", "fractions", "decimal", "itertools", "functools", "collections",
                "dataclasses", "datetime", "json", "re", "random", "typing", "heapq", "bisect",
                "textwrap", "enum", "abc", "copy", "numbers", "unittest", "agentlib", "tests", "__future__"}
BANNED_NAMES = {"eval", "exec", "compile", "__import__", "open", "input", "breakpoint", "getattr", "setattr",
                "delattr", "globals", "locals", "vars", "memoryview", "__builtins__", "__loader__", "__spec__",
                "__subclasses__", "__globals__", "__code__", "__dict__", "__getattribute__", "__reduce__",
                "__reduce_ex__", "__class__", "__bases__", "__mro__", "skip", "skipIf", "skipUnless",
                "SkipTest", "expectedFailure", "load_tests", "mock", "patch", "type", "format", "format_map",
                "run", "debug", "attrgetter", "methodcaller", "id", "shortDescription"}
# Result-recording calls (a test could report itself passed without running).
BANNED_NAMES |= {"addSuccess", "addFailure", "addError", "addSkip", "addSubTest", "addExpectedFailure",
                 "addUnexpectedSuccess", "startTest", "stopTest", "defaultTestResult",
                 # typing evaluates string annotations (codex/agy round 3)
                 "get_type_hints", "ForwardRef", "evaluate_forward_ref",
                 # frames and code objects reach builtins and globals without underscores (agy round 4)
                 "gi_frame", "cr_frame", "ag_frame", "gi_code", "cr_code", "ag_code", "f_builtins", "f_globals",
                 "f_locals", "f_back", "f_code", "tb_frame", "tb_next", "co_consts", "co_code",
                 # attribute or module lookup by text (Opus security review, 2026-10-05)
                 "Formatter", "get_field", "get_value", "vformat", "TestLoader", "defaultTestLoader",
                 "loadTestsFromName", "loadTestsFromNames", "loadTestsFromModule", "discover"}
# Importing or reaching a standard-library MODULE through an allowed one ("from unittest.case
# import sys") is banned; only the allowlisted modules themselves may be named.
STDLIB_MODULES = set(sys.stdlib_module_names) - SAFE_MODULES
ALLOWED_DUNDER_METHODS = {"__init__", "__repr__", "__str__", "__eq__", "__ne__", "__hash__", "__lt__", "__le__",
                          "__gt__", "__ge__", "__len__", "__iter__", "__contains__", "__post_init__", "__bool__"}
# Assigning to any framework method name, even on self, is refused: aliasing defeats
# name-based checks (codex round 5: `from unittest import TestCase as self`).
FRAMEWORK_ATTRIBUTES = ({name for name in dir(unittest.TestCase) + dir(json) + dir(unittest) if not name.startswith("_")}
                        - {"maxDiff", "longMessage"})
# Private attribute access is banned (it reaches harness internals such as self._outcome);
# super().__init__() is the one dunder attribute pure code needs.
ALLOWED_DUNDER_ATTRIBUTES = {"__init__"}
MAX_LINES, MAX_FILES = 300, 8
TIMEOUT, CPU_SECONDS, MAX_FILE_BYTES = 300, 240, 20 * 1024 * 1024
MAX_RSS_KB = 2 * 1024 * 1024  # macOS ignores RLIMIT_AS, so resident memory is polled instead
MAX_DIFF_BYTES, MAX_RESULT_FILE_BYTES = 256 * 1024, 64 * 1024
GIT_CONFIG = ("-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.symlinks=false",
              "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "core.attributesFile=/dev/null",
              "-c", "protocol.allow=never", "-c", "protocol.file.allow=always")


def control_digest(root=REPO_ROOT):
    return {name: hashlib.sha256((Path(root) / name).read_bytes()).hexdigest() for name in PINNED_FILES}


def pins_trusted(pins=None, user=None):
    """The pins and their folder: not symlinks, not group/other-writable, and, for the agent
    account, neither its own nor writable by it. A folder pre-made by the agent fails this."""
    pins = pins or PINS
    user = user or pwd.getpwuid(os.geteuid()).pw_name
    try:
        for path in (pins.parent, pins):
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode) or st.st_mode & 0o022:
                return False
            if user == AGENT_USER and (st.st_uid == os.geteuid() or os.access(path, os.W_OK)):
                return False
    except OSError:
        return False
    return True


def pins_ok(root=REPO_ROOT):
    try:
        return pins_trusted() and json.loads(PINS.read_text()) == control_digest(root)
    except (OSError, ValueError):
        return False


def write_pins():
    """Human only. Refuses a folder someone else made (the agent could pre-create it)."""
    if pwd.getpwuid(os.geteuid()).pw_name == AGENT_USER:
        raise SystemExit("the agent account cannot pin")
    PINS.parent.mkdir(mode=0o755, exist_ok=True)
    st = os.lstat(PINS.parent)
    if stat.S_ISLNK(st.st_mode) or st.st_uid != os.geteuid():
        raise SystemExit(f"{PINS.parent} is not yours: remove it and pin again")
    os.chmod(PINS.parent, 0o755)
    tmp = PINS.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(control_digest(), indent=2) + "\n")
    os.replace(tmp, PINS)


def git(*args, cwd=None, check=True):
    """Git with no hooks, filters, fsmonitor, signing or symlinks, and no global/system config."""
    env = {"PATH": "/usr/bin:/bin:/opt/homebrew/bin", "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_ATTR_NOSYSTEM": "1",
           "LANG": "C", "GIT_AUTHOR_NAME": "agent", "GIT_AUTHOR_EMAIL": "agent@localhost",
           "GIT_COMMITTER_NAME": "agent", "GIT_COMMITTER_EMAIL": "agent@localhost"}
    return subprocess.run(["git", *GIT_CONFIG, *args], cwd=cwd, env=env, capture_output=True, text=True,
                          check=check, timeout=120)


def _interpreter():
    python = Path(sys.executable).resolve()
    if str(python).startswith("/Users/"):
        raise RuntimeError("the evaluator needs a Python outside /Users (the sandbox cannot read home)")
    app = Path(sys.base_prefix).resolve() / "Resources/Python.app/Contents/MacOS/Python"
    return python, app


def _limits():
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE_BYTES, MAX_FILE_BYTES))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))


SCRATCH_IMAGE_MB = 150


def _rss_kb(pid):
    """Resident memory of the run, or None when it cannot be measured (the caller fails closed)."""
    try:
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True, timeout=5)
        return int(out.stdout.strip()) if out.stdout.strip() else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


class _ScratchDisk:
    """A quota-limited disk image mounted as the run's scratch folder: writes stop at its size
    however they are made (unlinked-but-open files, many tiny files, sparse tricks)."""

    def __init__(self, parent):
        self.image, self.mount = parent / "scratch.sparseimage", parent / "scratch"

    def __enter__(self):
        self.mount.mkdir()
        subprocess.run(["hdiutil", "create", "-quiet", "-size", f"{SCRATCH_IMAGE_MB}m", "-type", "SPARSE",
                        "-fs", "HFS+", "-volname", "agent-scratch", str(self.image.with_suffix(""))],
                       check=True, capture_output=True, timeout=60)
        subprocess.run(["hdiutil", "attach", "-quiet", "-nobrowse", "-noautoopen", "-owners", "on",
                        "-mountpoint", str(self.mount), str(self.image)], check=True, capture_output=True, timeout=60)
        return self.mount

    def __exit__(self, *exc):
        for _ in range(3):
            try:
                done = subprocess.run(["hdiutil", "detach", "-quiet", "-force", str(self.mount)],
                                      capture_output=True, timeout=60)
            except subprocess.TimeoutExpired:
                done = None
            if (done is not None and done.returncode == 0) or not os.path.ismount(self.mount):
                return
            time.sleep(1)
        raise RuntimeError(f"scratch disk still mounted at {self.mount}")


DOTTED = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,80}(\.[A-Za-z_][A-Za-z0-9_]{0,80}){0,7}$")  # as runner.py
REPORTED_EXCEPTIONS = {name for name, value in vars(builtins).items()
                       if isinstance(value, type) and issubclass(value, BaseException)} | {"OtherError"}


def _valid_report(result, max_tests=5000):
    """The report's shape, bounded; anything else is rejected rather than trusted."""
    if not isinstance(result, dict) or result.get("complete") is not True:
        return False
    expected, rows = result.get("expected"), result.get("tests")
    if not (isinstance(expected, list) and isinstance(rows, list) and len(rows) <= max_tests
            and len(expected) <= max_tests and all(isinstance(i, str) and len(i) <= 400 for i in expected)):
        return False
    # These fields reach the reviewer's prompt, so only the shapes runner.py itself emits pass:
    # a report forged from inside the sandbox can't carry free text (Opus security review, 2026-10-05).
    return all(isinstance(r, dict) and set(r) == {"id", "outcome", "exc", "missing"}
               and isinstance(r["id"], str) and (r["id"] == "nonconforming-test-id" or DOTTED.match(r["id"]))
               and r["outcome"] in ("pass", "fail", "error", "skip")
               and (r["exc"] is None or r["exc"] in REPORTED_EXCEPTIONS)
               and (r["missing"] is None or (isinstance(r["missing"], str) and DOTTED.match(r["missing"])))
               for r in rows)


def run_tests(src, files=None):
    """Runs the pinned harness on a read-only, .git-free snapshot. Returns (results or None, reason)."""
    python, app = _interpreter()
    with tempfile.TemporaryDirectory(prefix="agent-run-") as run_dir, \
            tempfile.TemporaryDirectory(prefix="agent-harness-") as harness, \
            tempfile.TemporaryDirectory(prefix="agent-control-") as control:
        run_dir, harness, control = (Path(d).resolve() for d in (run_dir, harness, control))
        (harness / "runner.py").write_bytes(RUNNER.read_bytes())
        disk = _ScratchDisk(run_dir)
        try:
            scratch = disk.__enter__()
        except (OSError, subprocess.SubprocessError):
            if os.path.ismount(disk.mount):
                disk.__exit__(None, None, None)
            return None, "could not create the scratch disk"
        proc = None
        try:
            report = os.open(control / "report.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            cmd = ["sandbox-exec", "-f", str(SANDBOX), "-D", f"SRC={src}", "-D", f"SCRATCH={scratch}",
                   "-D", f"HARNESS={harness}", "-D", f"PYTHON={python}", "-D", f"PYAPP={app}",
                   str(python), "-I", "-B", str(harness / "runner.py"), str(src), str(report), *(files or [])]
            env = {"PATH": "/usr/bin:/bin", "HOME": str(scratch), "TMPDIR": str(scratch), "LANG": "en_US.UTF-8",
                   "AGENT_SANDBOXED": "1"}
            try:
                with open(control / "out", "wb") as log:
                    proc = subprocess.Popen(cmd, cwd=scratch, env=env, stdin=subprocess.DEVNULL, stdout=log,
                                            stderr=subprocess.STDOUT, start_new_session=True,
                                            preexec_fn=_limits, pass_fds=(report,))
            finally:
                os.close(report)
            deadline, why = time.monotonic() + TIMEOUT, ""
            while proc.poll() is None:
                rss = _rss_kb(proc.pid)
                if time.monotonic() > deadline:
                    why = "timed out"
                elif rss is None and proc.poll() is None:
                    why = "memory could not be measured"
                elif rss is not None and rss > MAX_RSS_KB:
                    why = "memory limit"
                if why:
                    break
                time.sleep(0.25)
            if why:
                return None, why
            if proc.returncode < 0:
                return None, f"killed by signal {-proc.returncode}"
            if proc.returncode != 0:
                return None, f"the harness exited {proc.returncode}"
            try:
                result = json.loads((control / "report.json").read_bytes()[:20 * 1024 * 1024])
            except (OSError, ValueError):
                return None, "the harness did not finish"
            if not _valid_report(result):
                return None, "the harness report is malformed or incomplete"
            rows, expected = result["tests"], result["expected"]
            ids = [r["id"] for r in rows]
            # Exactly one result for every test the loader found, and nothing else.
            if len(set(expected)) != len(expected) or len(set(ids)) != len(ids) or set(ids) != set(expected):
                return None, "results do not match the test inventory"
            return rows, ""
        finally:
            if proc is not None and proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if proc is not None:
                proc.wait()
            disk.__exit__(None, None, None)


def _export(clone, into):
    """A .git-free copy of the clone's index: what is tested is exactly what was staged."""
    git("checkout-index", "-a", "-f", f"--prefix={into}/", cwd=clone)
    return into


def _assigns_outside_self(target):
    """True for an assignment target that rebinds something other than self.x / cls.x:
    rebinding unittest.TestCase.assertEqual would make every base test pass (Fable round 2).
    Binding the NAMES self or cls is itself refused, or `self = unittest.TestCase` would
    reopen it (codex/agy round 4)."""
    for node in ast.walk(target):
        if isinstance(node, ast.Name) and node.id in ("self", "cls") and isinstance(node.ctx, ast.Store):
            return True
        if isinstance(node, ast.Attribute) and node.attr in FRAMEWORK_ATTRIBUTES:
            return True
        if isinstance(node, ast.Attribute):
            base = node.value
            if not (isinstance(base, ast.Name) and base.id in ("self", "cls")):
                return True
    return False


def _code_problems(path, text):
    """Names and imports a changed Python file may not use (the whole file, parsed)."""
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError as exc:
        return [f"syntax error line {exc.lineno}"]
    problems = []
    methods = {id(f) for c in ast.walk(tree) if isinstance(c, ast.ClassDef)
               for f in c.body if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            params = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
            named = [a for a in params if a.arg in ("self", "cls")]
            first_is_self = bool(node.args.args) and node.args.args[0].arg in ("self", "cls") and not node.args.posonlyargs
            if named and (id(node) not in methods or not first_is_self or len(named) > 1
                          or len(node.args.defaults) >= len(node.args.args)):
                problems.append("self/cls used as a parameter outside a method's first argument")
        targets = (node.targets if isinstance(node, ast.Assign) else
                   [node.target] if isinstance(node, (ast.AugAssign, ast.AnnAssign, ast.For, ast.AsyncFor,
                                                      ast.comprehension, ast.NamedExpr)) else
                   [i.optional_vars for i in node.items if i.optional_vars is not None]
                   if isinstance(node, (ast.With, ast.AsyncWith)) else
                   node.targets if isinstance(node, ast.Delete) else [])
        if any(_assigns_outside_self(t) for t in targets):
            problems.append("assignment to an attribute of something other than self")
        if isinstance(node, (ast.Import, ast.ImportFrom)) and any(a.asname in ("self", "cls") for a in node.names):
            problems.append("import as self/cls")
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name in ("self", "cls"):
            problems.append("pattern capture named self/cls")
        if isinstance(node, ast.Import):
            problems += [f"import {a.name}" for a in node.names if a.name.split(".")[0] not in SAFE_MODULES
                         or (a.name.split(".")[0] == "tests" and not path.startswith("tests/"))]
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if node.level or root not in SAFE_MODULES or (root == "tests" and not path.startswith("tests/")):
                problems.append(f"from {'.' * node.level}{node.module or ''} import")
            problems += [f"import {a.name}" for a in node.names if a.name in BANNED_NAMES or a.name == "*"
                         or a.name in STDLIB_MODULES or a.name.startswith("_")]
        elif isinstance(node, ast.Name) and (node.id in BANNED_NAMES or
                                             (node.id.startswith("__") and node.id != "__name__")):
            problems.append(node.id)
        elif isinstance(node, ast.Attribute) and (node.attr in BANNED_NAMES or node.attr in STDLIB_MODULES or (
                node.attr.startswith("_") and node.attr not in ALLOWED_DUNDER_ATTRIBUTES)):
            problems.append(f".{node.attr}")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and (
                node.name in BANNED_NAMES or (node.name.startswith("__") and node.name not in ALLOWED_DUNDER_METHODS)):
            problems.append(f"def {node.name}")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and "__" in node.value \
                and node.value != "__main__":
            problems.append("a string containing a double underscore")
    return sorted(set(problems))


def _defined(text):
    """Top-level function, class and variable names a module defines."""
    names = set()
    for node in ast.parse(text).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                names |= {n.id for n in ast.walk(target) if isinstance(n, ast.Name)}
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


def _summary(rows, keep=lambda r: r["outcome"] != "pass"):
    return "; ".join(f"{r['id']}: {r['outcome']} {r['exc'] or ''}".strip() for r in rows if keep(r))[:1200]


def evaluate(repo, base, diff):
    """Returns {"passed", "checks": [{"gate", "ok", "detail"}], "tree", "files"} for `diff` against `base`."""
    checks = []
    report = {"passed": False, "checks": checks, "tree": None, "files": {}}

    def gate(name, ok, detail=""):
        checks.append({"gate": name, "ok": bool(ok), "detail": "" if ok else IDENTIFIERS.sub("[redacted]", detail[:2000])})
        return ok

    if not gate("integrity", pins_ok(), "control files differ from the external pins (or no pins)"):
        return report
    if not gate("size", len(diff.encode()) <= MAX_DIFF_BYTES, f"diff is {len(diff.encode())} bytes"):
        return report
    markers = sorted({m for line in diff.splitlines() for m in SHAPE_MARKERS if line.startswith(m)})
    modes = [line for line in diff.splitlines() if line.startswith("new file mode") and line.split()[-1] != "100644"]
    if not gate("shape", not markers and not modes, f"not allowed: {markers + modes}"):
        return report
    with tempfile.TemporaryDirectory(prefix="agent-eval-") as tmp:
        tmp = Path(tmp).resolve()
        patch = tmp / "change.diff"
        patch.write_text(diff if diff.endswith("\n") else diff + "\n")
        candidate, original = tmp / "candidate", tmp / "base"
        for clone in (candidate, original):
            git("clone", "-q", "--no-hardlinks", "--no-checkout", str(Path(repo).resolve()), str(clone))
            git("checkout", "-q", "--detach", base, cwd=clone)
        numstat = git("apply", "--numstat", "-z", str(patch), cwd=candidate, check=False)
        entries = [e for e in numstat.stdout.split("\0") if e]
        stats = [e.split("\t") for e in entries]
        if not gate("shape", numstat.returncode == 0 and stats and all(len(s) == 3 and s[0] != "-" for s in stats),
                    "binary, empty or unparseable patch"):
            return report
        files = [s[2] for s in stats]
        changed = sum(int(s[0]) + int(s[1]) for s in stats)
        bad = [f for f in files if not SAFE_PATH.match(f) or not f.startswith(ALLOWED) or f.startswith(FORBIDDEN)
               or len(f) > MAX_PATH_CHARS or IDENTIFIERS.search(f)
               or any(part in ("", ".", "..") or part.startswith(".") for part in f.split("/"))]
        if not gate("paths", not bad, f"not allowed: {bad}"):
            return report
        # A package folder beats a module of the same name at import time, so tests/test_evaluator/__init__.py
        # would replace the human-written tests/test_evaluator.py, and tests/test_stats/ an existing test file
        # (Opus security re-review, 2026-10-05). No new path may share a module name with an existing one.
        tracked = set(git("ls-files", "-z", cwd=original).stdout.split("\0")) - {""}
        tracked_dirs = {"/".join(t.split("/")[:i]) for t in tracked for i in range(1, t.count("/") + 1)}
        protected = {f[:-3] for f in FORBIDDEN if f.endswith(".py")}
        shadows = [f for f in files if f not in tracked and (
            any("/".join(f.split("/")[:i]) + ".py" in tracked or "/".join(f.split("/")[:i]) in protected
                for i in range(1, f.count("/") + 1))
            or (f.endswith(".py") and f[:-3] in tracked_dirs))]
        if not gate("paths", not shadows, f"would shadow an existing module: {shadows}"):
            return report
        if not gate("size", changed <= MAX_LINES and len(files) <= MAX_FILES, f"{changed} lines, {len(files)} files"):
            return report
        deps = [f for f in files if DEPENDENCY_FILES.search(f)]
        if not gate("deps", not deps, f"dependency files: {deps}"):
            return report
        applied = git("apply", str(patch), cwd=candidate, check=False)
        if applied.returncode == 0:
            # Judge what git actually did, not what numstat reported: mismatched a/ and b/
            # headers make git delete a file numstat never lists (Fable round 2).
            git("add", "-A", cwd=candidate)
            status = [line.split("\t") for line in
                      git("diff", "--cached", "--name-status", "--no-renames", base, cwd=candidate).stdout.splitlines()]
            surprises = [s for s in status if s[0] not in ("A", "M") or s[-1] not in files]
            if not gate("shape", not surprises and len(status) == len(files),
                        f"git changed files the patch did not declare: {surprises[:5]}"):
                return report
            # A change may add tests but never edit existing ones: the suite gate judges base tests by
            # id only, so rewritten assertions under the same names would pass (Fable security review).
            edited = [f for code, *rest in status for f in rest[-1:] if code != "A" and f.startswith("tests/")]
            if not gate("shape", not edited, f"existing test files can't be changed: {edited[:5]}"):
                return report
        contents = {}
        for f in files:
            target = candidate / f
            info = os.lstat(target) if os.path.lexists(target) else None
            if info is None or not stat.S_ISREG(info.st_mode) or candidate not in target.resolve().parents:
                applied = None
                break
            if info.st_size > MAX_RESULT_FILE_BYTES:
                applied = None
                break
            try:
                contents[f] = target.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                applied = None
                break
        if not gate("applies", applied is not None and applied.returncode == 0,
                    (applied.stderr[-300:] if applied else "a changed path is not a regular UTF-8 file")):
            return report
        long_lines = [f for f, text in contents.items() if any(len(line) > MAX_LINE_CHARS for line in text.splitlines())]
        if not gate("size", not long_lines, f"lines over {MAX_LINE_CHARS} characters in {long_lines}"):
            return report
        leaks = [f for f, text in contents.items() if any(IDENTIFIERS.search(line) for line in text.splitlines())]
        if not gate("identifiers", not leaks, f"in {leaks}"):
            return report
        problems = {f: _code_problems(f, text) for f, text in contents.items() if f.endswith(".py")}
        problems = {f: p for f, p in problems.items() if p}
        if not gate("code", not problems, json.dumps(problems)[:800]):
            return report
        tests = [f for f in files if f.startswith("tests/") and Path(f).name.startswith("test_") and f.endswith(".py")]
        if not gate("tests", tests, "the change carries no test file"):
            return report
        # Record the exact tree that will be tested, before any code runs; tests then run on
        # .git-free exports of the staged trees (no history, config or hooks are visible).
        git("add", "-A", cwd=candidate)
        report["tree"] = git("write-tree", cwd=candidate).stdout.strip()
        report["files"] = contents
        candidate_src = _export(candidate, tmp / "candidate-src")
        base_src = _export(original, tmp / "base-src")
        bite_src = _export(original, tmp / "bite-src")
        baseline, why = run_tests(base_src)
        if not gate("baseline", baseline is not None and all(r["outcome"] in ("pass", "skip") for r in baseline),
                    why or _summary(baseline, keep=lambda r: r["outcome"] not in ("pass", "skip"))):
            return report
        result, why = run_tests(candidate_src)
        if not gate("suite", result is not None, why):
            return report
        changed_modules = {f[:-3].replace("/", ".") for f in tests}
        in_changed = lambda test_id: any(test_id.startswith(m + ".") for m in changed_modules)
        ids = {r["id"]: r for r in result}
        base_ids = {r["id"] for r in baseline}
        base_pass = {r["id"] for r in baseline if r["outcome"] == "pass"}
        base_skip = {r["id"] for r in baseline if r["outcome"] == "skip"}
        # A base test that skips in the sandbox must still exist afterwards (Fable round 4).
        lost = sorted([i for i in base_pass if ids.get(i, {}).get("outcome") != "pass"] +
                      [i for i in base_skip if i not in ids])
        new_skips = sorted(i for i, r in ids.items() if r["outcome"] == "skip" and i not in base_skip)
        # New tests are judged by id, so a change may add a test to an existing test file.
        new_ids = sorted(i for i in ids if in_changed(i) and i not in base_ids)
        failing = [r for r in result if r["outcome"] not in ("pass", "skip")]
        if not gate("suite", not lost and not new_skips and not failing and new_ids
                    and all(ids[i]["outcome"] == "pass" for i in new_ids),
                    f"lost {lost[:5]}; new skips {new_skips[:5]}; new tests {len(new_ids)}; " + _summary(result)):
            return report
        # Bite: the changed test files (and any test helpers the change touches), on the base code.
        for f in (f for f in files if f.startswith("tests/")):
            (bite_src / f).parent.mkdir(parents=True, exist_ok=True)
            (bite_src / f).write_text(contents[f], encoding="utf-8")
        bite, why = run_tests(bite_src, tests)
        added = set()
        for f, text in contents.items():
            if f.startswith("agentlib/") and f.endswith(".py"):
                module = f[:-3].replace("/", ".")
                before = git("show", f"{base}:{f}", cwd=original, check=False)
                if before.returncode != 0:
                    added.add(module)
                else:
                    added |= {f"{module}.{n}" for n in _defined(text) - _defined(before.stdout)}

        def behavioural(r):
            """The test ran and the base code got it wrong; a load failure counts only when the
            missing thing is exactly what this change adds."""
            if r["outcome"] == "fail":
                return True
            if r["outcome"] != "error" or r["exc"] in (None, "SyntaxError", "IndentationError", "OtherError"):
                return False
            if r["exc"] in ("ImportError", "ModuleNotFoundError"):
                return r["missing"] in added
            return not r["id"].startswith("unittest.loader.")

        rows = {r["id"]: r for r in (bite or [])}
        load_failures = {r["id"].split("_FailedTest.", 1)[1]: r for r in (bite or []) if "_FailedTest." in r["id"]}

        def bitten(test_id):
            if test_id in rows:
                return behavioural(rows[test_id])
            module = next(m for m in changed_modules if test_id.startswith(m + "."))
            failure = next((r for key, r in load_failures.items() if module == key or module.endswith("." + key)), None)
            return failure is not None and behavioural(failure)

        weak = [i for i in new_ids if not bitten(i)]
        gate("bite", bite is not None and not weak,
             why or (f"{len(weak)} of {len(new_ids)} new tests pass or fail for a non-behavioural reason "
                     f"on the base code: {weak[:5]}"))
        report["bite"] = [{"id": r["id"], "outcome": r["outcome"], "exc": r["exc"], "missing": r["missing"]}
                          for r in (bite or [])]
    report["passed"] = all(c["ok"] for c in checks) and checks[-1]["gate"] == "bite"
    return report


def run_suite(repo, ref="HEAD"):
    """Agent-written code must never run unsandboxed: tests can reach os despite the static gate."""
    if not pins_ok():
        print("control files differ from the external pins (or no pins): not running")
        return 1
    with tempfile.TemporaryDirectory(prefix="agent-suite-") as tmp:
        tmp = Path(tmp).resolve()
        git("clone", "-q", "--no-hardlinks", "--no-checkout", str(Path(repo).resolve()), str(tmp / "clone"))
        git("checkout", "-q", "--detach", ref, cwd=tmp / "clone")
        rows, why = run_tests(_export(tmp / "clone", tmp / "src"))
    if rows is None:
        print(f"suite did not run: {why}")
        return 1
    bad = [r for r in rows if r["outcome"] not in ("pass", "skip")]
    print(f"{len(rows)} tests in the sandbox: {len(rows) - len(bad)} passed or skipped, {len(bad)} failed")
    for r in bad[:20]:
        print(f"  {r['outcome']}: {r['id']} {r['exc'] or ''}")
    return 1 if bad else 0


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(REPO_ROOT))
    ap.add_argument("--base", default="HEAD")
    ap.add_argument("--diff")
    ap.add_argument("--pin", action="store_true", help="human only: write the external pins from the current files")
    ap.add_argument("--suite", action="store_true",
                    help="run the committed HEAD's tests inside the sandbox (the only safe way to run agent code)")
    a = ap.parse_args(argv)
    if a.suite:
        return run_suite(a.repo, a.base)
    if a.pin:
        write_pins()
        print(f"pinned {len(PINNED_FILES)} control files in {PINS}")
        return 0
    report = evaluate(a.repo, a.base, Path(a.diff).read_text())
    print(json.dumps({k: v for k, v in report.items() if k != "files"}, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
