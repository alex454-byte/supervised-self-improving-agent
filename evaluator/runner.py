"""Pinned test harness. Runs inside the sandbox; reports every test by id.

    python -I runner.py ROOT FD [tests/test_x.py ...]

With no test files it discovers the whole suite under ROOT/tests. It writes its
report as JSON to the inherited file descriptor FD (never to a path the tests can
write): {"expected": [ids], "tests": [{"id", "outcome", "exc", "missing"}], "complete": true}.
"expected" is every test the loader found, listed before anything runs, so the
evaluator can require exactly one result per expected test. A failing subtest fails
its test (unittest reports subtests through a separate callback).
"complete" is written last, so a harness that was killed, timed out or exited
early never looks like a finished run. Only built-in exception names and plain
dotted module names leave the sandbox, so a test cannot smuggle data out through
an exception's class name or message.
"""
import builtins
import json
import os
import re
import sys
import unittest

# Captured before any test module is imported, so candidate code cannot swap them out.
_dumps, _fdopen, _TestResult = json.dumps, os.fdopen, unittest.TestResult

MISSING_NAME = re.compile(r"cannot import name '([^']+)' from '([^']+)'")
MISSING_MODULE = re.compile(r"No module named '([^']+)'")
DOTTED = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,80}(\.[A-Za-z_][A-Za-z0-9_]{0,80}){0,7}$")
BUILTIN_EXCEPTIONS = {name for name, value in vars(builtins).items()
                      if isinstance(value, type) and issubclass(value, BaseException)}


def _exc_name(exc):
    name = type(exc).__name__
    return name if name in BUILTIN_EXCEPTIONS and type(exc) is getattr(builtins, name) else "OtherError"


def _missing(exc):
    """What an ImportError could not find: a module path or 'module.name'.

    unittest re-raises a test module's load failure as a plain ImportError whose
    message carries the original traceback, so the message is read as well."""
    found = None
    if isinstance(exc, ModuleNotFoundError) and exc.name:
        found = exc.name
    else:
        text = str(exc)
        names = MISSING_NAME.findall(text)
        modules = MISSING_MODULE.findall(text)
        found = f"{names[-1][1]}.{names[-1][0]}" if names else modules[-1] if modules else None
    return found if found and DOTTED.match(found) else None


def _collect():
    rows = {}

    class Result(_TestResult):
        def _row(self, test, outcome, err=None):
            exc = err[1] if err else None
            row = {"id": _safe_id(test.id()), "outcome": outcome, "exc": _exc_name(exc) if exc else None,
                   "missing": _missing(exc) if isinstance(exc, ImportError) else None}
            earlier = rows.get(row["id"])
            # A test reported twice keeps its worst outcome; a pass never hides a failure.
            if earlier is None or earlier["outcome"] in ("pass", "skip"):
                rows[row["id"]] = row

        def addSuccess(self, test):
            self._row(test, "pass")

        def addSubTest(self, test, subtest, err):
            if err is not None:
                self._row(test, "fail" if issubclass(err[0], test.failureException) else "error", err)

        def addFailure(self, test, err):
            self._row(test, "fail", err)

        def addError(self, test, err):
            self._row(test, "error", err)

        def addSkip(self, test, reason):
            self._row(test, "skip")

        def addExpectedFailure(self, test, err):
            self._row(test, "error", err)

        def addUnexpectedSuccess(self, test):
            self._row(test, "error")

    return rows, Result()


def _safe_id(test_id):
    """Test ids leave the sandbox, so only plain dotted names pass (a test can override id())."""
    return test_id if DOTTED.match(test_id or "") else "nonconforming-test-id"


def _ids(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _ids(item)
        else:
            yield _safe_id(item.id())


def main(root, fd, files):
    report = _fdopen(int(fd), "w")
    sys.path.insert(0, root)
    loader = unittest.TestLoader()
    if files:
        suite = unittest.TestSuite(loader.loadTestsFromName(f[:-3].replace("/", ".")) for f in files)
    else:
        suite = loader.discover(start_dir=f"{root}/tests", top_level_dir=root)
    expected = list(_ids(suite))
    rows, result = _collect()
    suite.run(result)
    report.write(_dumps({"expected": expected, "tests": list(rows.values()), "complete": True}))
    report.close()


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3:])
