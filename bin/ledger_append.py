#!/usr/bin/env python3
"""Single-writer, append-only, hash-chained ledger for the agent.

Every stage submits rows through this one function, which takes an exclusive flock,
reads the last row's hash, and appends {seq, ts, type, data, prev_hash, hash}.
One writer means the chain cannot fork; `verify` proves no row was edited or removed.

    ledger_append.py append --type claim --data '{"id":"example-2026-09-28","check_on":"2026-10-28"}'
    ledger_append.py verify
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import sys

LEDGER = os.environ.get("AGENT_LEDGER",
                        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "state", "ledger.jsonl"))
TYPES = {"hypothesis", "claim", "insight", "spend", "backlog", "run", "decision", "llm_run",
         "review", "proposal"}
SCHEMA_VERSION = 1
# Raw identifiers must never enter the ledger: emails, long digit runs (account ids, phones).
FORBIDDEN = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|\d{7,}")


def _hash(row):
    body = {k: row[k] for k in ("seq", "ts", "type", "schemaVersion", "data", "prev_hash")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _strings(value):
    """Every string (keys and values) inside the row. Numbers such as token counts are not text
    identifiers and are not scanned; an account id or phone stored as text is."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)


def _rows(fh):
    fh.seek(0)
    return [json.loads(line) for line in fh if line.strip()]


def append(kind, data, path=LEDGER, now=None):
    if kind not in TYPES:
        raise ValueError(f"unknown ledger type: {kind}")
    if not isinstance(data, dict):
        raise ValueError("ledger data must be an object")
    if any(FORBIDDEN.search(s) for s in _strings(data)):
        raise ValueError("ledger row contains an email or long digit run; pseudonymise first")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a+") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            rows = _rows(fh)
            prev = rows[-1]["hash"] if rows else "0" * 64
            row = {"seq": len(rows) + 1,
                   "ts": (now or dt.datetime.now(dt.timezone.utc)).isoformat(timespec="seconds"),
                   "type": kind, "schemaVersion": SCHEMA_VERSION, "data": data, "prev_hash": prev}
            row["hash"] = _hash(row)
            fh.seek(0, os.SEEK_END)
            fh.write(json.dumps(row, separators=(",", ":")) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
            return row
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def verify(path=LEDGER):
    """Returns (ok, message). Detects edited, removed, reordered or forked rows."""
    if not os.path.exists(path):
        return True, "empty ledger"
    with open(path) as fh:
        rows = _rows(fh)
    prev = "0" * 64
    for i, row in enumerate(rows, 1):
        if row.get("seq") != i:
            return False, f"row {i}: sequence break (found {row.get('seq')})"
        if row.get("prev_hash") != prev:
            return False, f"row {i}: chain break"
        if _hash(row) != row.get("hash"):
            return False, f"row {i}: contents changed after writing"
        prev = row["hash"]
    return True, f"{len(rows)} rows verified"


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("append")
    a.add_argument("--type", required=True)
    a.add_argument("--data", required=True, help="JSON object")
    sub.add_parser("verify")
    args = ap.parse_args(argv)
    if args.cmd == "append":
        row = append(args.type, json.loads(args.data))
        print(row["hash"])
        return 0
    ok, message = verify()
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
