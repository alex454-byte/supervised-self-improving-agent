#!/usr/bin/env python3
"""Back up the agent ledger to a private, versioned bucket, and prove the backup restores.

    ledger_backup.py backup          verify the chain, then upload (every version is kept)
    ledger_backup.py restore-test    download the latest backup to a temp file and check that
                                     its chain verifies and that it is a prefix of the local ledger

A broken chain is never uploaded, so a bad local file cannot overwrite a good backup
(and the bucket's versioning keeps every earlier copy anyway). The ledger holds no
personal data: ledger_append refuses emails and long digit runs.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger_append  # noqa: E402

BUCKET = os.environ.get("AGENT_LEDGER_BUCKET", "gs://YOUR-LEDGER-BUCKET")
REMOTE = f"{BUCKET}/ledger.jsonl"


class GcsStore:
    def upload(self, local, remote):
        subprocess.run(["gcloud", "storage", "cp", "--quiet", local, remote], check=True, capture_output=True,
                       timeout=300)

    def download(self, remote, local):
        subprocess.run(["gcloud", "storage", "cp", "--quiet", remote, local], check=True, capture_output=True,
                       timeout=300)


def _hashes(path):
    with open(path) as fh:
        return [json.loads(line)["hash"] for line in fh if line.strip()]


def backup(path, store):
    ok, message = ledger_append.verify(path)
    if not ok:
        raise ValueError(f"ledger chain is broken, not uploading: {message}")
    store.upload(path, REMOTE)
    return {"rows": len(_hashes(path)), "remote": REMOTE}


def restore_test(path, store):
    with tempfile.TemporaryDirectory() as tmp:
        copy = os.path.join(tmp, "restored.jsonl")
        store.download(REMOTE, copy)
        ok, _ = ledger_append.verify(copy)
        remote, local = _hashes(copy), _hashes(path)
    prefix = remote == local[:len(remote)]
    return {"ok": ok and prefix, "rows": len(remote), "behind": len(local) - len(remote) if prefix else None}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=("backup", "restore-test"))
    a = ap.parse_args(argv)
    store = GcsStore()
    result = backup(ledger_append.LEDGER, store) if a.action == "backup" else restore_test(ledger_append.LEDGER, store)
    print(json.dumps(result))
    return 0 if result.get("ok", True) else 1


if __name__ == "__main__":
    sys.exit(main())
