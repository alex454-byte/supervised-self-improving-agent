"""Ledger backup refuses a broken chain; the restore test proves a backup is usable."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

BIN = Path(__file__).resolve().parent.parent / "bin"
sys.path.insert(0, str(BIN))
import ledger_append  # noqa: E402
import ledger_backup  # noqa: E402


class FakeStore:
    def __init__(self):
        self.objects = {}

    def upload(self, local, remote):
        self.objects[remote] = Path(local).read_bytes()

    def download(self, remote, local):
        if remote not in self.objects:
            raise FileNotFoundError(remote)
        Path(local).write_bytes(self.objects[remote])


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "ledger.jsonl")
        for i in range(3):
            ledger_append.append("claim", {"id": f"c{i}"}, path=self.path)
        self.store = FakeStore()

    def tearDown(self):
        self.tmp.cleanup()

    def test_backup_then_restore_test_passes(self):
        self.assertEqual(ledger_backup.backup(self.path, self.store)["rows"], 3)
        self.assertEqual(ledger_backup.restore_test(self.path, self.store), {"ok": True, "rows": 3, "behind": 0})

    def test_a_broken_chain_is_never_uploaded(self):
        lines = Path(self.path).read_text().splitlines()
        Path(self.path).write_text("\n".join([lines[0], lines[2]]) + "\n")
        with self.assertRaises(ValueError):
            ledger_backup.backup(self.path, self.store)
        self.assertEqual(self.store.objects, {})

    def test_restore_test_reports_a_stale_or_corrupt_backup(self):
        ledger_backup.backup(self.path, self.store)
        ledger_append.append("claim", {"id": "c3"}, path=self.path)
        self.assertEqual(ledger_backup.restore_test(self.path, self.store), {"ok": True, "rows": 3, "behind": 1})
        self.store.objects[ledger_backup.REMOTE] = self.store.objects[ledger_backup.REMOTE].replace(b'"c1"', b'"cX"')
        self.assertFalse(ledger_backup.restore_test(self.path, self.store)["ok"])

    def test_a_backup_that_is_not_a_prefix_of_the_local_ledger_fails(self):
        other = os.path.join(self.tmp.name, "other.jsonl")
        for i in range(3):
            ledger_append.append("claim", {"id": f"z{i}"}, path=other)
        ledger_backup.backup(other, self.store)
        self.assertFalse(ledger_backup.restore_test(self.path, self.store)["ok"])


if __name__ == "__main__":
    unittest.main()
