"""Tests for weekly ledger aggregation."""

from copy import deepcopy
import unittest

from agentlib.ledger_summary import summarise


class LedgerSummaryTests(unittest.TestCase):
    def test_two_weeks(self):
        entries = [
            {"type": "claim", "ts": "2026-09-28T09:00:00+00:00", "data": {}},
            {"type": "llm_run", "ts": "2026-09-29T09:00:00+00:00",
             "data": {"cli": "claude", "status": "ok", "tokens": 12}},
            {"type": "llm_run", "ts": "2026-09-30T09:00:00+00:00",
             "data": {"cli": "claude", "status": "ok", "tokens": 8}},
            {"type": "llm_run", "ts": "2026-10-01T09:00:00+00:00",
             "data": {"cli": "claude", "status": "quota", "tokens": None}},
            {"type": "llm_run", "ts": "2026-10-02T09:00:00+00:00",
             "data": {"cli": "codex", "status": "ok", "tokens": 5}},
            {"type": "llm_run", "ts": "2026-10-03T09:00:00+00:00",
             "data": {"cli": "gemini", "status": "error"}},
            {"type": "decision", "ts": "2026-10-03T10:00:00+00:00",
             "data": {"outcome": "accepted"}},
            {"type": "decision", "ts": "2026-10-04T10:00:00+00:00",
             "data": {"outcome": "accepted"}},
            {"type": "decision", "ts": "2026-10-04T11:00:00+00:00",
             "data": {"outcome": "rejected"}},
            {"type": "llm_run", "ts": "2026-10-05T09:00:00+00:00",
             "data": {"cli": "codex", "status": "error", "tokens": 3}},
            {"type": "decision", "ts": "2026-10-05T10:00:00+00:00",
             "data": {"outcome": "deferred"}},
        ]
        original = deepcopy(entries)
        self.assertEqual(summarise(iter(entries), (2026, 40)), {
            "counts": {"claim": 1, "llm_run": 5, "decision": 3},
            "model_runs": {
                "claude": {"ok": 2, "quota": 1},
                "codex": {"ok": 1},
                "gemini": {"error": 1},
            },
            "tokens": {"claude": 20, "codex": 5, "gemini": 0},
            "decisions": {"accepted": 2, "rejected": 1},
        })
        self.assertEqual(summarise(entries, (2026, 41)), {
            "counts": {"llm_run": 1, "decision": 1},
            "model_runs": {"codex": {"error": 1}},
            "tokens": {"codex": 3},
            "decisions": {"deferred": 1},
        })
        self.assertEqual(entries, original)

    def test_iso_year_and_empty_week(self):
        entries = [
            {"type": "claim", "ts": "2025-12-29T00:00:00+00:00", "data": {}},
            {"type": "claim", "ts": "2026-01-04T23:00:00-05:00", "data": {}},
            {"type": "claim", "ts": "2025-01-01T00:00:00+00:00", "data": {}},
        ]
        self.assertEqual(summarise(entries, (2026, 1)), {
            "counts": {"claim": 2},
            "model_runs": {}, "tokens": {}, "decisions": {},
        })
        empty = {"counts": {}, "model_runs": {}, "tokens": {}, "decisions": {}}
        self.assertEqual(summarise(entries, (2026, 2)), empty)
        self.assertEqual(summarise([], (2026, 1)), empty)
