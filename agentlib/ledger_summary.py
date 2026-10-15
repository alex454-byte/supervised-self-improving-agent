"""Pure weekly aggregation of ledger entries."""

from datetime import date


def summarise(entries, week):
    """Summarise an (ISO year, week number) using recorded calendar dates.

    Return counts by type, model_runs by CLI then status, tokens by CLI,
    and decisions by outcome. Only llm_run entries contribute model usage.
    Missing or null token counts contribute zero.
    """
    result = {"counts": {}, "model_runs": {}, "tokens": {}, "decisions": {}}
    for entry in entries:
        if date.fromisoformat(entry["ts"][:10]).isocalendar()[:2] != week:
            continue
        kind = entry["type"]
        counts = result["counts"]
        counts[kind] = counts.get(kind, 0) + 1
        data = entry["data"]
        if kind == "llm_run":
            cli = data["cli"]
            status = data["status"]
            statuses = result["model_runs"].setdefault(cli, {})
            statuses[status] = statuses.get(status, 0) + 1
            tokens = result["tokens"]
            tokens[cli] = tokens.get(cli, 0) + int(data.get("tokens") or 0)
        elif kind == "decision":
            outcome = data["outcome"]
            decisions = result["decisions"]
            decisions[outcome] = decisions.get(outcome, 0) + 1
    return result
