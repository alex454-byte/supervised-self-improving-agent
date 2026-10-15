"""Toy domain: small, pure text statistics the agent can be asked to extend.

It stands in for whatever pure, testable library code a real deployment would
let the agent improve. Code in agentlib/ must pass the frozen evaluator's rules:
standard-library computation only, no files, network, processes or reflection.
"""


def words(text):
    """The words in `text`, in order: runs of letters and apostrophes."""
    found, current = [], ""
    for ch in text:
        if ch.isalpha() or ch == "'":
            current += ch
        elif current:
            found.append(current)
            current = ""
    if current:
        found.append(current)
    return found


def word_count(text):
    return len(words(text))
