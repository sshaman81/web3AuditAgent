from typing import Set


class DuplicateHypothesisError(Exception):
    """Raised when the LLM produces an already attempted hypothesis."""


def word_overlap(candidate: str, existing: str) -> float:
    normalize = lambda text: {w for w in text.lower().split() if w}
    set_candidate = normalize(candidate)
    set_existing = normalize(existing)
    if not set_candidate or not set_existing:
        return 0.0
    intersection = set_candidate & set_existing
    union = set_candidate | set_existing
    return len(intersection) / len(union)
