from utils import word_overlap


def test_word_overlap_high_similarity():
    first = "reentrancy emergency pause drain".lower()
    second = "emergency pause drain reentrancy".lower()
    assert word_overlap(first, second) > 0.8


def test_word_overlap_low_similarity():
    assert word_overlap("reentrancy", "oracle manipulation") < 0.2
