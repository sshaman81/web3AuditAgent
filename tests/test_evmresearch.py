from types import SimpleNamespace

from web3audit.evmresearch import fetch_comparison_bug_references, render_comparison_bug_context


def test_fetch_comparison_bug_references_from_index_and_patterns(monkeypatch):
    pages = {
        "https://evmresearch.io/index": """
            [Vulnerability Patterns](https://evmresearch.io/vulnerability-patterns)
            [Storage Collision Writeups](https://evmresearch.io/notes/storage-collision)
        """,
        "https://evmresearch.io/vulnerability-patterns": """
            [Unsafe Precision Loss in AMM Math](https://evmresearch.io/notes/unsafe-precision-loss-in-amm-math)
            [Reentrancy Basics](https://evmresearch.io/notes/reentrancy-basics)
            [Invalid Comparison in Oracle Bounds](https://evmresearch.io/notes/invalid-comparison-in-oracle-bounds)
        """,
    }

    def fake_get(url, timeout):
        if url not in pages:
            raise AssertionError(f"Unexpected URL: {url}")
        return SimpleNamespace(text=pages[url], raise_for_status=lambda: None)

    monkeypatch.setattr("web3audit.evmresearch.requests.get", fake_get)
    refs = fetch_comparison_bug_references("https://evmresearch.io/index", timeout_seconds=2, max_refs=5)

    urls = {item["url"] for item in refs}
    assert "https://evmresearch.io/notes/unsafe-precision-loss-in-amm-math" in urls
    assert "https://evmresearch.io/notes/invalid-comparison-in-oracle-bounds" in urls
    assert all("reentrancy" not in item["url"] for item in refs)


def test_render_comparison_bug_context_empty():
    assert render_comparison_bug_context([]) == ""
