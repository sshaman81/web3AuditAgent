from web3audit.cache_manager import CacheManager


def test_llm_response_memory_bank_roundtrip(tmp_path):
    db_path = tmp_path / "cache.sqlite3"
    cache = CacheManager(str(db_path))

    assert cache.get_llm_response("missing") is None

    cache.set_llm_response("k1", {"content": "{\"ok\": true}"})
    cached = cache.get_llm_response("k1")
    assert cached is not None
    assert cached["content"] == "{\"ok\": true}"
