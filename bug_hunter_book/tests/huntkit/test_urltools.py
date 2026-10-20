"""Тесты huntkit.urltools — нормализация и дедупликация URL."""



from huntkit.urltools import dedupe, normalize, same_target


def test_lowercases_scheme_and_host() -> None:
    assert normalize("HTTP://Example.COM/Path") == "http://example.com/Path"


def test_drops_default_port() -> None:
    assert normalize("https://example.com:443/a") == "https://example.com/a"
    assert normalize("http://example.com:80/a") == "http://example.com/a"


def test_keeps_nondefault_port() -> None:
    assert normalize("http://example.com:8080/a") == "http://example.com:8080/a"


def test_empty_path_becomes_slash() -> None:
    assert normalize("https://example.com") == "https://example.com/"


def test_collapses_double_slashes_in_path() -> None:
    assert normalize("https://example.com//a///b") == "https://example.com/a/b"


def test_sorts_query_for_stable_comparison() -> None:
    assert normalize("https://e.com/?b=2&a=1") == "https://e.com/?a=1&b=2"


def test_drops_fragment_by_default() -> None:
    assert normalize("https://e.com/a#section") == "https://e.com/a"
    assert normalize("https://e.com/a#section", drop_fragment=False) == "https://e.com/a#section"


def test_same_target_ignores_cosmetic_differences() -> None:
    assert same_target("HTTP://E.com:80/a?b=2&a=1#x", "http://e.com/a?a=1&b=2")


def test_dedupe_keeps_first_occurrence_order() -> None:
    urls = [
        "http://e.com/a",
        "http://E.com/a/",          # отличается регистром — дубликат? путь /a vs /a/ различается
        "http://e.com/a#frag",      # дубликат /a (фрагмент отброшен)
        "http://e.com/b",
    ]
    result = dedupe(urls)
    assert result == ["http://e.com/a", "http://e.com/a/", "http://e.com/b"]


def test_dedupe_skips_broken_urls() -> None:
    result = dedupe(["http://e.com/a", "http://e.com/a"])
    assert result == ["http://e.com/a"]
