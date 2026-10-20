"""Тесты huntkit.respdiff — сравнение HTTP-ответов."""



from huntkit.respdiff import ResponseSnapshot, compare, snapshot_from_httpx


def _snap(status: int = 200, body: str = "", **headers: str) -> ResponseSnapshot:
    return ResponseSnapshot(status=status, headers=headers, body=body)


def test_identical_responses_not_different() -> None:
    a = _snap(200, "hello", **{"content-type": "text/plain"})
    b = _snap(200, "hello", **{"content-type": "text/plain"})
    result = compare(a, b)
    assert not result.looks_different()
    assert result.body_similarity == 1.0
    assert result.length_delta == 0


def test_status_change_is_difference() -> None:
    result = compare(_snap(200, "x"), _snap(500, "x"))
    assert result.status_changed
    assert result.looks_different()


def test_significant_header_change_detected() -> None:
    a = _snap(200, "x", **{"content-type": "text/html"})
    b = _snap(200, "x", **{"content-type": "application/json"})
    result = compare(a, b)
    assert "content-type" in result.changed_headers
    assert result.changed_headers["content-type"] == ("text/html", "application/json")
    assert result.looks_different()


def test_header_comparison_is_case_insensitive() -> None:
    a = _snap(200, "x", **{"Content-Type": "text/html"})
    b = _snap(200, "x", **{"content-type": "text/html"})
    result = compare(a, b)
    assert result.changed_headers == {}


def test_small_body_change_below_threshold_not_different() -> None:
    # Отличие в один токен в длинном теле — сходство высокое, различием не считаем.
    base = "token=" + "a" * 500
    a = _snap(200, base + "X")
    b = _snap(200, base + "Y")
    result = compare(a, b)
    assert result.body_similarity > 0.98
    assert not result.looks_different()


def test_large_body_change_is_difference() -> None:
    a = _snap(200, "нет результатов")
    b = _snap(200, "товар 1\nтовар 2\nтовар 3\n" * 10)
    result = compare(a, b)
    assert result.body_similarity < 0.98
    assert result.looks_different()
    assert result.length_delta > 0


def test_blind_boolean_pattern() -> None:
    # Имитация boolean-blind: TRUE-условие даёт полную выдачу, FALSE — пустую.
    true_resp = _snap(200, "товар 1\nтовар 2\nтовар 3")
    false_resp = _snap(200, "")
    assert compare(true_resp, false_resp).looks_different()
    # А два одинаковых FALSE между собой неразличимы.
    assert not compare(false_resp, _snap(200, "")).looks_different()


def test_snapshot_from_httpx_like_object() -> None:
    class FakeResp:
        status_code = 200
        headers = {"Content-Type": "application/json"}
        text = '{"ok": true}'

    snap = snapshot_from_httpx(FakeResp())
    assert snap.status == 200
    assert snap.header("content-type") == "application/json"
    assert snap.body == '{"ok": true}'
