import sys
sys.path.insert(0, "..")

from decoder import decode_url, decode_html_entities, decode_mime, decode_bytes


def test_t01_url_decode():
    # T01: URI chứa percent-encoding -> decode đúng, raw còn nguyên
    raw = "%27%20OR%201%3D1"
    decoded, status = decode_url(raw)
    assert decoded == "' OR 1=1"
    assert raw == "%27%20OR%201%3D1"  # raw không đổi
    assert status == "ok"
    print("[PASS] T01 - HTTP URL decode")


def test_t02_html_entity():
    # T02: &lt;script&gt; trong text HTTP -> decode đúng, không crash
    decoded, status = decode_html_entities("&lt;script&gt;alert(1)&lt;/script&gt;")
    assert decoded == "<script>alert(1)</script>"
    assert status == "ok"
    print("[PASS] T02 - HTML entity decode")


if __name__ == "__main__":
    test_t01_url_decode()
    test_t02_html_entity()
    print("\n=== Decoder tests PASSED ===")
