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


if __name__ == "__main__":
    test_t01_url_decode()
    print("\n=== Decoder tests PASSED ===")
