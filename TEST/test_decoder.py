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


def test_t03_smtp_base64_qp():
    # T03: MIME body có encoding -> decode đúng + decode_status
    b64, st1 = decode_mime("SGVsbG8gd29ybGQ=", "base64")
    assert b64 == "Hello world"
    assert st1 == "ok"

    qp, st2 = decode_mime("Hello=20World=21", "quoted-printable")
    assert qp == "Hello World!"
    assert st2 == "ok"
    print("[PASS] T03 - SMTP Base64/Quoted-Printable decode")


if __name__ == "__main__":
    test_t01_url_decode()
    test_t02_html_entity()
    test_t03_smtp_base64_qp()
    print("\n=== Decoder tests PASSED ===")
