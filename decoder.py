import base64
import binascii
import html
import quopri
from urllib.parse import unquote, unquote_plus


def decode_url(text):
    # %27%20OR%201%3D1 -> ' OR 1=1
    try:
        return unquote(text, errors="replace"), "ok"
    except Exception:
        return text, "error"


def decode_form_urlencoded(text):
    # application/x-www-form-urlencoded: dấu + thành khoảng trắng
    try:
        return unquote_plus(text, errors="replace"), "ok"
    except Exception:
        return text, "error"


def decode_html_entities(text):
    # &lt;script&gt; -> <script>
    try:
        return html.unescape(text), "ok"
    except Exception:
        return text, "error"


def decode_base64(data):
    try:
        raw = base64.b64decode(data, validate=False)
        return raw.decode("utf-8", errors="replace"), "ok"
    except (binascii.Error, ValueError):
        return data, "error"


def decode_quoted_printable(data):
    try:
        raw = quopri.decodestring(data.encode("utf-8") if isinstance(data, str) else data)
        return raw.decode("utf-8", errors="replace"), "ok"
    except Exception:
        return data, "error"


def decode_mime(body, encoding):
    # Chọn cách giải mã dựa trên header Content-Transfer-Encoding
    enc = (encoding or "").lower().strip()
    if enc == "base64":
        return decode_base64(body)
    if enc == "quoted-printable":
        return decode_quoted_printable(body)
    return body, "none"


def decode_bytes(raw):
    # Giải mã bytes sang text, không crash khi gặp byte không hợp lệ
    if isinstance(raw, str):
        return raw, "ok"
    try:
        return raw.decode("ascii"), "ascii"
    except (UnicodeDecodeError, AttributeError):
        pass
    try:
        return raw.decode("utf-8"), "utf-8"
    except (UnicodeDecodeError, AttributeError):
        return raw.decode("utf-8", errors="replace"), "partial"


def decode_event(event):
    # Nhận event đã parse, trả về bản sao có thêm field decoded + decode_status
    result = dict(event)
    status = {}

    if event.get("type") == "HTTP":
        if "path" in event:
            decoded, st = decode_url(event["path"])
            result["decoded_path"] = decoded
            status["path"] = st

        headers = event.get("headers", {})
        enc = headers.get("content-transfer-encoding")
        body = event.get("body")
        if body is not None and enc:
            decoded, st = decode_mime(body, enc)
            result["decoded_body"] = decoded
            status["body"] = st

    result["decode_status"] = status
    return result
