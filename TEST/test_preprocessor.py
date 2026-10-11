import sys
sys.path.insert(0, "..")

from preprocessor import preprocess


def test_t05_normalization():
    # T05: protocol/domain khác kiểu chữ -> sau preprocess nhất quán
    event = {
        "src_ip": "192.168.1.1", "dst_ip": "10.0.0.1",
        "protocol": "TCP", "type": "HTTP",
        "headers": {"Host": "EXAMPLE.COM", "User-Agent": "curl"},
    }
    result = preprocess(event)
    assert result["protocol"] == "tcp"
    assert result["headers"]["host"] == "example.com"
    assert "user-agent" in result["headers"]
    print("[PASS] T05 - Normalization consistent")


if __name__ == "__main__":
    test_t05_normalization()
    print("\n=== Preprocessor tests PASSED ===")
