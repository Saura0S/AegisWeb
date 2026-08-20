"""
Unit tests for SecretScanner
"""

from aegisweb.scanner.secret_scanner import SecretScanner


def test_detect_google_api_key():
    scanner = SecretScanner()
    html = """
    <html>
      <head>
        <script>
          const mapsApiKey = "AIzaSyD-1234567890abcdefghijklmnopqrstuvw";
        </script>
      </head>
    </html>
    """
    res = scanner.scan("https://example.com", html)
    assert res["total_secrets_found"] >= 1
    assert res["leaks"][0]["type"] == "Google API Key"
    assert res["leaks"][0]["severity"] == "HIGH"


def test_detect_aws_access_key():
    scanner = SecretScanner()
    html = """
    <script>
      var aws_key = "AKIAIOSFODNN7EXAMPLE";
    </script>
    """
    res = scanner.scan("https://example.com", html)
    assert res["total_secrets_found"] >= 1
    assert "AWS Access Key ID" in [l["type"] for l in res["leaks"]]


def test_no_secrets():
    scanner = SecretScanner()
    html = "<html><body><h1>Clean Public Website</h1></body></html>"
    res = scanner.scan("https://example.com", html)
    assert res["total_secrets_found"] == 0