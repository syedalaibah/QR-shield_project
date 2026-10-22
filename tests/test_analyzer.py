import unittest

from qrshield.analyzer import analyze_payload, redact_sensitive_payload


class TestQRShieldAnalyzer(unittest.TestCase):
    def test_baseline_https_url_is_low(self):
        result = analyze_payload("https://example.com/")
        self.assertEqual(result["kind"], "Web URL")
        self.assertEqual(result["level"], "Low")
        self.assertEqual(result["score"], 0)

    def test_http_ip_login_example_is_flagged(self):
        result = analyze_payload("http://192.0.2.10/login?verify=1")
        self.assertGreaterEqual(result["score"], 20)
        self.assertIn(result["level"], {"Moderate", "High", "Critical"})
        names = {item["indicator"] for item in result["indicators"]}
        self.assertIn("Unencrypted HTTP", names)
        self.assertIn("IP-address destination", names)

    def test_javascript_scheme_is_critical(self):
        result = analyze_payload("javascript:alert(1)")
        self.assertEqual(result["level"], "Critical")
        self.assertEqual(result["score"], 100)

    def test_wifi_password_is_redacted(self):
        value = redact_sensitive_payload("WIFI:T:WPA;S:LabNetwork;P:topsecret123;;")
        self.assertNotIn("topsecret123", value)
        self.assertIn("[REDACTED]", value)

    def test_sensitive_url_query_is_redacted(self):
        result = analyze_payload("https://example.com/?access_token=secret123")
        self.assertNotIn("secret123", result["payload"])
        self.assertNotIn("secret123", result["target"])
        self.assertIn("Sensitive query parameter", {item["indicator"] for item in result["indicators"]})

    def test_brand_lookalike_sample_is_high_risk(self):
        result = analyze_payload("http://paypal-security-check.verify-account.login.example.invalid/verify")
        self.assertEqual(result["level"], "High")
        self.assertIn("Possible brand impersonation", {item["indicator"] for item in result["indicators"]})

    def test_url_userinfo_is_redacted(self):
        result = analyze_payload("https://student:secret-password@example.com/login")
        self.assertNotIn("secret-password", result["payload"])
        self.assertNotIn("student", result["target"])

    def test_empty_payload_raises(self):
        with self.assertRaises(ValueError):
            analyze_payload("  ")


if __name__ == "__main__":
    unittest.main()
