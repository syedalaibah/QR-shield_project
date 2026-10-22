import unittest

from qrshield.analyzer import analyze_payload
from qrshield.reporting import build_html_report, build_json_report


class TestReports(unittest.TestCase):
    def test_reports_do_not_include_sensitive_token_value(self):
        result = analyze_payload("https://example.com/callback?access_token=hidden-demo-token")
        html_report = build_html_report(result).decode("utf-8")
        json_report = build_json_report(result).decode("utf-8")
        self.assertNotIn("hidden-demo-token", html_report)
        self.assertNotIn("hidden-demo-token", json_report)
        self.assertIn("[REDACTED]", html_report)
        self.assertIn("[REDACTED]", json_report)


if __name__ == "__main__":
    unittest.main()
