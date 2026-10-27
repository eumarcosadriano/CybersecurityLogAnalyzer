import unittest
from datetime import datetime, timezone

from cybersecurity_log_analyzer import analyzer


class ParseLogLineTests(unittest.TestCase):
    def _parser(self):
        self.assertTrue(hasattr(analyzer, "parse_log_line"))
        return analyzer.parse_log_line

    def test_valid_failed_login_line_is_parsed(self):
        parse_log_line = self._parser()

        result = parse_log_line(
            "2026-10-01T10:00:00+00:00 login_failed user=alice ip=203.0.113.10"
        )

        self.assertEqual(result.timestamp, datetime(2026, 10, 1, 10, tzinfo=timezone.utc))
        self.assertEqual(result.event, "login_failed")
        self.assertEqual(result.username, "alice")
        self.assertEqual(result.ip, "203.0.113.10")

    def test_valid_successful_login_line_is_parsed(self):
        parse_log_line = self._parser()

        result = parse_log_line(
            "2026-10-01T10:01:00+00:00 login_success user=bob ip=198.51.100.7"
        )

        self.assertEqual(result.event, "login_success")
        self.assertEqual(result.username, "bob")

    def test_invalid_record_is_rejected(self):
        parse_log_line = self._parser()

        result = parse_log_line(
            "2026-10-01T10:02:00+00:00 login_failed user=alice ip=not-an-ip"
        )

        self.assertIsNone(result)

    def test_malformed_line_is_rejected(self):
        parse_log_line = self._parser()

        result = parse_log_line("this is not an authentication record")

        self.assertIsNone(result)


class AnalyzeLinesTests(unittest.TestCase):
    def _analyzer(self):
        self.assertTrue(hasattr(analyzer, "analyze_lines"))
        return analyzer.analyze_lines

    def test_empty_input_returns_zeroed_report(self):
        analyze_lines = self._analyzer()

        result = analyze_lines([])

        self.assertEqual(result.total_entries, 0)
        self.assertEqual(result.failed_attempts, 0)
        self.assertEqual(result.successful_logins, 0)
        self.assertEqual(result.failed_by_ip, {})
        self.assertEqual(result.suspicious_ips, [])
        self.assertEqual(result.malformed_lines, 0)

    def test_suspicious_threshold_is_inclusive(self):
        analyze_lines = self._analyzer()
        lines = [
            "2026-10-01T10:00:00+00:00 login_failed user=alice ip=203.0.113.10",
            "2026-10-01T10:01:00+00:00 login_failed user=alice ip=203.0.113.10",
            "2026-10-01T10:02:00+00:00 login_failed user=alice ip=203.0.113.10",
            "2026-10-01T10:03:00+00:00 login_failed user=bob ip=192.0.2.44",
            "2026-10-01T10:04:00+00:00 login_failed user=bob ip=192.0.2.44",
        ]

        result = analyze_lines(lines, suspicious_threshold=3)

        self.assertEqual(result.failed_by_ip["203.0.113.10"], 3)
        self.assertNotIn("192.0.2.44", result.suspicious_ips)
        self.assertEqual(result.suspicious_ips, ["203.0.113.10"])

    def test_malformed_lines_are_counted(self):
        analyze_lines = self._analyzer()
        lines = [
            "2026-10-01T10:00:00+00:00 login_success user=bob ip=198.51.100.7",
            "not an authentication record",
            "2026-10-01T10:01:00+00:00 login_failed user=alice ip=not-an-ip",
        ]

        result = analyze_lines(lines)

        self.assertEqual(result.total_entries, 1)
        self.assertEqual(result.malformed_lines, 2)

    def test_suspicious_ips_are_sorted(self):
        analyze_lines = self._analyzer()
        lines = [
            "2026-10-01T10:00:00+00:00 login_failed user=alice ip=203.0.113.10",
            "2026-10-01T10:01:00+00:00 login_failed user=alice ip=203.0.113.10",
            "2026-10-01T10:02:00+00:00 login_failed user=alice ip=203.0.113.10",
            "2026-10-01T10:03:00+00:00 login_failed user=bob ip=192.0.2.44",
            "2026-10-01T10:04:00+00:00 login_failed user=bob ip=192.0.2.44",
            "2026-10-01T10:05:00+00:00 login_failed user=bob ip=192.0.2.44",
        ]

        result = analyze_lines(lines)

        self.assertEqual(result.suspicious_ips, ["192.0.2.44", "203.0.113.10"])

    def test_invalid_threshold_is_rejected(self):
        analyze_lines = self._analyzer()

        with self.assertRaises(ValueError):
            analyze_lines([], suspicious_threshold=0)


if __name__ == "__main__":
    unittest.main()
