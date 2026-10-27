import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from cybersecurity_log_analyzer import cli


class CliTests(unittest.TestCase):
    def _main(self):
        self.assertTrue(hasattr(cli, "main"))
        return cli.main

    def test_sample_input_emits_json_report(self):
        main = self._main()
        sample = "\n".join(
            [
                "2026-10-01T10:00:00+00:00 login_failed user=alice ip=203.0.113.10",
                "2026-10-01T10:01:00+00:00 login_success user=bob ip=198.51.100.7",
                "2026-10-01T10:02:00+00:00 login_failed user=alice ip=203.0.113.10",
                "2026-10-01T10:03:00+00:00 login_failed user=alice ip=203.0.113.10",
            ]
        )

        with TemporaryDirectory() as directory:
            input_path = Path(directory) / "auth.log"
            input_path.write_text(sample, encoding="utf-8")
            stdout = StringIO()

            with redirect_stdout(stdout):
                exit_code = main([str(input_path), "--threshold", "3"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["failed_attempts"], 3)
        self.assertEqual(payload["successful_logins"], 1)
        self.assertEqual(payload["suspicious_ips"], ["203.0.113.10"])

    def test_cli_reports_missing_file(self):
        main = self._main()
        stderr = StringIO()

        with redirect_stderr(stderr):
            exit_code = main(["does-not-exist.log"])

        self.assertEqual(exit_code, 2)
        self.assertIn("Input file not found", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
