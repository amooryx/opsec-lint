import contextlib
import io
from pathlib import Path
import tempfile
import unittest

import opsec_lint


class PrivateKeyLintTests(unittest.TestCase):
    def run_file(self, content: bytes) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "plan.txt"
            source.write_bytes(content)
            args = opsec_lint.build_parser().parse_args([str(source), "-y"])
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = opsec_lint.run(args)
            return status, stdout.getvalue(), stderr.getvalue()

    def test_reports_supported_private_key_headers_and_line_number(self) -> None:
        status, stdout, _ = self.run_file(
            b"Engagement notes\n  -----BEGIN RSA PRIVATE KEY----- \nredacted\n"
        )
        self.assertEqual(status, 1)
        self.assertIn("plan.txt:2: private-key PEM header found", stdout)
        self.assertNotIn("redacted", stdout)

    def test_reports_pkcs8_and_encrypted_key_headers(self) -> None:
        status, stdout, _ = self.run_file(
            b"-----BEGIN PRIVATE KEY-----\n"
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
            b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
        )
        self.assertEqual(status, 1)
        self.assertEqual(stdout.count("private-key PEM header found"), 3)

    def test_accepts_utf8_bom(self) -> None:
        status, stdout, _ = self.run_file(
            b"\xef\xbb\xbf-----BEGIN PRIVATE KEY-----\n"
        )
        self.assertEqual(status, 1)
        self.assertIn("plan.txt:1: private-key PEM header found", stdout)

    def test_ignores_mentions_that_are_not_exact_header_lines(self) -> None:
        status, stdout, _ = self.run_file(
            b"Do not include a private key\n"
            b"Example: -----BEGIN PRIVATE KEY-----\n"
            b"-----BEGIN CERTIFICATE-----\n"
        )
        self.assertEqual(status, 0)
        self.assertIn("No private-key PEM headers found.", stdout)

    def test_writes_findings_to_requested_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "plan.txt"
            output = Path(directory) / "findings.txt"
            source.write_bytes(b"-----BEGIN EC PRIVATE KEY-----\n")
            args = opsec_lint.build_parser().parse_args(
                [str(source), "-y", "--output", str(output)]
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = opsec_lint.run(args)
            self.assertEqual(status, 1)
            self.assertIn("results written", stdout.getvalue())
            self.assertIn("plan.txt:1: private-key PEM header found", output.read_text())
            self.assertEqual(stderr.getvalue(), "")

    def test_rejects_oversized_and_non_utf8_input(self) -> None:
        oversized_status, _, oversized_error = self.run_file(
            b"x" * (opsec_lint.MAX_INPUT_BYTES + 1)
        )
        invalid_status, _, invalid_error = self.run_file(b"\xff")
        self.assertEqual(oversized_status, 2)
        self.assertIn("exceeds", oversized_error)
        self.assertEqual(invalid_status, 2)
        self.assertIn("valid UTF-8", invalid_error)

    def test_refuses_to_overwrite_input_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "plan.txt"
            source.write_text("-----BEGIN PRIVATE KEY-----\n", encoding="utf-8")
            args = opsec_lint.build_parser().parse_args(
                [str(source), "-y", "--output", str(source)]
            )
            stderr = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
                status = opsec_lint.run(args)
            self.assertEqual(status, 2)
            self.assertIn("must not be the input file", stderr.getvalue())
            self.assertEqual(
                source.read_text(encoding="utf-8"), "-----BEGIN PRIVATE KEY-----\n"
            )

    def test_preserves_scaffold_for_non_file_targets(self) -> None:
        args = opsec_lint.build_parser().parse_args(["scope-id", "-y"])
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = opsec_lint.run(args)
        self.assertEqual(status, 0)
        self.assertIn("scaffold ready", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
