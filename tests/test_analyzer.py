import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from ssh_config_check import analyzer
from ssh_config_check.analyzer import analyze, read_input
from ssh_config_check.cli import DEMO, main, terminal_safe


def finding(result, name):
    return next(x for x in result["findings"] if x["check"] == name and x["value"] is not None)


class AnalyzerTests(unittest.TestCase):
    def test_demo_flags_review_items_and_keeps_mfa_context(self):
        result = analyze(DEMO)
        self.assertEqual(finding(result, "permitrootlogin")["status"], "WARN")
        self.assertEqual(finding(result, "passwordauthentication")["status"], "WARN")
        self.assertEqual(finding(result, "kbdinteractiveauthentication")["status"], "INFO")
        self.assertIn("MFA", finding(result, "passwordauthentication")["explanation"])

    def test_explicit_restrictive_values_are_info_not_pass(self):
        result = analyze(DEMO.replace("PermitRootLogin yes", "PermitRootLogin no").replace("PasswordAuthentication yes", "PasswordAuthentication no"))
        self.assertEqual(result["summary"], {"INFO": 7})
        self.assertEqual(result["coverage"], "partial")

    def test_first_value_wins_case_insensitive_keyword_and_line_number(self):
        result = analyze('pErMiTrOoTlOgIn "yes" # reason\nPermitRootLogin no')
        item = finding(result, "permitrootlogin")
        self.assertEqual((item["value"], item["line"]), ("yes", 1))
        self.assertEqual(finding(result, "duplicate")["status"], "INFO")

    def test_missing_values_do_not_assume_defaults(self):
        result = analyze("# empty fixture\n")
        self.assertEqual(result["summary"], {"UNKNOWN": 7})

    def test_include_does_not_read_any_additional_file(self):
        with patch("pathlib.Path.open", side_effect=AssertionError("Unexpected file access")):
            result = analyze("Include /tmp/*.conf\nPermitRootLogin no")
        self.assertEqual(finding(result, "include")["status"], "UNKNOWN")
        self.assertEqual(finding(result, "permitrootlogin")["value"], "no")

    def test_match_and_match_all_are_not_global(self):
        result = analyze("PermitRootLogin no\nMatch User demo\nPermitRootLogin yes\nMatch all\nPasswordAuthentication yes")
        self.assertEqual(finding(result, "permitrootlogin")["value"], "no")
        self.assertEqual(sum(x["check"] == "match" for x in result["findings"]), 2)
        self.assertFalse(any(x["check"] == "passwordauthentication" and x["value"] for x in result["findings"]))

    def test_invalid_first_value_not_hidden_by_later_valid_value(self):
        result = analyze("PermitRootLogin typo\nPermitRootLogin no")
        self.assertTrue(any(x["check"] == "permitrootlogin" and x["status"] == "UNKNOWN" for x in result["findings"]))
        self.assertFalse(any(x["check"] == "permitrootlogin" and x["status"] == "INFO" for x in result["findings"]))

    def test_invalid_syntax_and_controls_are_incomplete(self):
        for text in ('PermitRootLogin "yes', "PermitRootLogin yes no", "PermitRootLogin yes\x1b[31m", "PermitRootLogin yes\x00"):
            with self.subTest(text=text):
                self.assertGreater(analyze(text)["summary"].get("UNKNOWN", 0), 0)

    def test_case_sensitive_values_and_unassessed_directives(self):
        result = analyze("PermitRootLogin YES\nAllowUsers alice bob")
        self.assertIn("allowusers", result["unassessed_directives"])
        self.assertGreater(result["summary"]["UNKNOWN"], 0)

    def test_root_restriction_variants(self):
        for value in ("prohibit-password", "without-password", "forced-commands-only", "no"):
            with self.subTest(value=value):
                self.assertEqual(finding(analyze("PermitRootLogin " + value), "permitrootlogin")["status"], "INFO")

    def test_shell_quoting_and_control_line_breaks_are_not_normalized(self):
        for text in ("PermitRootLogin 'no'", "PermitRootLogin n\\o", "PermitRootLogin no\vPasswordAuthentication no"):
            with self.subTest(text=text):
                result = analyze(text)
                self.assertFalse(any(x["check"] == "permitrootlogin" and x["status"] == "INFO" for x in result["findings"]))
        self.assertEqual(finding(analyze('PermitRootLogin "no"\r\n'), "permitrootlogin")["value"], "no")

    def test_all_review_rules(self):
        for directive, value in (("PermitEmptyPasswords", "yes"), ("PubkeyAuthentication", "no"), ("StrictModes", "no"), ("LogLevel", "QUIET"), ("LogLevel", "DEBUG3")):
            with self.subTest(directive=directive, value=value):
                self.assertEqual(finding(analyze(directive + " " + value), directive.lower())["status"], "WARN")

    def test_effective_output_duplicate_is_unknown(self):
        result = analyze(DEMO + "\nPermitRootLogin no", effective=True)
        self.assertEqual(result["mode"], "effective-output")
        self.assertEqual(finding(result, "duplicate")["status"], "UNKNOWN")

    def test_size_encoding_and_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config"
            path.write_bytes(b"\xff")
            with self.assertRaises(UnicodeError):
                read_input(path)
            path.write_bytes(b"x" * (analyzer.MAX_BYTES + 1))
            with self.assertRaises(ValueError):
                read_input(path)
            with self.assertRaises(ValueError):
                analyze("x" * (analyzer.MAX_BYTES + 1))
            with self.assertRaises(OSError):
                read_input(Path(tmp) / "missing")

    def test_empty_password_and_disabled_keys_never_become_pass(self):
        result = analyze("PermitEmptyPasswords yes\nPubkeyAuthentication no")
        self.assertEqual(finding(result, "permitemptypasswords")["status"], "WARN")
        self.assertNotIn("PASS", result["summary"])


class CliTests(unittest.TestCase):
    def test_demo_json_is_single_document_and_never_reads_host(self):
        with patch("ssh_config_check.cli.read_input", side_effect=AssertionError("Host read")), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main(["--demo", "--format", "json"]), 0)
        self.assertTrue(json.loads(out.getvalue())["demo"])

    def test_strict_exit_codes(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--demo", "--strict"]), 1)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config"
            for text, code in (("", 2), (DEMO.replace("PermitRootLogin yes", "PermitRootLogin no").replace("PasswordAuthentication yes", "PasswordAuthentication no"), 0)):
                path.write_text(text)
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["--config", str(path), "--strict"]), code)

    def test_effective_file_json_source_and_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "effective.txt"
            path.write_text(DEMO)
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(main(["--effective", str(path), "--format", "json"]), 0)
        result = json.loads(out.getvalue())
        self.assertEqual(result["source"], str(path))
        self.assertEqual(result["mode"], "effective-output")

    def test_missing_file_no_traceback(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(main(["--config", "/missing/config"]), 2)
        self.assertIn("Cannot analyze input", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())

    def test_sources_are_required_and_mutually_exclusive(self):
        for args in ([], ["--demo", "--config", "x"], ["--effective", "a", "--config", "b"]):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(args)

    def test_terminal_control_escape(self):
        self.assertEqual(terminal_safe("x\x1b\ny"), "x\\x1b\\x0ay")
        with patch("ssh_config_check.cli.read_input", return_value="PermitRootLogin yes"), contextlib.redirect_stdout(io.StringIO()) as out:
            main(["--config", "bad\x1bname"])
        self.assertNotIn("\x1b", out.getvalue())


if __name__ == "__main__":
    unittest.main()
