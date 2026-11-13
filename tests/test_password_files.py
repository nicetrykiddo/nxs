"""Regression tests for literal password-file parsing."""
import tempfile
import unittest
from pathlib import Path

from nxs.cli import read_file_or_value, resolve_credentials


class PasswordFileParsingTests(unittest.TestCase):
    def test_hash_prefix_is_not_a_password_comment(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "passwords.txt"
            path.write_text("##123a8j8w5123##\n123\n$hadoW\n", encoding="utf-8")
            self.assertEqual(
                read_file_or_value(str(path), password_file=True),
                ["##123a8j8w5123##", "123", "$hadoW"],
            )

    def test_combo_includes_every_password(self):
        with tempfile.TemporaryDirectory() as directory:
            users = Path(directory) / "users.txt"
            passwords = Path(directory) / "passwords.txt"
            users.write_text("alice\nbob\n", encoding="utf-8")
            passwords.write_text("##123a8j8w5123##\n123\n", encoding="utf-8")
            pairs = resolve_credentials(str(users), str(passwords), None, None, None, combo=True)
            self.assertEqual(len(pairs), 4)
            self.assertIn(("alice", "##123a8j8w5123##"), [(c.user, c.password) for c in pairs])
            self.assertIn(("bob", "##123a8j8w5123##"), [(c.user, c.password) for c in pairs])

    def test_password_whitespace_is_literal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "passwords.txt"
            path.write_text(" #notacomment \n\npass\n", encoding="utf-8")
            self.assertEqual(read_file_or_value(str(path), password_file=True), [" #notacomment ", "pass"])

    def test_username_comment_behavior_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "users.txt"
            path.write_text("# ignored\nalice\n", encoding="utf-8")
            self.assertEqual(read_file_or_value(str(path)), ["alice"])


if __name__ == "__main__":
    unittest.main()
