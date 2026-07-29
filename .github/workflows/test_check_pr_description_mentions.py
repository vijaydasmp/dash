#!/usr/bin/env python3
# Copyright (c) 2026 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import importlib.util
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


SCRIPT_PATH = Path(__file__).with_name("check_pr_description_mentions.py")
SPEC = importlib.util.spec_from_file_location("check_pr_description_mentions", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
check_pr_description_mentions = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_pr_description_mentions)


class TestFindMentions(unittest.TestCase):
    def test_empty_body_has_no_mentions(self):
        self.assertEqual([], check_pr_description_mentions.find_mentions(""))

    def test_plain_text_without_at_has_no_mentions(self):
        body = "Explain the change and why.\n\n## Checklist\n- [x] tests"
        self.assertEqual([], check_pr_description_mentions.find_mentions(body))

    def test_email_addresses_are_allowed(self):
        body = (
            "Contact alice@example.com, bob.smith+ci@dash.org, "
            "or dev!@example.com for details."
        )
        self.assertEqual([], check_pr_description_mentions.find_mentions(body))

    def test_email_with_punctuation_boundaries_is_allowed(self):
        body = "Contact <dev!@example.com>; backup: (first.last@example.co.uk)."
        self.assertEqual([], check_pr_description_mentions.find_mentions(body))

    def test_single_username_mention_is_found(self):
        matches = check_pr_description_mentions.find_mentions("Thanks @knst for the review.")
        self.assertEqual([(1, "Thanks @knst for the review.", "@knst")], matches)

    def test_mention_after_period_is_found(self):
        matches = check_pr_description_mentions.find_mentions("Thanks.@knst")
        self.assertEqual([(1, "Thanks.@knst", "@knst")], matches)

    def test_mention_after_plus_is_found(self):
        matches = check_pr_description_mentions.find_mentions("cc +@knst")
        self.assertEqual([(1, "cc +@knst", "@knst")], matches)

    def test_mention_at_start_of_line(self):
        matches = check_pr_description_mentions.find_mentions("@PastaClaw requested this.")
        self.assertEqual([(1, "@PastaClaw requested this.", "@PastaClaw")], matches)

    def test_multiple_mentions_across_lines(self):
        body = "Ping @alice\nand also @bob-user later."
        matches = check_pr_description_mentions.find_mentions(body)
        self.assertEqual(
            [
                (1, "Ping @alice", "@alice"),
                (2, "and also @bob-user later.", "@bob-user"),
            ],
            matches,
        )

    def test_single_character_username(self):
        matches = check_pr_description_mentions.find_mentions("ask @a please")
        self.assertEqual([(1, "ask @a please", "@a")], matches)

    def test_username_with_internal_hyphen(self):
        matches = check_pr_description_mentions.find_mentions("cc @some-user-name")
        self.assertEqual([(1, "cc @some-user-name", "@some-user-name")], matches)

    def test_trailing_punctuation_does_not_break_match(self):
        matches = check_pr_description_mentions.find_mentions("See @reviewer.")
        self.assertEqual([(1, "See @reviewer.", "@reviewer")], matches)

    def test_github_url_without_at_is_allowed(self):
        body = "Discussed with https://github.com/knst in review."
        self.assertEqual([], check_pr_description_mentions.find_mentions(body))

    def test_email_and_mention_mixed(self):
        body = "Email dev@example.com and ping @maintainer"
        matches = check_pr_description_mentions.find_mentions(body)
        self.assertEqual(
            [(1, "Email dev@example.com and ping @maintainer", "@maintainer")],
            matches,
        )

    def test_mention_adjacent_to_email_is_found(self):
        body = "Email dev@example.com.@maintainer"
        matches = check_pr_description_mentions.find_mentions(body)
        self.assertEqual(
            [(1, "Email dev@example.com.@maintainer", "@maintainer")],
            matches,
        )

    def test_incomplete_email_is_not_exempted(self):
        body = "This is not a complete email: dev!@example"
        matches = check_pr_description_mentions.find_mentions(body)
        self.assertEqual(
            [(1, "This is not a complete email: dev!@example", "@example")],
            matches,
        )


class TestCheckBody(unittest.TestCase):
    def test_none_and_empty_pass(self):
        for body in (None, ""):
            with self.subTest(body=body):
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    code = check_pr_description_mentions.check_body(body)
                self.assertEqual(0, code)
                self.assertIn("empty", stdout.getvalue().lower())

    def test_clean_body_passes(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = check_pr_description_mentions.check_body(
                "No people tagged.\nContact team@example.com if needed."
            )
        self.assertEqual(0, code)
        self.assertIn("No @mentions found", stdout.getvalue())

    def test_body_with_mention_fails_and_prints_guidance(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = check_pr_description_mentions.check_body("cc @someone")
        self.assertEqual(1, code)
        self.assertIn("@someone", stdout.getvalue())
        self.assertIn("::error::PR description contains GitHub @mentions.", stderr.getvalue())
        self.assertIn("merge commits", stderr.getvalue())


class TestMain(unittest.TestCase):
    def test_main_reads_pr_body_env(self):
        with mock.patch.dict(os.environ, {"PR_BODY": "hello @user"}, clear=False):
            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                code = check_pr_description_mentions.main([])
        self.assertEqual(1, code)
        self.assertIn("@mentions", stderr.getvalue())

    def test_main_missing_pr_body_env_treated_as_empty(self):
        env = {k: v for k, v in os.environ.items() if k != "PR_BODY"}
        with mock.patch.dict(os.environ, env, clear=True):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = check_pr_description_mentions.main([])
        self.assertEqual(0, code)
        self.assertIn("empty", stdout.getvalue().lower())

    def test_main_body_file(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write("safe body with email only: a@b.co\n")
            path = handle.name
        try:
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = check_pr_description_mentions.main(["--body-file", path])
            self.assertEqual(0, code)
            self.assertIn("No @mentions found", stdout.getvalue())
        finally:
            os.unlink(path)

    def test_main_stdin(self):
        stdin = io.StringIO("@bad\n")
        with mock.patch.object(check_pr_description_mentions.sys, "stdin", stdin):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = check_pr_description_mentions.main(["--stdin"])
        self.assertEqual(1, code)


if __name__ == "__main__":
    unittest.main()
