"""Testes da CLI (argparse)."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import unittest
from io import StringIO
from unittest import mock

from src.cli import build_parser, cmd_generate


class TestCLI(unittest.TestCase):
    def test_parser_build(self) -> None:
        parser = build_parser()
        self.assertIsInstance(parser, argparse.ArgumentParser)

    def test_parser_add_requires_site(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["add", "--username", "user"])

    def test_parser_add_requires_username(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["add", "--site", "github.com"])

    def test_parser_add_parses_args(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["add", "--site", "github.com", "--username", "user", "--notes", "nota"]
        )
        self.assertEqual(args.site, "github.com")
        self.assertEqual(args.username, "user")
        self.assertEqual(args.notes, "nota")
        self.assertIsNone(args.password)

    def test_parser_list_no_args(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["list"])
        self.assertEqual(args.command, "list")

    def test_parser_search_with_termo(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["search", "github"])
        self.assertEqual(args.termo, "github")

    def test_parser_search_no_termo(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["search"])
        self.assertEqual(args.termo, "")

    def test_parser_generate(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["generate"])
        self.assertEqual(args.command, "generate")

    def test_cmd_generate_runs(self) -> None:
        buf = StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            mock.patch("src.main.limpar_tela").start()
            mock.patch("src.main.pausar").start()
            cmd_generate(argparse.Namespace())
        finally:
            sys.stdout = old
            mock.patch.stopall()
        self.assertIn("chars", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
