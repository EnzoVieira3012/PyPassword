"""Testes da CLI (argparse)."""

from __future__ import annotations

import argparse
import argparse
import os
import sys
import tempfile
import unittest
from io import StringIO
from unittest import mock

import src.storage as storage
from src.cli import (
    build_parser,
    cmd_add,
    cmd_generate,
    cmd_list,
    cmd_qr,
    cmd_search,
    cmd_sync,
    cmd_vaults,
    main as cli_main,
)
from src.models import PasswordEntry, Vault


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

    def test_parser_add_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["add", "--site", "github.com", "--username", "u", "--category", "trabalho"]
        )
        self.assertEqual(args.category, "trabalho")

    def test_parser_add_category_default(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["add", "--site", "s", "--username", "u"])
        self.assertEqual(args.category, "")

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


def _capturar(funcao: object, *args: object) -> str:
    buf = StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        funcao(*args)  # type: ignore[operator]
    finally:
        sys.stdout = old
    return buf.getvalue()


class TestCLIComandos(unittest.TestCase):
    """Comandos com autenticação mockada — sem disco, sem getpass."""

    def _vault(self) -> Vault:
        vault = Vault()
        vault.add(
            PasswordEntry(
                site="github.com",
                username="user",
                password="senha123",
                category="dev",
            )
        )
        return vault

    def test_cmd_add(self) -> None:
        args = argparse.Namespace(
            site="github.com", username="user", password="senha123", notes="", category=""
        )
        with mock.patch("src.cli._autenticar", return_value=(b"k" * 32, Vault())):
            with mock.patch("src.cli.save_vault") as salvar:
                saida = _capturar(cmd_add, args)
        salvar.assert_called_once()
        self.assertIn("sucesso", saida)

    def test_cmd_add_invalido(self) -> None:
        args = argparse.Namespace(site="", username="", password="", notes="", category="")
        with mock.patch("src.cli._autenticar", return_value=(b"k" * 32, Vault())):
            with mock.patch("src.cli.save_vault") as salvar:
                saida = _capturar(cmd_add, args)
        salvar.assert_not_called()
        self.assertIn("Erro:", saida)

    def test_cmd_add_sem_auth(self) -> None:
        with mock.patch("src.cli._autenticar", return_value=None):
            self.assertEqual(_capturar(cmd_add, argparse.Namespace()), "")

    def test_cmd_list(self) -> None:
        with mock.patch("src.cli._autenticar", return_value=(b"k" * 32, self._vault())):
            with mock.patch("src.cli.fluxo_listar") as listar:
                _capturar(cmd_list, argparse.Namespace())
        listar.assert_called_once()

    def test_cmd_search(self) -> None:
        with mock.patch("src.cli._autenticar", return_value=(b"k" * 32, self._vault())):
            with mock.patch("src.cli.fluxo_buscar") as buscar:
                _capturar(cmd_search, argparse.Namespace(termo="git"))
        buscar.assert_called_once()

    def test_cmd_qr_mostra(self) -> None:
        vault = self._vault()
        entrada = next(iter(vault))
        args = argparse.Namespace(id=str(entrada.id)[:8])
        with mock.patch("src.cli._autenticar", return_value=(b"k" * 32, vault)):
            with mock.patch("src.cli.mostrar_qr") as qr:
                _capturar(cmd_qr, args)
        qr.assert_called_once()

    def test_cmd_qr_nao_encontrado(self) -> None:
        args = argparse.Namespace(id="naoexiste")
        with mock.patch("src.cli._autenticar", return_value=(b"k" * 32, Vault())):
            with mock.patch("src.cli.mostrar_qr") as qr:
                saida = _capturar(cmd_qr, args)
        qr.assert_not_called()
        self.assertIn("nao encontrada", saida)

    def test_cmd_sync_push(self) -> None:
        with mock.patch("src.cli.sync_push", return_value=["dados.enc"]):
            saida = _capturar(cmd_sync, argparse.Namespace(destino="D", pull=False))
        self.assertIn("dados.enc", saida)

    def test_cmd_sync_pull(self) -> None:
        with mock.patch("src.cli._autenticar", return_value=(b"k" * 32, Vault())):
            with mock.patch("src.cli.sync_puxar", return_value=["dados.enc"]):
                saida = _capturar(cmd_sync, argparse.Namespace(destino="D", pull=True))
        self.assertIn("Puxado", saida)

    def test_cmd_sync_pull_corrompido(self) -> None:
        with mock.patch("src.cli._autenticar", return_value=(b"k" * 32, Vault())):
            with mock.patch(
                "src.cli.sync_puxar", side_effect=storage.VaultCorrompido("x")
            ):
                saida = _capturar(cmd_sync, argparse.Namespace(destino="D", pull=True))
        self.assertIn("Falha no pull", saida)

    def test_cmd_vaults_vazio(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            antigo = os.getcwd()
            os.chdir(tmp)
            try:
                saida = _capturar(cmd_vaults, argparse.Namespace())
            finally:
                os.chdir(antigo)
        self.assertIn("Nenhum vault", saida)

    def test_cmd_vaults_lista(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for nome in ("dados.enc", "dados.trabalho.enc", "dados.enc.bak.1"):
                open(os.path.join(tmp, nome), "wb").close()
            antigo = os.getcwd()
            os.chdir(tmp)
            try:
                saida = _capturar(cmd_vaults, argparse.Namespace())
            finally:
                os.chdir(antigo)
        self.assertIn("(padrao)", saida)
        self.assertIn("trabalho", saida)
        self.assertNotIn("bak", saida)

    def test_main_dispatch(self) -> None:
        with mock.patch.object(sys, "argv", ["pytask", "list"]):
            with mock.patch("src.cli.cmd_list") as listar:
                cli_main()
        listar.assert_called_once()

    def test_main_sem_comando(self) -> None:
        with mock.patch.object(sys, "argv", ["pytask"]):
            with self.assertRaises(SystemExit):
                cli_main()


if __name__ == "__main__":
    unittest.main()
