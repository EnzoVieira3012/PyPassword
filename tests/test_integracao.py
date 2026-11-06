"""Testes de integracao end-to-end do PyTask (unittest)."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from io import StringIO
from unittest import mock
from datetime import timedelta, timezone, datetime
from typing import cast

from src.main import (
    primeira_execucao,
    autenticar,
    fluxo_cadastrar,
    fluxo_listar,
    fluxo_buscar,
    fluxo_editar,
    fluxo_excluir,
    fluxo_gerar_senha,
)
from src.models import Vault
from src.storage import load_vault


class Saida(str):
    valor: object = None


def rodar(
    funcao: object,
    *args: object,
    entradas: list[str] | None = None,
    senhas: list[str] | None = None,
) -> Saida:
    buffer = StringIO()
    old_stdout = sys.stdout
    sys.stdout = buffer
    patchers = []
    try:
        if senhas is not None:
            it_s = iter(senhas)
            p = mock.patch("src.main.getpass.getpass", side_effect=lambda prompt="": next(it_s))
            p.start()
            patchers.append(p)
        if entradas is not None:
            it_e = iter(entradas)
            p = mock.patch("builtins.input", side_effect=lambda prompt="": next(it_e))
            p.start()
            patchers.append(p)
        resultado = funcao(*args)
        saida = Saida(buffer.getvalue())
        saida.valor = resultado
        return saida
    finally:
        sys.stdout = old_stdout
        for p in patchers:
            p.stop()


class BaseIntegracao(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.orig_cwd = os.getcwd()
        os.chdir(self.tmpdir.name)
        self.addCleanup(os.chdir, self.orig_cwd)
        self.patchers = [
            mock.patch("src.main.limpar_tela"),
            mock.patch("src.main.pausar"),
            mock.patch("src.main.sys.exit", side_effect=lambda code: None),
        ]
        for p in self.patchers:
            p.start()
        self.addCleanup(mock.patch.stopall)

    def criar_cofre(self, senha: str = "SenhaMestra123!") -> bytes:
        saida = rodar(primeira_execucao, senhas=[senha, senha])
        self.assertIsInstance(saida.valor, bytes)
        return cast(bytes, saida.valor)


class TestIntegracaoCompleta(BaseIntegracao):
    def test_primeira_execucao_cria_arquivos(self) -> None:
        chave = self.criar_cofre()
        self.assertTrue(os.path.exists("salt.bin"))
        self.assertTrue(os.path.exists("hash.bin"))
        self.assertTrue(os.path.exists("dados.enc"))
        self.assertEqual(len(chave), 64)

    def test_autenticar_sucesso(self) -> None:
        senha = "SenhaMestra123!"
        self.criar_cofre(senha)
        saida = rodar(autenticar, senhas=[senha])
        self.assertIsInstance(saida.valor, bytes)
        self.assertEqual(len(saida.valor), 64)  # type: ignore[arg-type]

    def test_autenticar_falha_3_tentativas(self) -> None:
        self.criar_cofre()
        saida = rodar(autenticar, senhas=["errada", "errada", "errada"])
        self.assertIsNone(saida.valor)

    def test_fluxo_cadastrar_valido(self) -> None:
        chave = self.criar_cofre()
        vault = load_vault(chave)
        rodar(fluxo_cadastrar, vault, chave,
              entradas=["github.com", "usuario", "Nota teste"],
              senhas=["SenhaForte123!"])
        self.assertEqual(len(vault), 1)
        entrada = vault.list_all()[0]
        self.assertEqual(entrada.site, "github.com")
        self.assertEqual(entrada.username, "usuario")
        self.assertEqual(entrada.notes, "Nota teste")

    def test_fluxo_cadastrar_campo_vazio(self) -> None:
        chave = self.criar_cofre()
        vault = load_vault(chave)
        saida = rodar(fluxo_cadastrar, vault, chave,
                      entradas=["", "usuario", "nota"],
                      senhas=["SenhaForte123!"])
        self.assertEqual(len(vault), 0)
        self.assertIn("obrigatório", saida.lower())

    def test_fluxo_listar_mostra_tabela(self) -> None:
        chave = self.criar_cofre()
        vault = load_vault(chave)
        rodar(fluxo_cadastrar, vault, chave,
              entradas=["teste.com", "user", ""],
              senhas=["senha"])
        saida = rodar(fluxo_listar, vault)
        self.assertIn("teste.com", saida)
        self.assertIn("user", saida)
        self.assertIn("***", saida)

    def test_fluxo_buscar_encontrado(self) -> None:
        chave = self.criar_cofre()
        vault = load_vault(chave)
        rodar(fluxo_cadastrar, vault, chave,
              entradas=["github.com", "user", ""],
              senhas=["senha123"])
        saida = rodar(fluxo_buscar, vault,
                      entradas=["github", ""])
        self.assertIn("github.com", saida)

    def test_fluxo_editar_atualiza(self) -> None:
        chave = self.criar_cofre()
        vault = load_vault(chave)
        rodar(fluxo_cadastrar, vault, chave,
              entradas=["site.com", "user", "nota"],
              senhas=["senha"])
        entrada = vault.list_all()[0]
        entrada.updated_at = datetime.now(timezone.utc) - timedelta(days=1)
        prefixo = str(entrada.id)[:8]
        saida = rodar(fluxo_editar, vault, chave,
                      entradas=[prefixo, "novo-site.com", "", "atualizada", ""],
                      senhas=[""])
        atualizada = vault.get(entrada.id)
        self.assertEqual(atualizada.site, "novo-site.com")
        self.assertEqual(atualizada.username, "user")

    def test_fluxo_excluir_dupla_confirmacao(self) -> None:
        chave = self.criar_cofre()
        vault = load_vault(chave)
        rodar(fluxo_cadastrar, vault, chave,
              entradas=["site.com", "user", ""],
              senhas=["senha"])
        entrada = vault.list_all()[0]
        prefixo = str(entrada.id)[:8]
        rodar(fluxo_excluir, vault, chave,
              entradas=[prefixo, "CONFIRMO", "CONFIRMO"])
        self.assertEqual(len(vault), 0)

    def test_fluxo_excluir_cancelado(self) -> None:
        chave = self.criar_cofre()
        vault = load_vault(chave)
        rodar(fluxo_cadastrar, vault, chave,
              entradas=["site.com", "user", ""],
              senhas=["senha"])
        entrada = vault.list_all()[0]
        prefixo = str(entrada.id)[:8]
        saida = rodar(fluxo_excluir, vault, chave,
                      entradas=[prefixo, "NAO"])
        self.assertEqual(len(vault), 1)
        self.assertIn("cancelada", saida.lower())

    def test_fluxo_gerar_senha_padrao(self) -> None:
        saida = rodar(fluxo_gerar_senha, entradas=[""])
        self.assertIn("16 chars", saida)

    def test_fluxo_gerar_senha_custom(self) -> None:
        saida = rodar(fluxo_gerar_senha, entradas=["20"])
        self.assertIn("20 chars", saida)

    def test_fluxo_completo_ciclo_vida(self) -> None:
        senha = "SenhaMestra123!"
        chave = self.criar_cofre(senha)
        vault = load_vault(chave)

        # cadastrar
        rodar(fluxo_cadastrar, vault, chave,
              entradas=["google.com", "meuuser", "conta principal"],
              senhas=["MinhaSenh@123"])
        self.assertEqual(len(vault), 1)

        # listar
        saida = rodar(fluxo_listar, vault)
        self.assertIn("google.com", saida)

        # buscar
        saida = rodar(fluxo_buscar, vault, entradas=["google", ""])
        self.assertIn("google.com", saida)

        # editar
        entrada = vault.list_all()[0]
        entrada.updated_at = datetime.now(timezone.utc) - timedelta(days=1)
        prefixo = str(entrada.id)[:8]
        rodar(fluxo_editar, vault, chave,
              entradas=[prefixo, "gmail.com", "", "atualizada", ""],
              senhas=["NovaSenh@456"])
        atualizada = vault.get(entrada.id)
        self.assertEqual(atualizada.site, "gmail.com")
        self.assertEqual(atualizada.password, "NovaSenh@456")
        self.assertEqual(atualizada.notes, "atualizada")

        # excluir
        prefixo = str(atualizada.id)[:8]
        rodar(fluxo_excluir, vault, chave,
              entradas=[prefixo, "CONFIRMO", "CONFIRMO"])
        self.assertEqual(len(vault), 0)

        # gerar senha
        saida = rodar(fluxo_gerar_senha, entradas=["32"])
        self.assertIn("32 chars", saida)


if __name__ == "__main__":
    unittest.main()
