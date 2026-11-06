"""Testes da GUI (apenas helpers puros, sem abrir janela)."""

from __future__ import annotations

import unittest

from src.gui import linhas_tabela
from src.models import PasswordEntry, Vault


class TestGUI(unittest.TestCase):
    def setUp(self) -> None:
        self.vault = Vault()

    def test_linhas_tabela_vazia(self) -> None:
        self.assertEqual(linhas_tabela(self.vault), [])

    def test_linhas_tabela_mascara_senha(self) -> None:
        self.vault.add(
            PasswordEntry(
                site="github.com", username="user", password="segredo",
                category="trabalho", notes="conta",
            )
        )
        linhas = linhas_tabela(self.vault)
        self.assertEqual(len(linhas), 1)
        id_curto, site, usuario, senha, categoria, notas = linhas[0]
        self.assertEqual(len(id_curto), 8)
        self.assertEqual(site, "github.com")
        self.assertEqual(usuario, "user")
        self.assertEqual(senha, "***")
        self.assertNotIn("segredo", str(linhas))
        self.assertEqual(categoria, "trabalho")
        self.assertEqual(notas, "conta")

    def test_linhas_tabela_ordem(self) -> None:
        self.vault.add(PasswordEntry(site="a.com", username="u1", password="p"))
        self.vault.add(PasswordEntry(site="b.com", username="u2", password="p"))
        sites = [linha[1] for linha in linhas_tabela(self.vault)]
        self.assertEqual(sites, ["a.com", "b.com"])


if __name__ == "__main__":
    unittest.main()
