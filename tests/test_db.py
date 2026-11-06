"""Testes do backend SQLite (src/db.py)."""

from __future__ import annotations

import os
import tempfile
import unittest

from src import db, storage
from src.crypto import derivar_chave
from src.models import PasswordEntry, Vault

CHAVE = derivar_chave("senha123", b"0" * 16)


class BaseDB(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)
        self.addCleanup(os.chdir, self._cwd)
        self.addCleanup(storage.definir_namespace, "")

    def test_init_cria_arquivo(self) -> None:
        db.init_vault_sql(CHAVE)
        self.assertTrue(os.path.exists(storage.ARQUIVO_VAULT))

    def test_roundtrip(self) -> None:
        vault = Vault()
        vault.add(
            PasswordEntry(
                site="github.com", username="user", password="s3nh4",
                notes="conta", category="trabalho",
            )
        )
        db.save_vault_sql(vault, CHAVE)
        carregado = db.load_vault_sql(CHAVE)
        self.assertEqual(len(carregado), 1)
        entrada = carregado.list_all()[0]
        self.assertEqual(entrada.site, "github.com")
        self.assertEqual(entrada.password, "s3nh4")
        self.assertEqual(entrada.category, "trabalho")
        self.assertEqual(entrada.notes, "conta")

    def test_indices_reconstruidos(self) -> None:
        vault = Vault()
        vault.add(PasswordEntry("a.com", "user", "p", category="cat"))
        db.save_vault_sql(vault, CHAVE)
        carregado = db.load_vault_sql(CHAVE)
        self.assertEqual(len(carregado.search("cat")), 1)
        self.assertEqual(len(carregado.search("a.com")), 1)

    def test_chave_errada(self) -> None:
        db.init_vault_sql(CHAVE)
        with self.assertRaises(storage.VaultCorrompido):
            db.load_vault_sql(derivar_chave("outra", b"1" * 16))

    def test_arquivo_ausente(self) -> None:
        with self.assertRaises(storage.VaultCorrompido):
            db.load_vault_sql(CHAVE)

    def test_arquivo_corrompido(self) -> None:
        db.init_vault_sql(CHAVE)
        with open(storage.ARQUIVO_VAULT, "r+b") as f:
            f.seek(5)
            f.write(b"\x00\xff")
        with self.assertRaises(storage.VaultCorrompido):
            db.load_vault_sql(CHAVE)

    def test_sobrescreve_conteudo_anterior(self) -> None:
        vault = Vault()
        vault.add(PasswordEntry("a.com", "u", "p"))
        db.save_vault_sql(vault, CHAVE)
        db.save_vault_sql(Vault(), CHAVE)
        self.assertEqual(len(db.load_vault_sql(CHAVE)), 0)

    def test_namespace(self) -> None:
        storage.definir_namespace("trabalho")
        db.init_vault_sql(CHAVE)
        self.assertTrue(os.path.exists("dados.trabalho.enc"))


if __name__ == "__main__":
    unittest.main()
