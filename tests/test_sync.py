"""Testes de sincronizacao local (src/sync.py)."""

from __future__ import annotations

import os
import tempfile
import unittest

from src import storage, sync
from src.crypto import derivar_chave
from src.models import PasswordEntry, Vault

CHAVE = derivar_chave("senha123", b"0" * 16)


class BaseSync(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._cwd = os.getcwd()
        os.chdir(self._tmp.name)
        self.addCleanup(os.chdir, self._cwd)
        self.addCleanup(storage.definir_namespace, "")
        self.destino = os.path.join(self._tmp.name, "nuvem")
        self.criar_cofre()

    def criar_cofre(self) -> None:
        with open(storage.ARQUIVO_SALT, "wb") as f:
            f.write(b"s" * 16)
        with open(storage.ARQUIVO_HASH, "wb") as f:
            f.write(b"h" * 32)
        vault = Vault()
        vault.add(PasswordEntry("github.com", "user", "segredo"))
        storage.save_vault(vault, CHAVE)


class TestSync(BaseSync):
    def test_push_copia_arquivos(self) -> None:
        copiados = sync.sincronizar(self.destino)
        self.assertEqual(len(copiados), 3)
        for nome in copiados:
            self.assertTrue(os.path.exists(os.path.join(self.destino, nome)))

    def test_push_cria_pasta(self) -> None:
        sync.sincronizar(os.path.join(self.destino, "sub", "dir"))
        self.assertTrue(os.path.isdir(os.path.join(self.destino, "sub", "dir")))

    def test_pull_substitui_local(self) -> None:
        sync.sincronizar(self.destino)
        storage.save_vault(Vault(), CHAVE)  # local fica vazio
        self.assertEqual(len(storage.load_vault(CHAVE)), 0)

        substituidos = sync.puxar(self.destino, CHAVE)
        self.assertIn(storage.ARQUIVO_VAULT, substituidos)
        self.assertEqual(len(storage.load_vault(CHAVE)), 1)

    def test_pull_nao_destroi_em_chave_errada(self) -> None:
        sync.sincronizar(self.destino)
        chave_errada = derivar_chave("outra", b"1" * 16)
        with self.assertRaises(storage.VaultCorrompido):
            sync.puxar(self.destino, chave_errada)
        # cofre local intacto
        self.assertEqual(len(storage.load_vault(CHAVE)), 1)

    def test_pull_sem_arquivo(self) -> None:
        with self.assertRaises(FileNotFoundError):
            sync.puxar(self.destino, CHAVE)

    def test_pull_gera_backup(self) -> None:
        sync.sincronizar(self.destino)
        sync.puxar(self.destino, CHAVE)
        backups = [n for n in os.listdir(".") if n.startswith(storage.PREFIXO_BACKUP)]
        self.assertTrue(backups)

    def test_namespace_propaga_nomes(self) -> None:
        storage.definir_namespace("pessoal")
        self.criar_cofre()
        copiados = sync.sincronizar(self.destino)
        self.assertIn("dados.pessoal.enc", copiados)
        self.assertIn("salt.pessoal.bin", copiados)


if __name__ == "__main__":
    unittest.main()
