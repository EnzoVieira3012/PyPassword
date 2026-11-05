"""Testes de storage.py. Rodar: python -m unittest -v test_storage"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import storage
from crypto import derivar_chave, encrypt_data
from models import PasswordEntry, Vault
from storage import (
    ARQUIVO_VAULT,
    VaultCorrompido,
    backup_vault,
    init_vault,
    load_vault,
    restore_vault,
    save_vault,
    vault_existe,
)

CHAVE = derivar_chave("senha mestra", b"1234567890123456")
OUTRA_CHAVE = derivar_chave("outra senha", b"1234567890123456")


class BaseStorage(unittest.TestCase):
    """Roda cada teste em um diretório temporário vazio."""

    def setUp(self) -> None:
        self._anterior = Path.cwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self) -> None:
        os.chdir(self._anterior)
        self._tmp.cleanup()

    @staticmethod
    def vault_com_entradas(quantidade: int = 3) -> Vault:
        vault = Vault()
        for i in range(quantidade):
            vault.add(PasswordEntry(f"site{i}", f"user{i}", f"senha{i}", "nota"))
        return vault


class TestVaultExiste(BaseStorage):
    def test_inexistente(self) -> None:
        self.assertFalse(vault_existe())

    def test_existente(self) -> None:
        Path(ARQUIVO_VAULT).write_bytes(b"qualquer coisa")
        self.assertTrue(vault_existe())

    def test_arquivo_vazio(self) -> None:
        Path(ARQUIVO_VAULT).touch()
        self.assertTrue(vault_existe())


class TestSaveInitLoad(BaseStorage):
    def test_init_vault(self) -> None:
        vault = init_vault(CHAVE)
        self.assertIsInstance(vault, Vault)
        self.assertEqual(len(vault), 0)
        self.assertTrue(vault_existe())
        self.assertEqual(len(load_vault(CHAVE)), 0)

    def test_roundtrip(self) -> None:
        original = self.vault_com_entradas(3)
        save_vault(original, CHAVE)
        carregado = load_vault(CHAVE)
        self.assertEqual(len(carregado), 3)
        self.assertEqual(
            [e.to_dict() for e in carregado], [e.to_dict() for e in original]
        )
        self.assertEqual(len(carregado.search("site1")), 1)

    def test_nao_deixa_temporario(self) -> None:
        save_vault(self.vault_com_entradas(1), CHAVE)
        self.assertEqual(Path(f"{ARQUIVO_VAULT}.tmp").exists(), False)

    def test_vault_grande(self) -> None:
        vault = self.vault_com_entradas(1000)
        save_vault(vault, CHAVE)
        self.assertEqual(len(load_vault(CHAVE)), 1000)

    def test_conteudo_nao_e_texto_puro(self) -> None:
        save_vault(self.vault_com_entradas(1), CHAVE)
        bruto = Path(ARQUIVO_VAULT).read_bytes()
        self.assertNotIn(b"site0", bruto)
        self.assertNotIn(b"senha0", bruto)

    def test_falha_ao_criptografar_preserva_arquivo_antigo(self) -> None:
        original = self.vault_com_entradas(2)
        save_vault(original, CHAVE)
        antes = Path(ARQUIVO_VAULT).read_bytes()
        with mock.patch.object(storage, "encrypt_data", side_effect=RuntimeError):
            with self.assertRaises(RuntimeError):
                save_vault(self.vault_com_entradas(5), CHAVE)
        self.assertEqual(Path(ARQUIVO_VAULT).read_bytes(), antes)
        self.assertFalse(Path(f"{ARQUIVO_VAULT}.tmp").exists())
        self.assertEqual(len(load_vault(CHAVE)), 2)

    def test_falha_de_io_faz_rollback(self) -> None:
        save_vault(self.vault_com_entradas(2), CHAVE)
        antes = Path(ARQUIVO_VAULT).read_bytes()
        with mock.patch.object(os, "replace", side_effect=OSError("disco")):
            with self.assertRaises(OSError):
                save_vault(self.vault_com_entradas(5), CHAVE)
        self.assertEqual(Path(ARQUIVO_VAULT).read_bytes(), antes)
        self.assertFalse(Path(f"{ARQUIVO_VAULT}.tmp").exists())


class TestLoadErros(BaseStorage):
    def test_arquivo_ausente(self) -> None:
        with self.assertRaises(FileNotFoundError):
            load_vault(CHAVE)

    def test_chave_errada(self) -> None:
        save_vault(self.vault_com_entradas(1), CHAVE)
        with self.assertRaises(VaultCorrompido):
            load_vault(OUTRA_CHAVE)

    def test_byte_adulterado(self) -> None:
        save_vault(self.vault_com_entradas(1), CHAVE)
        adulterado = bytearray(Path(ARQUIVO_VAULT).read_bytes())
        adulterado[len(adulterado) // 2] ^= 0x01
        Path(ARQUIVO_VAULT).write_bytes(bytes(adulterado))
        with self.assertRaises(VaultCorrompido):
            load_vault(CHAVE)

    def test_arquivo_truncado(self) -> None:
        save_vault(self.vault_com_entradas(1), CHAVE)
        bruto = Path(ARQUIVO_VAULT).read_bytes()
        Path(ARQUIVO_VAULT).write_bytes(bruto[: len(bruto) // 2])
        with self.assertRaises(VaultCorrompido):
            load_vault(CHAVE)

    def test_arquivo_vazio(self) -> None:
        Path(ARQUIVO_VAULT).touch()
        with self.assertRaises(VaultCorrompido):
            load_vault(CHAVE)

    def test_json_invalido_com_hmac_valido(self) -> None:
        Path(ARQUIVO_VAULT).write_bytes(encrypt_data(b"nao e json", CHAVE))
        with self.assertRaises(VaultCorrompido):
            load_vault(CHAVE)

    def test_json_fora_do_formato_esperado(self) -> None:
        Path(ARQUIVO_VAULT).write_bytes(encrypt_data(b'{"nao": "lista"}', CHAVE))
        with self.assertRaises(VaultCorrompido):
            load_vault(CHAVE)

    @unittest.skipIf(sys.platform == "win32", "chmod POSIX não aplica no Windows")
    def test_sem_permissao(self) -> None:
        save_vault(self.vault_com_entradas(1), CHAVE)
        os.chmod(ARQUIVO_VAULT, 0o000)
        try:
            with self.assertRaises(PermissionError):
                load_vault(CHAVE)
        finally:
            os.chmod(ARQUIVO_VAULT, 0o600)


class TestBackupRestore(BaseStorage):
    def test_backup(self) -> None:
        save_vault(self.vault_com_entradas(2), CHAVE)
        caminho = backup_vault()
        self.assertIsInstance(caminho, str)
        self.assertTrue(Path(caminho).exists())
        self.assertEqual(Path(caminho).read_bytes(), Path(ARQUIVO_VAULT).read_bytes())
        nome = Path(caminho).name
        self.assertRegex(
            nome,
            r"^dados\.enc\.bak\.\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{6}$",
        )

    def test_backups_unicos(self) -> None:
        save_vault(self.vault_com_entradas(1), CHAVE)
        self.assertNotEqual(backup_vault(), backup_vault())

    def test_backup_sem_vault(self) -> None:
        with self.assertRaises(FileNotFoundError):
            backup_vault()

    def test_restore(self) -> None:
        vault = self.vault_com_entradas(2)
        save_vault(vault, CHAVE)
        caminho = backup_vault()
        vault.add(PasswordEntry("novo", "user", "p"))
        save_vault(vault, CHAVE)
        restaurado = restore_vault(caminho, CHAVE)
        self.assertEqual(len(restaurado), 2)
        self.assertEqual(len(load_vault(CHAVE)), 2)
        self.assertTrue(vault_existe())
        self.assertEqual(Path(ARQUIVO_VAULT).read_bytes(), Path(caminho).read_bytes())

    def test_restore_backup_ausente(self) -> None:
        with self.assertRaises(FileNotFoundError):
            restore_vault("nao-existe.bak", CHAVE)

    def test_restore_nao_destroi_vault_atual(self) -> None:
        save_vault(self.vault_com_entradas(2), CHAVE)
        antes = Path(ARQUIVO_VAULT).read_bytes()
        Path("corrompido.bak").write_bytes(b"lixo")
        with self.assertRaises(VaultCorrompido):
            restore_vault("corrompido.bak", CHAVE)
        self.assertEqual(Path(ARQUIVO_VAULT).read_bytes(), antes)
        self.assertEqual(len(load_vault(CHAVE)), 2)


if __name__ == "__main__":
    unittest.main()
