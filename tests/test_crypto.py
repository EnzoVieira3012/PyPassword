"""Testes de crypto.py. Rodar: python -m unittest -v test_crypto"""

import base64
import hashlib
import hmac
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.fernet import Fernet

import src.crypto as crypto
from src.crypto import (
    _dividir_chave_mestra,
    decrypt_data,
    derivar_chave,
    encrypt_data,
    gerar_chave_fernet,
    hash_senha_mestra,
)

SALT = b"1234567890123456"
CHAVE = derivar_chave("senha123", SALT)  # 64 bytes, derivada uma vez só


class TestDerivarChave(unittest.TestCase):
    def test_deterministico(self) -> None:
        self.assertEqual(derivar_chave("senha123", SALT), CHAVE)

    def test_salt_diferente(self) -> None:
        self.assertNotEqual(derivar_chave("senha123", b"0000000000000000"), CHAVE)

    def test_senha_diferente(self) -> None:
        self.assertNotEqual(derivar_chave("outra", SALT), CHAVE)

    def test_tamanho_e_tipo(self) -> None:
        self.assertIsInstance(CHAVE, bytes)
        self.assertEqual(len(CHAVE), 64)
        self.assertEqual(len(derivar_chave("senha123", SALT, dklen=32)), 32)

    def test_salt_invalido(self) -> None:
        for salt in (b"", b"curto", b"x" * 17):
            with self.assertRaises(ValueError):
                derivar_chave("senha123", salt)

    def test_lentidao_esperada(self) -> None:
        inicio = time.perf_counter()
        derivar_chave("senha123", SALT)
        self.assertGreater(time.perf_counter() - inicio, 0.02)

    def test_unicode(self) -> None:
        self.assertEqual(
            len(derivar_chave("sênha ção 🔐", SALT)),
            64,
        )


class TestChaveFernet(unittest.TestCase):
    def test_arquivo_e_retorno(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destino = Path(tmp) / "chave.key"
            chave = gerar_chave_fernet(destino)
            self.assertIsInstance(chave, bytes)
            self.assertEqual(len(chave), 44)
            self.assertEqual(destino.read_bytes(), chave)
            Fernet(chave)  # chave válida

    def test_aleatoriedade(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            a = gerar_chave_fernet(Path(tmp) / "a.key")
            b = gerar_chave_fernet(Path(tmp) / "b.key")
            self.assertNotEqual(a, b)

    @unittest.skipIf(sys.platform == "win32", "chmod POSIX não aplica no Windows")
    def test_permissao_0o600(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destino = Path(tmp) / "chave.key"
            gerar_chave_fernet(destino)
            self.assertEqual(stat.S_IMODE(os.stat(destino).st_mode), 0o600)


class TestDividirChaveMestra(unittest.TestCase):
    def test_64_bytes(self) -> None:
        enc, mac = _dividir_chave_mestra(b"A" * 32 + b"B" * 32)
        self.assertEqual((len(enc), len(mac)), (32, 32))
        self.assertEqual(enc, b"A" * 32)
        self.assertEqual(mac, b"B" * 32)

    def test_ignora_excedente(self) -> None:
        enc, mac = _dividir_chave_mestra(CHAVE + b"lixo extra")
        self.assertEqual((enc, mac), _dividir_chave_mestra(CHAVE))

    def test_curta_demais(self) -> None:
        for tamanho in (0, 32, 63):
            with self.assertRaises(ValueError):
                _dividir_chave_mestra(b"x" * tamanho)

    def test_chaves_utilizaveis(self) -> None:
        enc, mac = _dividir_chave_mestra(CHAVE)
        self.assertNotEqual(enc, mac)
        Fernet(base64.urlsafe_b64encode(enc))
        self.assertEqual(len(hmac.new(mac, b"data", hashlib.sha256).digest()), 32)


class TestHashSenhaMestra(unittest.TestCase):
    def test_arquivo_e_retorno(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destino = Path(tmp) / "hash.bin"
            digest = hash_senha_mestra("senha123", SALT, destino)
            self.assertIsInstance(digest, bytes)
            self.assertEqual(len(digest), 32)
            self.assertEqual(destino.read_bytes(), digest)

    def test_deterministico(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            a = hash_senha_mestra("senha123", SALT, Path(tmp) / "a.bin")
            b = hash_senha_mestra("senha123", SALT, Path(tmp) / "b.bin")
            self.assertEqual(a, b)

    def test_salt_diferente(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            a = hash_senha_mestra("senha123", SALT, Path(tmp) / "a.bin")
            b = hash_senha_mestra("senha123", b"0" * 16, Path(tmp) / "b.bin")
            self.assertNotEqual(a, b)

    def test_diferente_de_derivar_chave(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            digest = hash_senha_mestra("senha123", SALT, Path(tmp) / "h.bin")
        self.assertNotEqual(digest, CHAVE[:32])

    def test_salt_invalido(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                hash_senha_mestra("senha123", b"curto", Path(tmp) / "h.bin")

    def test_unicode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                len(hash_senha_mestra("sênha 🔐", SALT, Path(tmp) / "h.bin")), 32
            )


class TestEncryptDecrypt(unittest.TestCase):
    def test_roundtrip(self) -> None:
        for dados in (b"", b"{}", b'[{"site": "github"}]', os.urandom(1024 * 1024)):
            self.assertEqual(decrypt_data(encrypt_data(dados, CHAVE), CHAVE), dados)

    def test_formato_token(self) -> None:
        token = encrypt_data(b"dados", CHAVE)
        self.assertIsInstance(token, bytes)
        self.assertGreater(len(token), 32)
        # ciphertext = Fernet token (base64) + tag de 32 bytes
        ciphertext = token[:-32]
        self.assertEqual(len(token) - len(ciphertext), 32)
        self.assertEqual(
            token[-32:], hmac.new(CHAVE[32:64], ciphertext, hashlib.sha256).digest()
        )

    def test_tampering(self) -> None:
        token = bytearray(encrypt_data(b"dados", CHAVE))
        for posicao in (0, len(token) // 2, len(token) - 1):
            adulterado = bytearray(token)
            adulterado[posicao] ^= 0x01
            with self.assertRaises(ValueError):
                decrypt_data(bytes(adulterado), CHAVE)

    def test_chave_errada(self) -> None:
        outra = derivar_chave("senha456", SALT)
        token = encrypt_data(b"dados", CHAVE)
        with self.assertRaises(ValueError):
            decrypt_data(token, outra)

    def test_token_truncado(self) -> None:
        for token in (b"", b"x" * 32, encrypt_data(b"dados", CHAVE)[:20]):
            with self.assertRaises(ValueError):
                decrypt_data(token, CHAVE)

    def test_chave_mestra_curta(self) -> None:
        with self.assertRaises(ValueError):
            encrypt_data(b"dados", b"x" * 32)
        with self.assertRaises(ValueError):
            decrypt_data(encrypt_data(b"dados", CHAVE), b"x" * 32)

    def test_constantes(self) -> None:
        self.assertEqual(crypto.ITERACOES_PBKDF2, 100_000)
        self.assertEqual(crypto.TAMANHO_SALT, 16)
        self.assertEqual(crypto.TAMANHO_CHAVE_MAESTRA, 64)


if __name__ == "__main__":
    unittest.main()
