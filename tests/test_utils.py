"""Testes de utils.py. Rodar: python -m unittest -v test_utils"""

import os
import unittest
from unittest import mock

from src.models import PasswordEntry
from src.utils import (
    DIGITOS,
    MAIUSCULAS,
    MINUSCULAS,
    SIMBOLOS,
    TODOS,
    formatar_saida,
    gerar_senha_aleatoria,
    limpar_tela,
    pausar,
    sanitizar_texto,
    validar_entrada,
)


class TestGerarSenha(unittest.TestCase):
    def test_tamanhos(self) -> None:
        self.assertEqual(len(gerar_senha_aleatoria()), 16)
        self.assertEqual(len(gerar_senha_aleatoria(20)), 20)
        self.assertEqual(len(gerar_senha_aleatoria(4)), 4)

    def test_tamanho_invalido(self) -> None:
        for tamanho in (0, 1, 3, -5):
            with self.assertRaises(ValueError):
                gerar_senha_aleatoria(tamanho)

    def test_garante_quatro_tipos(self) -> None:
        for _ in range(50):  # o shuffle pode esconder falha em uma amostra
            senha = gerar_senha_aleatoria()
            self.assertTrue(any(c in MAIUSCULAS for c in senha))
            self.assertTrue(any(c in MINUSCULAS for c in senha))
            self.assertTrue(any(c in DIGITOS for c in senha))
            self.assertTrue(any(c in SIMBOLOS for c in senha))

    def test_so_caracteres_permitidos(self) -> None:
        self.assertTrue(set(gerar_senha_aleatoria(500)) <= set(TODOS))

    def test_aleatoriedade(self) -> None:
        self.assertNotEqual(gerar_senha_aleatoria(), gerar_senha_aleatoria())

    def test_usa_secrets_nao_random(self) -> None:
        with mock.patch("src.utils.secrets.choice", return_value="A") as choice:
            gerar_senha_aleatoria(8)
        self.assertEqual(choice.call_count, 8)  # 4 fixos + 4 preenchimentos

    def test_embaralha(self) -> None:
        # secrets.choice devolve sempre o primeiro char do conjunto; sem shuffle
        # a senha sairia "Aa0!..." com os tipos em ordem fixa.
        senhas = {gerar_senha_aleatoria() for _ in range(30)}
        self.assertGreater(len(senhas), 1)
        self.assertTrue(any(s[0] not in MAIUSCULAS for s in senhas))


class TestSanitizarEValidar(unittest.TestCase):
    def test_sanitizar(self) -> None:
        self.assertEqual(sanitizar_texto("  github  "), "github")
        self.assertEqual(sanitizar_texto("si\x00te\x1f"), "site")
        self.assertEqual(sanitizar_texto("\x7fabc\x07"), "abc")

    def test_sanitizar_preserva_tab_quebra(self) -> None:
        self.assertEqual(sanitizar_texto("a\tb\nc"), "a\tb\nc")

    def test_valida(self) -> None:
        self.assertEqual(validar_entrada("github", "user", "senha", ""), (True, ""))
        self.assertEqual(validar_entrada("github", "user", "senha", "nota"), (True, ""))

    def test_obrigatorios(self) -> None:
        self.assertEqual(validar_entrada("", "u", "p", ""), (False, "Site é obrigatório"))
        self.assertEqual(
            validar_entrada("s", "", "p", ""), (False, "Usuário/e-mail é obrigatório")
        )
        self.assertEqual(validar_entrada("s", "u", "", ""), (False, "Senha é obrigatória"))

    def test_so_espacos_conta_como_vazio(self) -> None:
        self.assertFalse(validar_entrada("   ", "u", "p", "")[0])
        self.assertFalse(validar_entrada("s", "   ", "p", "")[0])
        self.assertFalse(validar_entrada("s", "u", "   ", "")[0])

    def test_controle_removido_antes_de_validar(self) -> None:
        self.assertEqual(validar_entrada("git\x00hub", "u", "p", ""), (True, ""))

    def test_senha_nao_e_sanitizada(self) -> None:
        # validar_entrada não devolve texto sanitizado: a senha do cofre tem que
        # ser exatamente a digitada, com espaços internos.
        senha = "  com espaco  "
        self.assertEqual(validar_entrada("git\x00hub", "user", senha, ""), (True, ""))

    def test_limites(self) -> None:
        self.assertTrue(validar_entrada("s" * 255, "u" * 255, "p" * 500, "")[0])
        self.assertFalse(validar_entrada("s" * 256, "u", "p", "")[0])
        self.assertFalse(validar_entrada("s", "u" * 256, "p", "")[0])
        self.assertFalse(validar_entrada("s", "u", "p" * 501, "")[0])


class TestFormatarSaida(unittest.TestCase):
    def test_vazio(self) -> None:
        self.assertEqual(formatar_saida([]), "(vazio)")

    def test_estrutura(self) -> None:
        entrada = PasswordEntry("github", "user", "senha-real", "nota")
        tabela = formatar_saida([entrada]).splitlines()
        self.assertEqual(len(tabela), 3)  # header + separador + 1 linha
        self.assertIn("ID", tabela[0])
        self.assertIn("Observações", tabela[0])
        self.assertIn("-+-", tabela[1])

    def test_varias_entradas(self) -> None:
        entradas = [PasswordEntry(f"site{i}", "user", "p") for i in range(5)]
        self.assertEqual(len(formatar_saida(entradas).splitlines()), 7)

    def test_senha_mascarada(self) -> None:
        entrada = PasswordEntry("github", "user", "senha-real")
        tabela = formatar_saida([entrada])
        self.assertIn("***", tabela)
        self.assertNotIn("senha-real", tabela)

    def test_id_truncado(self) -> None:
        entrada = PasswordEntry("github", "user", "p")
        self.assertIn(str(entrada.id)[:8], formatar_saida([entrada]))
        self.assertNotIn(str(entrada.id), formatar_saida([entrada]))

    def test_alinhamento_dinamico(self) -> None:
        entradas = [
            PasswordEntry("a", "u", "p", "curta"),
            PasswordEntry("site-bem-maior", "u", "p", "n" * 60),
        ]
        linhas = formatar_saida(entradas).splitlines()
        self.assertEqual(len({len(linha) for linha in linhas}), 1)
        self.assertIn("n" * 60, linhas[-1])

    def test_colunas_alinhadas_por_pipe(self) -> None:
        entradas = [PasswordEntry("github", "user", "p", "x")]
        linhas = formatar_saida(entradas).splitlines()
        posicoes = {
            tuple(i for i, c in enumerate(linha) if c == "|")
            for linha in [linhas[0], *linhas[2:]]  # separador usa "+", não "|"
        }
        self.assertEqual(len(posicoes), 1)


class TestUx(unittest.TestCase):
    def test_pausar(self) -> None:
        with mock.patch("builtins.input", return_value="") as entrada:
            pausar("Aperte Enter")
        entrada.assert_called_once_with("Aperte Enter")

    def test_pausar_propaga_keyboard_interrupt(self) -> None:
        with mock.patch("builtins.input", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                pausar()

    def test_pausar_propaga_eof(self) -> None:
        with mock.patch("builtins.input", side_effect=EOFError):
            with self.assertRaises(EOFError):
                pausar()

    def test_limpar_tela(self) -> None:
        with mock.patch("src.utils.os.system") as system:
            limpar_tela()
        system.assert_called_once_with("cls" if os.name == "nt" else "clear")


if __name__ == "__main__":
    unittest.main()
