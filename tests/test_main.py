"""Testes de integração de main.py. Rodar: python -m unittest -v test_main"""

import os
import tempfile
import unittest
from collections.abc import Callable
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from unittest import mock

import src.main as main
import src.storage as storage
from src.crypto import ARQUIVO_HASH, derivar_chave
from src.models import PasswordEntry, Vault

CHAVE = b"\x01" * 64  # qualquer 64 bytes servem: derivar_chave não é o alvo aqui
SENHA = "senha mestre"


class Saida(str):
    """Saída padrão capturada; `.valor` guarda o retorno da função."""

    valor: object = None


def rodar(
    funcao: Callable[..., object],
    *args: object,
    entradas: list[str] | None = None,
    senhas: list[str] | None = None,
) -> Saida:
    """Executa `funcao` com input/getpass simulados e captura a saída padrão."""
    entrada = mock.patch("builtins.input", side_effect=entradas or [])
    senha = mock.patch("src.main.getpass.getpass", side_effect=senhas or [])
    with entrada, senha:
        buffer = StringIO()
        with redirect_stdout(buffer):
            retorno = funcao(*args)
    saida = Saida(buffer.getvalue())
    saida.valor = retorno
    return saida


class BaseMain(unittest.TestCase):
    def setUp(self) -> None:
        self._cwd = Path.cwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.addCleanup(os.chdir, str(self._cwd))
        for alvo in ("src.main.limpar_tela", "src.main.pausar"):
            patcher = mock.patch(alvo)
            patcher.start()
            self.addCleanup(patcher.stop)

    def criar_cofre(self, senha: str = SENHA) -> bytes:
        """Roda o setup inicial de verdade e devolve a chave derivada."""
        chave = rodar(main.primeira_execucao, senhas=[senha, senha]).valor
        assert isinstance(chave, bytes)
        return chave

    def vault(self, quantidade: int = 2) -> Vault:
        vault = Vault()
        for i in range(quantidade):
            entrada = PasswordEntry(f"site{i}", f"user{i}", f"senha{i}", f"nota{i}")
            vault.add(entrada)
            # relógio do Windows não garante µs distinta entre add() seguidos
            entrada.created_at = datetime.now(timezone.utc) + timedelta(seconds=i)
        return vault


class TestPrimeiraExecucao(BaseMain):
    def test_cria_arquivos_e_retorna_chave(self) -> None:
        chave = self.criar_cofre()
        self.assertEqual(len(chave), 64)
        self.assertEqual(len(Path("salt.bin").read_bytes()), 16)
        self.assertEqual(len(Path(ARQUIVO_HASH).read_bytes()), 32)
        self.assertTrue(storage.vault_existe())
        self.assertEqual(len(storage.load_vault(chave)), 0)
        # chave.key não é gravado de propósito (ver docstring)
        self.assertFalse(Path("chave.key").exists())

    def test_rejeita_senha_vazia_e_diferente(self) -> None:
        chave = rodar(
            main.primeira_execucao,
            senhas=["", "abc", "xyz", SENHA, SENHA],  # vazia, não confere, confere
        ).valor
        self.assertIsInstance(chave, bytes)
        assert isinstance(chave, bytes)
        self.assertEqual(len(chave), 64)

    def test_hash_nao_e_da_chave(self) -> None:
        chave = self.criar_cofre()
        self.assertNotEqual(chave[:32], Path(ARQUIVO_HASH).read_bytes())


class TestAutenticar(BaseMain):
    def test_senha_correta(self) -> None:
        chave_setup = self.criar_cofre()
        chave = rodar(main.autenticar, senhas=[SENHA]).valor
        self.assertEqual(chave, chave_setup)

    def test_errada_depois_correta(self) -> None:
        chave_setup = self.criar_cofre()
        chave = rodar(main.autenticar, senhas=["errada", SENHA]).valor
        self.assertEqual(chave, chave_setup)

    def test_tres_erradas_encerra(self) -> None:
        self.criar_cofre()
        with self.assertRaises(SystemExit) as contexto:
            rodar(main.autenticar, senhas=["a", "b", "c"])
        self.assertEqual(contexto.exception.code, 1)

    def test_arquivos_ausentes(self) -> None:
        self.assertIsNone(rodar(main.autenticar, senhas=[SENHA]).valor)

    def test_salt_corrompido(self) -> None:
        Path("salt.bin").write_bytes(b"curto")
        Path(ARQUIVO_HASH).write_bytes(b"x" * 32)
        self.assertIsNone(rodar(main.autenticar, senhas=[SENHA]).valor)

    def test_hash_corrompido(self) -> None:
        Path("salt.bin").write_bytes(b"x" * 16)
        Path(ARQUIVO_HASH).write_bytes(b"curto")
        self.assertIsNone(rodar(main.autenticar, senhas=[SENHA]).valor)


class TestMenu(BaseMain):
    def test_despacha_fluxos(self) -> None:
        alvos = [
            "fluxo_cadastrar",
            "fluxo_listar",
            "fluxo_buscar",
            "fluxo_editar",
            "fluxo_excluir",
            "fluxo_gerar_senha",
        ]
        mocks = {}
        for alvo in alvos:
            patcher = mock.patch(f"src.main.{alvo}")
            mocks[alvo] = patcher.start()
            self.addCleanup(patcher.stop)
        rodar(main.menu_principal, self.vault(), CHAVE, entradas=["1", "2", "3", "4", "5", "6", "0"])
        for alvo in alvos:
            mocks[alvo].assert_called_once()

    def test_opcao_invalida(self) -> None:
        with mock.patch("src.main.pausar") as pausar:
            rodar(main.menu_principal, self.vault(), CHAVE, entradas=["9", "0"])
        pausar.assert_called_once()

    def test_sai_com_7(self) -> None:
        rodar(main.menu_principal, self.vault(), CHAVE, entradas=["7"])

    def test_ctrl_c_e_ctrl_d(self) -> None:
        for efeito in (KeyboardInterrupt, EOFError):
            with mock.patch("builtins.input", side_effect=efeito):
                with redirect_stdout(StringIO()):
                    main.menu_principal(self.vault(), CHAVE)


class TestFluxoCadastrar(BaseMain):
    def test_cadastra_e_persiste(self) -> None:
        vault = Vault()
        rodar(
            main.fluxo_cadastrar,
            vault,
            CHAVE,
            entradas=["  github  ", " user ", " nota "],
            senhas=["s3nh4"],
        )
        self.assertEqual(len(vault), 1)
        entrada = vault.list_all()[0]
        self.assertEqual((entrada.site, entrada.username), ("github", "user"))
        self.assertEqual(entrada.password, "s3nh4")
        self.assertEqual(entrada.notes, "nota")
        self.assertEqual(len(storage.load_vault(CHAVE)), 1)

    def test_site_vazio(self) -> None:
        vault = Vault()
        saida = rodar(main.fluxo_cadastrar, vault, CHAVE, entradas=["   "])
        self.assertIn("Site é obrigatório", saida)
        self.assertEqual(len(vault), 0)

    def test_usuario_vazio(self) -> None:
        vault = Vault()
        saida = rodar(main.fluxo_cadastrar, vault, CHAVE, entradas=["github", "  "])
        self.assertIn("obrigatório", saida)
        self.assertEqual(len(vault), 0)

    def test_senha_vazia(self) -> None:
        vault = Vault()
        saida = rodar(
            main.fluxo_cadastrar, vault, CHAVE, entradas=["github", "user"], senhas=["  "]
        )
        self.assertIn("Senha é obrigatória", saida)
        self.assertEqual(len(vault), 0)

    def test_notes_opcional(self) -> None:
        vault = Vault()
        rodar(
            main.fluxo_cadastrar,
            vault,
            CHAVE,
            entradas=["github", "user", ""],
            senhas=["p"],
        )
        self.assertEqual(len(vault), 1)
        self.assertEqual(vault.list_all()[0].notes, "")


class TestFluxoListar(BaseMain):
    def test_vazio(self) -> None:
        self.assertIn("vazio", rodar(main.fluxo_listar, Vault()))

    def test_com_entradas(self) -> None:
        vault = self.vault(3)
        saida = rodar(main.fluxo_listar, vault)
        self.assertIn("Total: 3 entrada(s)", saida)
        self.assertIn("***", saida)
        self.assertNotIn("senha0", saida)

    def test_ordem_desc(self) -> None:
        vault = self.vault(2)
        saida = rodar(main.fluxo_listar, vault)
        self.assertLess(saida.index("site1"), saida.index("site0"))


class TestFluxoBuscar(BaseMain):
    def test_termo_vazio(self) -> None:
        self.assertIn("Termo vazio", rodar(main.fluxo_buscar, self.vault(), entradas=[" "]))

    def test_sem_resultado(self) -> None:
        saida = rodar(main.fluxo_buscar, self.vault(), entradas=["inexistente"])
        self.assertIn("Nenhum resultado", saida)

    def test_encontra_e_revela(self) -> None:
        vault = self.vault(2)
        prefixo = str(vault.search("site")[0].id)[:8]
        saida = rodar(main.fluxo_buscar, vault, entradas=["site", prefixo, ""])
        self.assertIn("2 resultado(s)", saida)
        self.assertIn("senha0", saida)

    def test_id_invalido_avisa(self) -> None:
        vault = self.vault(1)
        saida = rodar(main.fluxo_buscar, vault, entradas=["site0", "zzzz", ""])
        self.assertIn("n\u00e3o encontrado", saida)

    def test_busca_case_insensitive(self) -> None:
        vault = Vault()
        vault.add(PasswordEntry("GitHub", "User", "p"))
        saida = rodar(main.fluxo_buscar, vault, entradas=["github", ""])
        self.assertIn("1 resultado(s)", saida)


class TestFluxoEditar(BaseMain):
    def test_id_inexistente(self) -> None:
        saida = rodar(main.fluxo_editar, self.vault(), CHAVE, entradas=["zzzz"])
        self.assertIn("não encontrada", saida)

    def test_sem_alteracao(self) -> None:
        vault = self.vault(1)
        prefixo = str(vault.list_all()[0].id)[:8]
        saida = rodar(
            main.fluxo_editar, vault, CHAVE, entradas=[prefixo, "", "", ""], senhas=[""]
        )
        self.assertIn("Nenhuma alteração", saida)

    def test_edita_campos(self) -> None:
        vault = self.vault(1)
        entrada = vault.list_all()[0]
        entrada.updated_at = datetime.now(timezone.utc) - timedelta(days=1)
        antes = entrada.updated_at
        rodar(
            main.fluxo_editar,
            vault,
            CHAVE,
            entradas=[str(entrada.id)[:8], "novo-site", "", "nova nota"],
            senhas=["nova senha"],
        )
        self.assertEqual(entrada.site, "novo-site")
        self.assertEqual(entrada.password, "nova senha")
        self.assertEqual(entrada.notes, "nova nota")
        self.assertGreater(entrada.updated_at, antes)
        self.assertEqual(storage.load_vault(CHAVE).list_all()[0].site, "novo-site")

    def test_senha_so_espacos_bloqueia(self) -> None:
        vault = self.vault(1)
        entrada = vault.list_all()[0]
        saida = rodar(
            main.fluxo_editar,
            vault,
            CHAVE,
            entradas=[str(entrada.id)[:8], "", "", ""],
            senhas=["   "],
        )
        self.assertIn("Senha é obrigatória", saida)
        self.assertEqual(entrada.password, "senha0")


class TestFluxoExcluir(BaseMain):
    def test_id_inexistente(self) -> None:
        saida = rodar(main.fluxo_excluir, self.vault(), CHAVE, entradas=["zzzz"])
        self.assertIn("não encontrada", saida)

    def test_primeira_confirmacao_errada(self) -> None:
        vault = self.vault(1)
        prefixo = str(vault.list_all()[0].id)[:8]
        saida = rodar(main.fluxo_excluir, vault, CHAVE, entradas=[prefixo, "nao"])
        self.assertIn("cancelada", saida)
        self.assertEqual(len(vault), 1)

    def test_segunda_confirmacao_errada(self) -> None:
        vault = self.vault(1)
        prefixo = str(vault.list_all()[0].id)[:8]
        saida = rodar(
            main.fluxo_excluir, vault, CHAVE, entradas=[prefixo, "CONFIRMO", "nao"]
        )
        self.assertIn("segunda confirmação", saida)
        self.assertEqual(len(vault), 1)

    def test_exclui_com_confirmacao_dupla(self) -> None:
        vault = self.vault(2)
        prefixo = str(vault.list_all()[0].id)[:8]
        rodar(
            main.fluxo_excluir,
            vault,
            CHAVE,
            entradas=[prefixo, "CONFIRMO", "CONFIRMO"],
        )
        self.assertEqual(len(vault), 1)
        self.assertEqual(len(storage.load_vault(CHAVE)), 1)


class TestFluxoGerarSenha(BaseMain):
    def test_padrao(self) -> None:
        saida = rodar(main.fluxo_gerar_senha, entradas=[""])
        self.assertIn("(16 chars)", saida)

    def test_custom(self) -> None:
        self.assertIn("(20 chars)", rodar(main.fluxo_gerar_senha, entradas=["20"]))

    def test_invalido_usa_padrao(self) -> None:
        self.assertIn("(16 chars)", rodar(main.fluxo_gerar_senha, entradas=["abc"]))

    def test_limites(self) -> None:
        self.assertIn("entre 4 e", rodar(main.fluxo_gerar_senha, entradas=["3"]))
        self.assertIn("entre 4 e", rodar(main.fluxo_gerar_senha, entradas=["200"]))

    def test_sem_pyperclip(self) -> None:
        with mock.patch.dict("sys.modules", {"pyperclip": None}):
            saida = rodar(main.fluxo_gerar_senha, entradas=[""])
        self.assertIn("não instalado", saida)


class TestMain(BaseMain):
    def test_primeira_execucao_abre_menu(self) -> None:
        with mock.patch("src.main.menu_principal") as menu:
            rodar(main.main, senhas=[SENHA, SENHA])
        menu.assert_called_once()
        self.assertEqual(len(menu.call_args.args[0]), 0)

    def test_login_abre_menu(self) -> None:
        self.criar_cofre()
        with mock.patch("src.main.menu_principal") as menu:
            rodar(main.main, senhas=[SENHA])
        menu.assert_called_once()

    def test_login_falho_nao_abre_menu(self) -> None:
        self.criar_cofre()
        with mock.patch("src.main.menu_principal") as menu:
            with self.assertRaises(SystemExit):
                rodar(main.main, senhas=["a", "b", "c"])
        menu.assert_not_called()

    def test_cofre_corrompido_sai(self) -> None:
        self.criar_cofre()
        Path(storage.ARQUIVO_VAULT).write_bytes(b"lixo")
        with self.assertRaises(SystemExit):
            rodar(main.main, senhas=[SENHA])


class TestDerivacaoCompativel(BaseMain):
    def test_chave_setup_abre_cofre_salvo(self) -> None:
        chave = self.criar_cofre()
        vault = storage.load_vault(chave)
        vault.add(PasswordEntry("github", "user", "p"))
        storage.save_vault(vault, chave)
        self.assertEqual(derivar_chave(SENHA, Path("salt.bin").read_bytes()), chave)


if __name__ == "__main__":
    unittest.main()
