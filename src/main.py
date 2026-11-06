"""Camada de apresentacao: setup inicial, login e menu do cofre."""

from __future__ import annotations

import getpass
import hmac
import os
import secrets
import sys
from collections.abc import Iterable
from pathlib import Path

import src.storage as storage
from src.crypto import ARQUIVO_HASH, derivar_chave, hash_senha_mestra
from src.models import PasswordEntry, Vault
from src.utils import (
    formatar_saida,
    gerar_senha_aleatoria,
    limpar_tela,
    pausar,
    sanitizar_texto,
    validar_entrada,
)

ARQUIVO_SALT = "salt.bin"
TENTATIVAS_LOGIN = 3
TAMANHO_MAX_SENHA_GERADA = 128


def primeira_execucao() -> bytes:
    """Configura o cofre na primeira vez (CREATE DATABASE)."""
    limpar_tela()
    print("=== PRIMEIRA EXECUÇÃO ===")
    print("Defina a senha mestra. Ela NAO pode ser recuperada.")

    while True:
        senha = getpass.getpass("Senha mestra: ")
        if not senha.strip():
            print("Senha não pode ser vazia.")
            continue
        confirmacao = getpass.getpass("Confirme a senha mestra: ")
        if senha != confirmacao:
            print("Senhas não conferem. Tente novamente.")
            continue
        break

    salt = secrets.token_bytes(16)
    Path(ARQUIVO_SALT).write_bytes(salt)
    os.chmod(ARQUIVO_SALT, 0o600)

    chave = derivar_chave(senha, salt)
    hash_senha_mestra(senha, salt)
    storage.init_vault(chave)

    print("Setup concluído. Cofre criado em dados.enc")
    return chave


def autenticar(
    salt_path: str = ARQUIVO_SALT, hash_path: str = ARQUIVO_HASH
) -> bytes | None:
    """Login com até 3 tentativas, comparacao timing-safe."""
    try:
        salt = Path(salt_path).read_bytes()
        hash_salvo = Path(hash_path).read_bytes()
    except OSError:
        print("Arquivos de autenticação não encontrados.")
        return None

    if len(salt) != 16 or len(hash_salvo) != 32:
        print("Arquivos de autenticação corrompidos.")
        return None

    for tentativa in range(1, TENTATIVAS_LOGIN + 1):
        senha = getpass.getpass(f"Senha mestra ({tentativa}/{TENTATIVAS_LOGIN}): ")
        chave = derivar_chave(senha, salt)
        calculado = hash_senha_mestra(senha, salt, None)
        if hmac.compare_digest(calculado, hash_salvo):
            print("Autenticação concluída. Bem-vindo!")
            return chave
        restantes = TENTATIVAS_LOGIN - tentativa
        print(f"Senha incorreta. Tentativas restantes: {restantes}")

    print("Máximo de tentativas excedido. Encerrando.")
    sys.exit(1)


def _buscar_por_prefixo(
    entradas: Iterable[PasswordEntry], prefixo: str
) -> PasswordEntry | None:
    """SELECT WHERE id LIKE 'prefixo%'."""
    for entrada in entradas:
        if str(entrada.id).startswith(prefixo):
            return entrada
    return None


def fluxo_cadastrar(vault: Vault, chave: bytes) -> None:
    """INSERT com validação em cascata: site, usuario, senha, notas."""
    limpar_tela()
    print("=== CADASTRAR SENHA ===")

    site = sanitizar_texto(input("Site/serviço: "))
    if not site:
        print("Site é obrigatório")
        pausar()
        return

    username = sanitizar_texto(input("Usuário/e-mail: "))
    if not username:
        print("Usuário/e-mail é obrigatório")
        pausar()
        return

    password = getpass.getpass("Senha: ")
    if not password.strip():
        print("Senha é obrigatória")
        pausar()
        return

    notes = sanitizar_texto(input("Observações (opcional): "))

    ok, erro = validar_entrada(site, username, password, notes)
    if not ok:
        print(erro)
        pausar()
        return

    entrada = PasswordEntry(
        site=site, username=username, password=password, notes=notes
    )
    entrada_id = vault.add(entrada)
    storage.save_vault(vault, chave)
    print("Senha cadastrada. ID: " + entrada_id[:8])
    pausar()


def fluxo_listar(vault: Vault) -> None:
    """VIEW publica: SELECT * ORDER BY created_at DESC, senha mascarada."""
    limpar_tela()
    print("=== LISTA DE SENHAS ===")

    entradas = vault.list_all()
    if not entradas:
        print("(vazio - nenhuma senha cadastrada)")
    else:
        print(formatar_saida(entradas))
        print(f"Total: {len(entradas)} entrada(s)")
    pausar()


def fluxo_buscar(vault: Vault) -> None:
    """WHERE site/username LIKE, com toggle para revelar a senha."""
    limpar_tela()
    print("=== BUSCAR SENHA ===")

    termo = sanitizar_texto(input("Termo (site ou usuário): "))
    if not termo:
        print("Termo vazio.")
        pausar()
        return

    resultados = vault.search(termo)
    if not resultados:
        print(f"Nenhum resultado para '{termo}'.")
        pausar()
        return

    print(f"{len(resultados)} resultado(s):")
    print(formatar_saida(resultados))

    while True:
        escolha = input("ID (8 chars) para ver a senha, Enter para voltar: ").strip()
        if not escolha:
            break
        entrada = _buscar_por_prefixo(resultados, escolha)
        if entrada is None:
            print("ID não encontrado nos resultados.")
            continue
        print(f"Senha de {entrada.site} / {entrada.username}: {entrada.password}")

    pausar()


def fluxo_editar(vault: Vault, chave: bytes) -> None:
    """UPDATE: campo em branco mantem o valor atual; updated_at e trigger."""
    limpar_tela()
    print("=== EDITAR SENHA ===")

    prefixo = input("ID da entrada (8 chars): ").strip()
    entrada = _buscar_por_prefixo(vault, prefixo) if prefixo else None
    if entrada is None:
        print("Entrada não encontrada.")
        pausar()
        return

    print(f"Editando: {entrada.site} / {entrada.username}")
    print("(Enter mantém o valor atual)")

    novos: dict[str, str] = {}

    novo_site = sanitizar_texto(input(f"Site [{entrada.site}]: "))
    if novo_site:
        novos["site"] = novo_site

    novo_user = sanitizar_texto(input(f"Usuário [{entrada.username}]: "))
    if novo_user:
        novos["username"] = novo_user

    nova_senha = getpass.getpass("Senha [****]: ")
    if nova_senha:
        novos["password"] = nova_senha

    novas_notas = sanitizar_texto(input(f"Observações [{entrada.notes}]: "))
    if novas_notas:
        novos["notes"] = novas_notas

    if not novos:
        print("Nenhuma alteração feita.")
        pausar()
        return

    ok, erro = validar_entrada(
        novos.get("site", entrada.site),
        novos.get("username", entrada.username),
        novos.get("password", entrada.password),
        novos.get("notes", entrada.notes),
    )
    if not ok:
        print(erro)
        pausar()
        return

    vault.update(entrada.id, **novos)
    storage.save_vault(vault, chave)
    print("Entrada atualizada.")
    pausar()


def fluxo_excluir(vault: Vault, chave: bytes) -> None:
    """DELETE com confirmação dupla - irreversível, sem lixeira."""
    limpar_tela()
    print("=== EXCLUIR SENHA ===")

    prefixo = input("ID da entrada (8 chars): ").strip()
    entrada = _buscar_por_prefixo(vault, prefixo) if prefixo else None
    if entrada is None:
        print("Entrada não encontrada.")
        pausar()
        return

    print(f"EXCLUIR: {entrada.site} / {entrada.username}")
    print(f"ID completo: {entrada.id}")
    print(f"Criada em: {entrada.created_at.strftime('%d/%m/%Y %H:%M')}")
    print("ESTA AÇÃO É IRREVERSÍVEL.")

    primeira = input("Digite CONFIRMO para continuar: ").strip()
    if primeira != "CONFIRMO":
        print("Operação cancelada.")
        pausar()
        return

    segunda = input("Tem certeza? Digite CONFIRMO novamente: ").strip()
    if segunda != "CONFIRMO":
        print("Operação cancelada na segunda confirmação.")
        pausar()
        return

    vault.delete(entrada.id)
    storage.save_vault(vault, chave)
    print("Entrada excluída permanentemente.")
    pausar()


def fluxo_gerar_senha() -> None:
    """Gera senha com CSPRNG e tenta copiar para o clipboard."""
    limpar_tela()
    print("=== GERAR SENHA ===")

    digitado = input("Tamanho (Enter = 16): ").strip()
    try:
        tamanho = int(digitado) if digitado else 16
    except ValueError:
        print("Valor inválido, usando 16.")
        tamanho = 16

    if tamanho < 4 or tamanho > TAMANHO_MAX_SENHA_GERADA:
        print(f"Tamanho deve estar entre 4 e {TAMANHO_MAX_SENHA_GERADA}.")
        pausar()
        return

    senha = gerar_senha_aleatoria(tamanho)
    print(f"Senha gerada ({tamanho} chars):")
    print("   " + senha)

    try:
        import pyperclip  # type: ignore[import-untyped]
    except ImportError:
        print("pyperclip não instalado - selecione e copie manualmente.")
        print("Para instalar: python -m pip install pyperclip")
    else:
        pyperclip.copy(senha)
        print("Copiada para o clipboard.")

    pausar()


def menu_principal(vault: Vault, chave: bytes) -> None:
    """Loop do menu: while True + match/case com 6 fluxos e saida."""
    while True:
        try:
            limpar_tela()
            print("=== GERENCIADOR DE SENHAS ===")
            print(f"Entradas: {len(vault)}")
            print("1. Cadastrar  2. Listar   3. Buscar")
            print("4. Editar     5. Excluir  6. Gerar senha")
            print("0. Sair")
            print("-" * 34)

            opção = input("Escolha: ").strip()
            match opção:
                case "1":
                    fluxo_cadastrar(vault, chave)
                case "2":
                    fluxo_listar(vault)
                case "3":
                    fluxo_buscar(vault)
                case "4":
                    fluxo_editar(vault, chave)
                case "5":
                    fluxo_excluir(vault, chave)
                case "6":
                    fluxo_gerar_senha()
                case "0" | "7":
                    print("Até logo!")
                    break
                case _:
                    print("Opção inválida.")
                    pausar()
        except (KeyboardInterrupt, EOFError):
            print("Saindo...")
            break


def main() -> None:
    """Ponto de entrada: setup inicial ou login, depois o menu."""
    chave = primeira_execucao() if not storage.vault_existe() else autenticar()
    if chave is None:
        return
    try:
        vault = storage.load_vault(chave)
    except storage.VaultCorrompido as exc:
        print(f"{exc}")
        print("O cofre nao abre. Restaure um backup ou apague dados.enc.")
        sys.exit(1)
    menu_principal(vault, chave)


if __name__ == "__main__":
    main()
