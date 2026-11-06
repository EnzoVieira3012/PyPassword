"""CLI com argparse para PyTask."""

from __future__ import annotations

import argparse
import sys

from src.models import Vault
from src.crypto import derivar_chave
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
from src.storage import load_vault, save_vault
from src.utils import sanitizar_texto, validar_entrada


def _autenticar() -> tuple[bytes, Vault] | None:
    chave = autenticar()
    if chave is None:
        return None
    vault = load_vault(chave)
    return (chave, vault)


def cmd_add(args: argparse.Namespace) -> None:
    resultado = _autenticar()
    if resultado is None:
        return
    chave, vault = resultado
    site = sanitizar_texto(args.site or "")
    username = sanitizar_texto(args.username or "")
    password = args.password or ""
    notes = sanitizar_texto(args.notes or "")
    valido, erro = validar_entrada(site, username, password, notes)
    if not valido:
        print(f"Erro: {erro}")
        return
    from src.models import PasswordEntry
    from datetime import datetime, timezone
    entry = PasswordEntry(
        site=site,
        username=username,
        password=password,
        notes=notes,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    vault.add(entry)
    save_vault(vault, chave)
    print("Credencial cadastrada com sucesso.")


def cmd_list(args: argparse.Namespace) -> None:
    resultado = _autenticar()
    if resultado is None:
        return
    _, vault = resultado
    fluxo_listar(vault)


def cmd_search(args: argparse.Namespace) -> None:
    resultado = _autenticar()
    if resultado is None:
        return
    _, vault = resultado
    fluxo_buscar(vault)


def cmd_edit(args: argparse.Namespace) -> None:
    resultado = _autenticar()
    if resultado is None:
        return
    chave, vault = resultado
    fluxo_editar(vault, chave)


def cmd_delete(args: argparse.Namespace) -> None:
    resultado = _autenticar()
    if resultado is None:
        return
    chave, vault = resultado
    fluxo_excluir(vault, chave)


def cmd_generate(args: argparse.Namespace) -> None:
    from unittest import mock
    with mock.patch("builtins.input", return_value=""):
        fluxo_gerar_senha()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pytask",
        description="Gerenciador de senhas criptografado",
    )
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponiveis")

    # add
    p_add = subparsers.add_parser("add", help="Cadastrar credencial")
    p_add.add_argument("--site", required=True, help="Site")
    p_add.add_argument("--username", required=True, help="Usuario")
    p_add.add_argument("--password", help="Senha (se omitido, gera)")
    p_add.add_argument("--notes", default="", help="Observacoes")
    p_add.set_defaults(func=cmd_add)

    # list
    p_list = subparsers.add_parser("list", help="Listar credenciais")
    p_list.set_defaults(func=cmd_list)

    # search
    p_search = subparsers.add_parser("search", help="Buscar credencial")
    p_search.add_argument("termo", nargs="?", default="", help="Termo de busca")
    p_search.set_defaults(func=cmd_search)

    # edit
    p_edit = subparsers.add_parser("edit", help="Editar credencial")
    p_edit.set_defaults(func=cmd_edit)

    # delete
    p_delete = subparsers.add_parser("delete", help="Excluir credencial")
    p_delete.set_defaults(func=cmd_delete)

    # generate
    p_gen = subparsers.add_parser("generate", help="Gerar senha aleatoria")
    p_gen.set_defaults(func=cmd_generate)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(0)
    args.func(args)


if __name__ == "__main__":
    main()
