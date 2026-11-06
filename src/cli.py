"""CLI com argparse para PyPassword."""

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
import src.storage as storage
from src.storage import load_vault, save_vault
from src.main import _buscar_por_prefixo
from src.qr import mostrar_qr
from src.sync import puxar as sync_puxar, sincronizar as sync_push
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
    category = sanitizar_texto(args.category or "")
    valido, erro = validar_entrada(site, username, password, notes, category)
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
        category=category,
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


def cmd_sync(args: argparse.Namespace) -> None:
    if args.pull:
        resultado = _autenticar()
        if resultado is None:
            return
        chave, _ = resultado
        try:
            nomes = sync_puxar(args.destino, chave)
        except (FileNotFoundError, storage.VaultCorrompido) as exc:
            print(f"Falha no pull: {exc}")
            return
        print(f"Puxado: {', '.join(nomes) if nomes else 'nada'}")
        return
    nomes = sync_push(args.destino)
    print(f"Enviado: {', '.join(nomes) if nomes else 'nada'}")


def cmd_vaults(args: argparse.Namespace) -> None:
    nomes = storage.vaults_disponiveis()
    if not nomes:
        print("Nenhum vault encontrado.")
        return
    for nome in nomes:
        print(nome or "(padrao)")


def cmd_qr(args: argparse.Namespace) -> None:
    resultado = _autenticar()
    if resultado is None:
        return
    _, vault = resultado
    entrada = _buscar_por_prefixo(list(vault), args.id)
    if entrada is None:
        print(f"Entrada nao encontrada: {args.id}")
        return
    mostrar_qr(f"{entrada.site}\n{entrada.username}\n{entrada.password}")


def cmd_generate(args: argparse.Namespace) -> None:
    from unittest import mock
    with mock.patch("builtins.input", return_value=""):
        fluxo_gerar_senha()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pypassword",
        description="Gerenciador de senhas criptografado",
    )
    parser.add_argument(
        "--vault", default="", help="Namespace do cofre (multi-vault)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponiveis")

    # add
    p_add = subparsers.add_parser("add", help="Cadastrar credencial")
    p_add.add_argument("--site", required=True, help="Site")
    p_add.add_argument("--username", required=True, help="Usuario")
    p_add.add_argument("--password", help="Senha (se omitido, gera)")
    p_add.add_argument("--notes", default="", help="Observacoes")
    p_add.add_argument("--category", default="", help="Categoria/tag")
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

    # sync
    p_sync = subparsers.add_parser("sync", help="Sincronizar cofre com uma pasta")
    p_sync.add_argument("--destino", required=True, help="Pasta de destino/origem")
    p_sync.add_argument(
        "--pull", action="store_true", help="Trazer da pasta (default: enviar)"
    )
    p_sync.set_defaults(func=cmd_sync)

    # vaults
    p_vaults = subparsers.add_parser("vaults", help="Listar coffres (namespaces)")
    p_vaults.set_defaults(func=cmd_vaults)

    # qr
    p_qr = subparsers.add_parser("qr", help="QR code da credencial (celular)")
    p_qr.add_argument("id", help="Prefixo do ID (8 chars)")
    p_qr.set_defaults(func=cmd_qr)

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
    storage.definir_namespace(args.vault)
    args.func(args)


if __name__ == "__main__":
    main()
