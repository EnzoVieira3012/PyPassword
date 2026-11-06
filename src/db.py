"""Persistência alternativa em SQLite, mantendo a API `Vault`.

Mesmo contrato de `storage.py` (init/save/load/backup/restore + namespaces),
mas o `Vault` é serializado em uma tabela normalizada (3FN) e o arquivo
`.db` é cifrado em repouso com `crypto.encrypt_data` antes de ir para disco.
`dados*.enc` continua sendo o artefato que viaja.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import tempfile
from collections.abc import Iterator

import src.storage as storage
from src.crypto import encrypt_data, decrypt_data
from src.models import PasswordEntry, Vault

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    id         TEXT PRIMARY KEY,
    site       TEXT NOT NULL,
    username   TEXT NOT NULL,
    password   TEXT NOT NULL,
    notes      TEXT NOT NULL DEFAULT '',
    category   TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


@contextlib.contextmanager
def _conectar(caminho: str) -> Iterator[sqlite3.Connection]:
    """Conexão com commit/rollback automático e close garantido.

    Windows não libera o arquivo antes do `close()`; sem isso o tempfile
    de `save_vault_sql` quebra com `PermissionError: WinError 32`.
    """
    conn = sqlite3.connect(caminho)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def criar_banco(caminho: str) -> None:
    """Cria o schema em `caminho` (idempotente)."""
    with _conectar(caminho) as conn:
        conn.executescript(SCHEMA)


def salvar_db(vault: Vault, caminho: str) -> None:
    """Grava o vault no SQLite (substitui o conteúdo da tabela)."""
    criar_banco(caminho)
    with _conectar(caminho) as conn:
        conn.execute("DELETE FROM entries")
        conn.executemany(
            "INSERT INTO entries "
            "(id, site, username, password, notes, category, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    str(e.id),
                    e.site,
                    e.username,
                    e.password,
                    e.notes,
                    e.category,
                    e.created_at.isoformat(),
                    e.updated_at.isoformat(),
                )
                for e in vault
            ],
        )


def carregar_db(caminho: str) -> Vault:
    """Lê o SQLite e devolve um `Vault` com os índices reconstruídos."""
    with _conectar(caminho) as conn:
        conn.executescript(SCHEMA)
        linhas = conn.execute(
            "SELECT id, site, username, password, notes, category, created_at, updated_at "
            "FROM entries"
        ).fetchall()
    vault = Vault()
    for linha in linhas:
        vault.add(
            PasswordEntry.from_dict(
                {
                    "id": linha[0],
                    "site": linha[1],
                    "username": linha[2],
                    "password": linha[3],
                    "notes": linha[4],
                    "category": linha[5],
                    "created_at": linha[6],
                    "updated_at": linha[7],
                }
            )
        )
    return vault


def save_vault_sql(vault: Vault, chave: bytes) -> None:
    """Salva em SQLite e grava o `.db` cifrado em `storage.ARQUIVO_VAULT`."""
    fd, temporario = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        salvar_db(vault, temporario)
        with open(temporario, "rb") as f:
            dados = f.read()
        storage._gravar_atomico(encrypt_data(dados, chave), storage.ARQUIVO_VAULT)
    finally:
        if os.path.exists(temporario):
            os.remove(temporario)


def load_vault_sql(chave: bytes) -> Vault:
    """Decifra `storage.ARQUIVO_VAULT` e carrega do SQLite."""
    try:
        with open(storage.ARQUIVO_VAULT, "rb") as f:
            dados = decrypt_data(f.read(), chave)
    except FileNotFoundError as exc:
        raise storage.VaultCorrompido("Arquivo nao encontrado") from exc
    except PermissionError as exc:
        raise storage.VaultCorrompido("Sem permissao de leitura") from exc
    except (ValueError, OSError) as exc:
        raise storage.VaultCorrompido("Vault corrompido ou chave errada") from exc

    fd, temporario = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        with open(temporario, "wb") as f:
            f.write(dados)
        return carregar_db(temporario)
    except sqlite3.DatabaseError as exc:
        raise storage.VaultCorrompido("Banco SQLite invalido") from exc
    finally:
        if os.path.exists(temporario):
            os.remove(temporario)


def init_vault_sql(chave: bytes) -> None:
    """Cria um vault SQLite vazio já cifrado."""
    save_vault_sql(Vault(), chave)
