"""Sincronizacao local do cofre cifrado (pasta/git/OneDrive/Dropbox).

O que viaja sao os proprios arquivos cifrados: `dados*.enc` (cifrado),
`salt*.bin` e `hash*.bin` (publicos por natureza). A chave mestra nunca sai
do dispositivo — a senha mestra e digitada em cada maquina.
"""

from __future__ import annotations

import os
import shutil

import src.storage as storage

ARQUIVOS_EXTRA = ("ARQUIVO_SALT", "ARQUIVO_HASH")


def _nomes_arquivos() -> list[str]:
    """Nomes dos arquivos do namespace atual (vault + salt + hash)."""
    return [storage.ARQUIVO_VAULT] + [getattr(storage, n) for n in ARQUIVOS_EXTRA]


def sincronizar(destino: str) -> list[str]:
    """Envia (push) os arquivos do cofre para `destino`. Retorna copiados."""
    os.makedirs(destino, exist_ok=True)
    copiados: list[str] = []
    for nome in _nomes_arquivos():
        if os.path.exists(nome):
            shutil.copy2(nome, os.path.join(destino, nome))
            copiados.append(nome)
    return copiados


def puxar(origem: str, chave: bytes) -> list[str]:
    """Traz (pull) o cofre de `origem`, validando antes de sobrescrever.

    O vault remoto e decifrado primeiro; so se abrir com `chave` os arquivos
    locais sao substituidos. Um sync corrompido nao destroi o cofre local.

    Args:
        origem: Pasta com os arquivos do cofre.
        chave: Chave mestra derivada (usada para validar o vault remoto).

    Returns:
        Nomes dos arquivos substituidos.

    Raises:
        FileNotFoundError: Se o vault remoto nao existir.
        storage.VaultCorrompido: Se o vault remoto nao abrir com `chave`.
    """
    remoto = os.path.join(origem, storage.ARQUIVO_VAULT)
    if not os.path.exists(remoto):
        raise FileNotFoundError(f"Vault remoto nao encontrado: {remoto}")
    storage._carregar(remoto, chave)  # valida antes de tocar no local

    substituidos: list[str] = []
    for nome in _nomes_arquivos():
        origem_arquivo = os.path.join(origem, nome)
        if os.path.exists(origem_arquivo):
            if nome == storage.ARQUIVO_VAULT:
                storage.backup_vault()
            shutil.copy2(origem_arquivo, nome)
            substituidos.append(nome)
    return substituidos
