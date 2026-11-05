"""Camada de persistência do cofre.

Analogia SQL:
    save_vault()    -> BEGIN TRAN → serialize → encrypt → atomic write → COMMIT
    load_vault()    -> SELECT com validação de integridade (HMAC antes de tudo)
    backup_vault()  -> BACKUP DATABASE (versionado)
    restore_vault() -> RESTORE DATABASE (valida antes de sobrescrever)
"""

from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone

from cryptography.fernet import InvalidToken

from crypto import decrypt_data, encrypt_data
from models import Vault

ARQUIVO_VAULT = "dados.enc"
PREFIXO_BACKUP = "dados.enc.bak."


class VaultCorrompido(Exception):
    """O arquivo do cofre existe mas não abre.

    Cobre os três modos de falha da leitura, que são indistinguíveis para quem
    chama: chave mestra errada, arquivo adulterado/truncado (HMAC inválido) e
    JSON inválido mesmo com HMAC correto.
    """


def vault_existe() -> bool:
    """CHECK EXISTS `dados.enc`.

    Usado para decidir entre primeira execução (`init_vault`) e login normal
    (`load_vault`) antes de qualquer tentativa de leitura.

    Returns:
        `True` se o arquivo criptografado existe no diretório atual.
    """
    return os.path.exists(ARQUIVO_VAULT)


def _gravar_atomico(dados: bytes, destino: str) -> None:
    """Escreve em `destino.tmp`, força o disco e só então troca o arquivo final.

    Crash ou queda de energia no meio: `dados.enc` continua intacto e sobra um
    `.tmp` órfão, que a próxima gravação sobrescreve. `os.replace` é atômico no
    POSIX e substitui a existente no Windows (`os.rename` falharia lá).

    Args:
        dados: Bytes já criptografados.
        destino: Caminho final.

    Raises:
        OSError: Falha de I/O (disco cheio, permissão). O temporário é removido.
    """
    temporario = f"{destino}.tmp"
    try:
        with open(temporario, "wb") as arquivo:
            arquivo.write(dados)
            arquivo.flush()
            os.fsync(arquivo.fileno())
        # ponytail: fsync do diretório não é feito (não portável no Windows).
        # Adicionar se o projeto rodar em servidor Linux com requisito de durability.
        os.replace(temporario, destino)
    except BaseException:
        if os.path.exists(temporario):
            try:
                os.remove(temporario)  # ROLLBACK
            except OSError:
                pass  # best effort: o próximo save sobrescreve
        raise


def save_vault(vault: Vault, chave: bytes) -> None:
    """COMMIT: serializa → criptografa → grava atomicamente.

    Args:
        vault: Instância a persistir.
        chave: Chave mestra de 64+ bytes (`crypto.derivar_chave`).

    Raises:
        ValueError: Chave mestra curta demais.
        OSError: Falha de I/O. O arquivo anterior permanece intacto.
    """
    _gravar_atomico(encrypt_data(vault.backup(), chave), ARQUIVO_VAULT)


def init_vault(chave: bytes) -> Vault:
    """CREATE VAULT: cria cofre vazio e persiste (equivalente a CREATE TABLE + COMMIT).

    Args:
        chave: Chave mestra de 64+ bytes.

    Returns:
        `Vault` vazio já gravado em `dados.enc`.
    """
    vault = Vault()
    save_vault(vault, chave)
    return vault


def _carregar(caminho: str, chave: bytes) -> Vault:
    """Lê, valida HMAC, decodifica JSON e restaura o vault de um caminho qualquer.

    Raises:
        FileNotFoundError: Arquivo ausente.
        PermissionError: Sem permissão de leitura.
        VaultCorrompido: HMAC inválido, chave errada ou JSON inválido.
    """
    try:
        with open(caminho, "rb") as arquivo:
            token = arquivo.read()
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Vault não encontrado: {caminho}") from exc
    except PermissionError as exc:
        raise PermissionError(f"Sem permissão para ler: {caminho}") from exc

    try:
        dados = decrypt_data(token, chave)  # valida HMAC ANTES de descriptografar
    except (ValueError, InvalidToken) as exc:
        raise VaultCorrompido(
            f"Vault ilegível (chave errada ou arquivo adulterado): {caminho}"
        ) from exc

    try:
        return Vault.restore(dados)
    except ValueError as exc:
        raise VaultCorrompido(f"Conteúdo do vault inválido: {caminho}") from exc


def load_vault(chave: bytes) -> Vault:
    """SELECT: carrega o cofre do disco com validação de integridade.

    Args:
        chave: Chave mestra de 64+ bytes.

    Returns:
        `Vault` restaurado.

    Raises:
        FileNotFoundError: `dados.enc` não existe (use `init_vault`).
        PermissionError: Sem permissão de leitura.
        VaultCorrompido: Chave errada, arquivo adulterado/truncado ou JSON inválido.
    """
    return _carregar(ARQUIVO_VAULT, chave)


def backup_vault() -> str:
    """BACKUP DATABASE: cópia versionada point-in-time.

    Returns:
        Caminho do backup criado, `dados.enc.bak.{ISO8601}` com microssegundos
        (evita colisão em backups seguidos).

    Raises:
        FileNotFoundError: Não existe cofre para copiar.
        OSError: Falha de cópia (disco cheio, permissão).
    """
    if not vault_existe():
        raise FileNotFoundError(f"Vault não existe para backup: {ARQUIVO_VAULT}")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S-%f")
    destino = f"{PREFIXO_BACKUP}{timestamp}"
    shutil.copy2(ARQUIVO_VAULT, destino)  # copy2 preserva mtime
    return destino


def restore_vault(backup_path: str, chave: bytes) -> Vault:
    """RESTORE DATABASE: valida o backup e só então substitui o cofre atual.

    A validação acontece antes da cópia de propósito: um backup corrompido não
    pode destruir o `dados.enc` que ainda estava legível.

    Args:
        backup_path: Caminho do backup.
        chave: Chave mestra de 64+ bytes.

    Returns:
        `Vault` restaurado (e já gravado como `dados.enc`).

    Raises:
        FileNotFoundError: Backup não existe.
        VaultCorrompido: Backup ilegível. `dados.enc` permanece intacto.
        OSError: Falha de I/O.
    """
    if not os.path.exists(backup_path):
        raise FileNotFoundError(f"Backup não encontrado: {backup_path}")
    vault = _carregar(backup_path, chave)  # valida ANTES de sobrescrever
    with open(backup_path, "rb") as arquivo:
        _gravar_atomico(arquivo.read(), ARQUIVO_VAULT)
    return vault
