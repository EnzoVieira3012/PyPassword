"""Camada de criptografia do cofre.

Analogia SQL: cada função aqui é uma *stored procedure* — lógica encapsulada,
recebe parâmetros IN e devolve um valor OUT, sem expor detalhes ao chamador.

Fluxo de chaves:

    senha mestra + salt --PBKDF2(100k, 64 bytes)--> chave mestra
    chave mestra --split--> chave_enc (32B) + chave_hmac (32B)
    dados --Fernet(chave_enc)--> ciphertext
    ciphertext --HMAC-SHA256(chave_hmac)--> tag
    token = ciphertext || tag          (Encrypt-then-MAC)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

ITERACOES_PBKDF2 = 100_000
TAMANHO_SALT = 16
TAMANHO_CHAVE_MAESTRA = 64  # 32 bytes para Fernet + 32 bytes para HMAC
TAMANHO_TAG = 32  # SHA-256

ARQUIVO_CHAVE = "chave.key"
ARQUIVO_HASH = "hash.bin"


def _validar_salt(salt: bytes) -> None:
    """Valida o tamanho do salt.

    Raises:
        ValueError: Se `salt` não tiver exatamente 16 bytes (128 bits).
    """
    if len(salt) != TAMANHO_SALT:
        raise ValueError(f"Salt deve ter {TAMANHO_SALT} bytes, recebeu {len(salt)}")


def derivar_chave(
    senha: str, salt: bytes, dklen: int = TAMANHO_CHAVE_MAESTRA
) -> bytes:
    """Deriva a chave mestra com PBKDF2-HMAC-SHA256.

    PBKDF2 é propositalmente lento (~100 ms com 100k iterações): transforma um
    ataque de força bruta de bilhões/s em ~10/s por núcleo. O salt único de
    16 bytes (2^128 combinações) inviabiliza rainbow tables.

    Args:
        senha: Senha mestra em texto puro.
        salt: Salt aleatório de 16 bytes (`secrets.token_bytes(16)`).
        dklen: Tamanho da chave derivada. Padrão 64 bytes, que é o mínimo
            aceito por `_dividir_chave_mestra` (32 enc + 32 hmac). Use 32
            apenas para usos que não passam por `encrypt_data`.

    Returns:
        Chave derivada com `dklen` bytes.

    Raises:
        ValueError: Se `salt` não tiver 16 bytes.
    """
    _validar_salt(salt)
    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=senha.encode("utf-8"),
        salt=salt,
        iterations=ITERACOES_PBKDF2,
        dklen=dklen,
    )


def gerar_chave_fernet(caminho: str | os.PathLike[str] = ARQUIVO_CHAVE) -> bytes:
    """Gera uma chave Fernet e a grava com permissão 0o600.

    Fernet = AES-128-CBC + HMAC-SHA256, chave de 32 bytes em base64 url-safe
    (44 bytes no arquivo).

    Args:
        caminho: Onde salvar a chave. Padrão `chave.key` no diretório atual.

    Returns:
        A chave Fernet gerada (44 bytes, base64 url-safe).

    Raises:
        OSError: Se não for possível escrever o arquivo.
    """
    chave = Fernet.generate_key()
    destino = Path(caminho)
    destino.write_bytes(chave)
    os.chmod(destino, 0o600)  # ponytail: no Windows só o bit read-only aplica
    return chave


def hash_senha_mestra(
    senha: str, salt: bytes, caminho: str | os.PathLike[str] = ARQUIVO_HASH
) -> bytes:
    """Calcula SHA-256(senha || salt) e grava em `hash.bin`.

    Usado **apenas** para verificar login (rápido, ~1 µs), nunca para
    criptografar. Comparar sempre com `secrets.compare_digest` / `hmac.compare_digest`.

    Args:
        senha: Senha mestra em texto puro.
        salt: Salt de 16 bytes, o mesmo usado em `derivar_chave`.
        caminho: Onde salvar o hash. Padrão `hash.bin`.

    Returns:
        Hash SHA-256 de 32 bytes.

    Raises:
        ValueError: Se `salt` não tiver 16 bytes.
        OSError: Se não for possível escrever o arquivo.
    """
    _validar_salt(salt)
    digest = hashlib.sha256(senha.encode("utf-8") + salt).digest()
    destino = Path(caminho)
    destino.write_bytes(digest)
    os.chmod(destino, 0o600)  # ponytail: no Windows só o bit read-only aplica
    return digest


def _dividir_chave_mestra(chave: bytes) -> tuple[bytes, bytes]:
    """Separa a chave mestra em chave de criptografia e chave de HMAC.

    Key separation principle: reutilizar a mesma chave para cifrar e autenticar
    abre espaço para ataques de extensão/relacionados. Duas metades
    independentes de 32 bytes eliminam isso.

    Args:
        chave: Chave mestra de pelo menos 64 bytes.

    Returns:
        Tupla `(chave_enc, chave_hmac)`, ambas com 32 bytes.

    Raises:
        ValueError: Se `chave` tiver menos de 64 bytes.
    """
    if len(chave) < TAMANHO_CHAVE_MAESTRA:
        raise ValueError(
            f"Chave mestra deve ter >= {TAMANHO_CHAVE_MAESTRA} bytes, "
            f"recebeu {len(chave)}"
        )
    return chave[:32], chave[32:64]


def encrypt_data(dados: bytes, chave_mestra: bytes) -> bytes:
    """Encrypt-then-MAC: Fernet(chave_enc) + HMAC-SHA256(chave_hmac, ciphertext).

    Encrypt-then-MAC é a ordem segura: o MAC cobre o ciphertext, então a
    verificação na leitura rejeita qualquer adulteração antes de descriptografar
    (evita padding oracle).

    Args:
        dados: Bytes a criptografar (JSON do vault).
        chave_mestra: Chave de 64+ bytes vinda de `derivar_chave`.

    Returns:
        Token = ciphertext || tag (últimos 32 bytes).

    Raises:
        ValueError: Se `chave_mestra` tiver menos de 64 bytes.
    """
    chave_enc, chave_hmac = _dividir_chave_mestra(chave_mestra)
    ciphertext = Fernet(base64.urlsafe_b64encode(chave_enc)).encrypt(dados)
    tag = hmac.new(chave_hmac, ciphertext, hashlib.sha256).digest()
    return ciphertext + tag


def decrypt_data(token: bytes, chave_mestra: bytes) -> bytes:
    """Verifica o HMAC (timing-safe) e só então descriptografa.

    Args:
        token: `ciphertext || tag`, como devolvido por `encrypt_data`.
        chave_mestra: Chave de 64+ bytes vinda de `derivar_chave`.

    Returns:
        Dados originais.

    Raises:
        ValueError: Token com menos de 32 bytes, ou HMAC inválido (dados
            adulterados, truncados ou chave errada).
        InvalidToken: HMAC válido mas o ciphertext não abre (praticamente
            inalcançável; existe como rede de segurança).
    """
    if len(token) <= TAMANHO_TAG:
        raise ValueError(
            f"Token muito curto: {len(token)} bytes (mínimo {TAMANHO_TAG + 1})"
        )
    ciphertext, tag_recebida = token[:-TAMANHO_TAG], token[-TAMANHO_TAG:]
    chave_enc, chave_hmac = _dividir_chave_mestra(chave_mestra)

    tag_esperada = hmac.new(chave_hmac, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag_recebida, tag_esperada):
        raise ValueError("HMAC inválido: dados corrompidos ou chave errada")

    try:
        return Fernet(base64.urlsafe_b64encode(chave_enc)).decrypt(ciphertext)
    except InvalidToken as exc:
        raise InvalidToken(
            "Falha ao descriptografar: chave errada ou dados corrompidos"
        ) from exc
