"""Utilitários de interface: geração de senha, validação, tabela e UX.

Analogia SQL: `formatar_saida` é a VIEW pública (`SELECT id, site, username,
'***', notes`) — a senha nunca sai daqui.
"""

from __future__ import annotations

import os
import re
import secrets
import string

from src.models import PasswordEntry

MAIUSCULAS = string.ascii_uppercase
MINUSCULAS = string.ascii_lowercase
DIGITOS = string.digits
SIMBOLOS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
TODOS = MAIUSCULAS + MINUSCULAS + DIGITOS + SIMBOLOS

TAMANHO_MINIMO_SENHA = 4  # precisa de 4 posições para cobrir os 4 tipos
LIMITE_SITE = 255
LIMITE_USERNAME = 255
LIMITE_SENHA = 500

_CONTROLES = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def gerar_senha_aleatoria(tamanho: int = 16) -> str:
    """Gera senha com CSPRNG, garantindo os 4 tipos de caractere.

    `secrets` usa `os.urandom` (entropia do SO). `random` (Mersenne Twister)
    é previsível depois de 624 saídas — nunca usar para senha.

    Args:
        tamanho: Comprimento desejado (mínimo 4).

    Returns:
        Senha com 1+ maiúscula, 1+ minúscula, 1+ dígito e 1+ símbolo,
        em ordem embaralhada.

    Raises:
        ValueError: Se `tamanho` < 4.
    """
    if tamanho < TAMANHO_MINIMO_SENHA:
        raise ValueError(
            f"Tamanho mínimo {TAMANHO_MINIMO_SENHA} (um por tipo), recebeu {tamanho}"
        )

    caracteres = [
        secrets.choice(MAIUSCULAS),
        secrets.choice(MINUSCULAS),
        secrets.choice(DIGITOS),
        secrets.choice(SIMBOLOS),
    ]
    caracteres += [secrets.choice(TODOS) for _ in range(tamanho - 4)]
    secrets.SystemRandom().shuffle(caracteres)  # senão os 4 fixos ficam na frente
    return "".join(caracteres)


def sanitizar_texto(valor: str) -> str:
    """Remove caracteres de controle e espaços nas pontas.

    Args:
        valor: Texto digitado pelo usuário.

    Returns:
        Texto sem controles (`\\x00-\\x08`, `\\x0b`, `\\x0c`, `\\x0e-\\x1f`,
        `\\x7f`), preservando `\\t`, `\\n` e `\\r`, com `strip()`.

    Note:
        Use antes de `Vault.add`. `validar_entrada` valida mas não devolve o
        texto sanitizado (a assinatura devolve `(valido, erro)`), então quem
        grava precisa chamar isto.
    """
    return _CONTROLES.sub("", valor).strip()


def validar_entrada(
    site: str, username: str, password: str, notes: str
) -> tuple[bool, str]:
    """Valida os campos obrigatórios em cascata (site → usuário → senha → notas).

    A senha **não** é sanitizada: alterar a senha digitada faria o cofre guardar
    algo diferente do que o site espera. Só é checada contra vazio.

    Args:
        site: Site/serviço.
        username: Login.
        password: Senha em texto puro.
        notes: Observações (opcional).

    Returns:
        `(True, "")` se válido, `(False, "mensagem")` no primeiro erro.
    """
    site, username, notes = (sanitizar_texto(campo) for campo in (site, username, notes))

    if not site:
        return False, "Site é obrigatório"
    if not username:
        return False, "Usuário/e-mail é obrigatório"
    if not password or not password.strip():
        return False, "Senha é obrigatória"

    if len(site) > LIMITE_SITE:
        return False, f"Site muito longo (máx {LIMITE_SITE} caracteres)"
    if len(username) > LIMITE_USERNAME:
        return False, f"Usuário muito longo (máx {LIMITE_USERNAME} caracteres)"
    if len(password) > LIMITE_SENHA:
        return False, f"Senha muito longa (máx {LIMITE_SENHA} caracteres)"

    return True, ""


def formatar_saida(entradas: list[PasswordEntry]) -> str:
    """Monta tabela ASCII alinhada a partir da lista de entradas.

    Largura de cada coluna = `max(header, maior célula) + 2`. A senha sai
    sempre como `***` (view pública, equivalente ao SELECT que omite a coluna).

    Args:
        entradas: Entradas a exibir.

    Returns:
        Tabela pronta para `print`, ou `"(vazio)"` se a lista estiver vazia.
    """
    if not entradas:
        return "(vazio)"

    cabecalhos = ["ID", "Site", "Usuário", "Senha", "Observações"]
    # ponytail: len() conta code points. Emoji/ideogramas largos desalinham;
    # trocar por wcwidth se a tabela precisar de CJK.
    linhas = [
        [str(e.id)[:8], e.site, e.username, "***", e.notes] for e in entradas
    ]

    larguras = [
        max(len(cabecalhos[i]), *(len(linha[i]) for linha in linhas)) + 2
        for i in range(len(cabecalhos))
    ]

    def juntar(celulas: list[str]) -> str:
        return " | ".join(celula.ljust(largura) for celula, largura in zip(celulas, larguras))

    tabela = [juntar(cabecalhos), "-+-".join("-" * largura for largura in larguras)]
    tabela += [juntar(linha) for linha in linhas]
    return "\n".join(tabela)


def pausar(mensagem: str = "Pressione Enter para continuar...") -> None:
    """Aguarda Enter, propagando Ctrl+C e Ctrl+D para o chamador tratar.

    Raises:
        EOFError: Entrada encerrada (Ctrl+D / stdin fechado).
        KeyboardInterrupt: Ctrl+C.
    """
    try:
        input(mensagem)
    except (EOFError, KeyboardInterrupt):
        print()  # evita o prompt colar na próxima linha do terminal
        raise


def limpar_tela() -> None:
    """Limpa o terminal (`cls` no Windows, `clear` no resto)."""
    os.system("cls" if os.name == "nt" else "clear")  # noqa: S605 — comando fixo
