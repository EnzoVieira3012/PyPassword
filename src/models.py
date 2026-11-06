"""Camada de domínio do cofre de senhas.

Analogia SQL:
    PasswordEntry -> tabela normalizada em 3FN: colunas atômicas, sem grupos
                     repetitivos e sem dependência transitiva (só `id` como PK).
    Vault         -> repositório/DAO: INSERT/UPDATE/DELETE/SELECT, índices de
                     busca, view pública sem senha e trigger de `updated_at`.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator

CAMPOS_EDITAVEIS = ("site", "username", "password", "notes", "category")


class PasswordEntry:
    """Uma credencial = uma linha da tabela `password_entry` (3FN).

    Attributes:
        id: Chave primária (UUID4).
        site: Serviço/site da credencial (normalizado com strip).
        username: Login usado no serviço (strip).
        password: Senha em texto puro, apenas em memória. Nunca sofre strip,
            pois espaço pode ser parte da senha.
        notes: Observações livres.
        created_at: Data/hora UTC de criação.
        updated_at: Data/hora UTC da última alteração (trigger).
    """

    def __init__(
        self,
        site: str,
        username: str,
        password: str,
        notes: str = "",
        category: str = "",
        id: uuid.UUID | None = None,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        agora = datetime.now(timezone.utc)
        self.id = id or uuid.uuid4()
        self.site = site.strip()
        self.username = username.strip()
        self.password = password
        self.notes = notes.strip()
        self.category = category.strip()
        self.created_at = created_at or agora
        self.updated_at = updated_at or agora

    def to_dict(self) -> dict[str, Any]:
        """Serializa para JSON-compatível (datetime -> ISO 8601).

        Returns:
            Dicionário com os 7 campos, pronto para `json.dumps`.
        """
        return {
            "id": str(self.id),
            "site": self.site,
            "username": self.username,
            "password": self.password,
            "notes": self.notes,
            "category": self.category,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PasswordEntry:
        """Reconstrói a entidade a partir de um dicionário (inverso de `to_dict`).

        Args:
            data: Dicionário com `id`, `site`, `username`, `password`,
                `created_at`, `updated_at`; `notes` é opcional.

        Returns:
            Nova `PasswordEntry`.

        Raises:
            ValueError: Se faltar campo obrigatório ou algum valor for inválido.
        """
        try:
            return cls(
                id=uuid.UUID(data["id"]),
                site=data["site"],
                username=data["username"],
                password=data["password"],
                notes=data.get("notes", ""),
                category=data.get("category", ""),
                created_at=datetime.fromisoformat(data["created_at"]),
                updated_at=datetime.fromisoformat(data["updated_at"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Dados inválidos: {exc}") from exc

    def __str__(self) -> str:
        """View de exibição: senha mascarada, resto em colunas alinhadas."""
        return (
            f"{str(self.id)[:8]} | {self.site:<16} | {self.username:<16} | "
            f"*** | {self.category:<12} | {self.notes[:30]}"
        )


class Vault:
    """Agregador de credenciais: repository/DAO sobre `list[PasswordEntry]`.

    Índices internos espelham os índices de busca SQL:
        `_by_id`   -> PRIMARY KEY
        `_by_site` -> INDEX (site)
        `_by_user` -> INDEX (username)

    Também implementa o Container Protocol (`len`, `in`, `for`).
    """

    def __init__(self) -> None:
        self._entries: list[PasswordEntry] = []
        self._by_id: dict[uuid.UUID, PasswordEntry] = {}
        self._by_site: dict[str, list[PasswordEntry]] = {}
        self._by_user: dict[str, list[PasswordEntry]] = {}
        self._by_category: dict[str, list[PasswordEntry]] = {}

    # -- índices -----------------------------------------------------------
    def _index(self, entry: PasswordEntry) -> None:
        self._by_id[entry.id] = entry
        self._by_site.setdefault(entry.site.lower(), []).append(entry)
        self._by_user.setdefault(entry.username.lower(), []).append(entry)
        self._by_category.setdefault(entry.category.lower(), []).append(entry)

    def _unindex(self, entry: PasswordEntry) -> None:
        self._by_id.pop(entry.id, None)
        for indice in (self._by_site, self._by_user, self._by_category):
            for chave in [k for k, v in indice.items() if any(e is entry for e in v)]:
                indice[chave] = [e for e in indice[chave] if e is not entry]
                if not indice[chave]:
                    del indice[chave]

    # -- CRUD --------------------------------------------------------------
    def add(self, entry: PasswordEntry) -> str:
        """INSERT: insere a entrada e dispara o trigger de timestamps.

        Args:
            entry: Entidade a inserir.

        Returns:
            `str(entry.id)` (PK gerada/confirmada).
        """
        agora = datetime.now(timezone.utc)
        entry.created_at = agora
        entry.updated_at = agora
        self._entries.append(entry)
        self._index(entry)
        return str(entry.id)

    def get(self, id: uuid.UUID | str) -> PasswordEntry | None:
        """SELECT BY PRIMARY KEY.

        Args:
            id: UUID ou string UUID.

        Returns:
            A entrada, ou `None` se não existir (UUID inválido também dá `None`).
        """
        if isinstance(id, str):
            try:
                id = uuid.UUID(id)
            except ValueError:
                return None
        return self._by_id.get(id)

    def list_all(self) -> list[PasswordEntry]:
        """VIEW pública: SELECT * ORDER BY created_at DESC (sem senha na saída)."""
        return sorted(self._entries, key=lambda e: e.created_at, reverse=True)

    def search(self, termo: str) -> list[PasswordEntry]:
        """SELECT WHERE site LIKE %termo% OR username LIKE %termo% (case-insensitive).

        Args:
            termo: Texto buscado. Vazio retorna todas as entradas.
        """
        termo = termo.strip().lower()
        return [
            e
            for e in self._entries
            if termo in e.site.lower()
            or termo in e.username.lower()
            or termo in e.category.lower()
            or termo in e.notes.lower()
        ]

    def update(self, id: uuid.UUID | str, **campos: Any) -> bool:
        """UPDATE: altera campos permitidos e dispara o trigger `updated_at`.

        Campos fora de `site`, `username`, `password`, `notes` são ignorados.
        Strings sofrem strip, exceto `password`.

        Returns:
            `True` se a entrada existia e foi atualizada.
        """
        entry = self.get(id)
        if entry is None:
            return False
        chaves_antes = (entry.site.lower(), entry.username.lower(), entry.category.lower())
        for campo, valor in campos.items():
            if campo in CAMPOS_EDITAVEIS:
                if isinstance(valor, str) and campo != "password":
                    valor = valor.strip()
                setattr(entry, campo, valor)
        if (entry.site.lower(), entry.username.lower(), entry.category.lower()) != chaves_antes:
            self._unindex(entry)
            self._index(entry)
        entry.updated_at = datetime.now(timezone.utc)
        return True

    def delete(self, id: uuid.UUID | str) -> bool:
        """DELETE: remove a entrada e seus índices.

        Returns:
            `True` se algo foi removido.
        """
        entry = self.get(id)
        if entry is None:
            return False
        self._entries = [e for e in self._entries if e is not entry]
        self._unindex(entry)
        return True

    # -- Container Protocol ------------------------------------------------
    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[PasswordEntry]:
        return iter(self._entries)

    def __contains__(self, id: object) -> bool:
        if not isinstance(id, (uuid.UUID, str)):
            return False
        return self.get(id) is not None

    # -- backup / restore --------------------------------------------------
    def backup(self) -> bytes:
        """Serializa o cofre inteiro em JSON UTF-8 (a criptografia vem depois)."""
        return json.dumps(
            [e.to_dict() for e in self._entries], ensure_ascii=False
        ).encode("utf-8")

    @classmethod
    def restore(cls, data: bytes) -> Vault:
        """Deserializa JSON UTF-8 em um `Vault` novo.

        Preserva `created_at`/`updated_at` originais: não usa `add()`, que
        sobrescreveria os timestamps.

        Raises:
            ValueError: Se o JSON for inválido ou alguma entrada estiver corrompida.
        """
        try:
            lista = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Backup inválido: {exc}") from exc
        if not isinstance(lista, list):
            raise ValueError("Backup inválido: esperado uma lista de entradas")
        vault = cls()
        for item in lista:
            entry = PasswordEntry.from_dict(item)
            vault._entries.append(entry)
            vault._index(entry)
        return vault
