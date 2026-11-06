"""Interface grafica Tkinter (stdlib) para o PyTask."""

from __future__ import annotations

import secrets
import sys
import tkinter as tk
from datetime import datetime, timezone
from tkinter import messagebox, simpledialog, ttk

from src.crypto import derivar_chave, hash_senha_mestra
from src.models import PasswordEntry, Vault
import src.storage as storage
from src.storage import (
    init_vault,
    load_vault,
    save_vault,
    vault_existe,
)
from src.utils import gerar_senha_aleatoria, validar_entrada


def linhas_tabela(vault: Vault) -> list[tuple[str, str, str, str, str, str]]:
    """View do vault -> linhas da Treeview (id curto, senha mascarada)."""
    return [
        (
            str(e.id)[:8],
            e.site,
            e.username,
            "***",
            e.category,
            e.notes,
        )
        for e in vault.list_all()
    ]


class App(tk.Tk):
    """Janela principal."""

    def __init__(self, vault: Vault, chave: bytes) -> None:
        super().__init__()
        self.vault = vault
        self.chave = chave
        self.title("PyTask - Gerenciador de Senhas")
        self.geometry("820x420")
        self._montar()

    # -- widgets ---------------------------------------------------------
    def _montar(self) -> None:
        colunas = ("id", "site", "usuario", "senha", "categoria", "notas")
        self.tree = ttk.Treeview(self, columns=colunas, show="headings")
        larguras = {"id": 80, "site": 160, "usuario": 140, "senha": 70,
                    "categoria": 120, "notas": 200}
        for col in colunas:
            self.tree.heading(col, text=col.capitalize())
            self.tree.column(col, width=larguras[col], anchor="w")
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)

        barra = ttk.Frame(self)
        barra.pack(fill="x", padx=8, pady=(0, 8))
        for texto, comando in (
            ("Adicionar", self.adicionar),
            ("Editar", self.editar),
            ("Excluir", self.excluir),
            ("Gerar senha", self.gerar_senha),
            ("Atualizar", self.atualizar),
        ):
            ttk.Button(barra, text=texto, command=comando).pack(side="left", padx=4)

        self.atualizar()

    def atualizar(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for linha in linhas_tabela(self.vault):
            self.tree.insert("", "end", values=linha)

    # -- acoes -----------------------------------------------------------
    def _selecionada(self) -> PasswordEntry | None:
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("PyTask", "Selecione uma entrada.")
            return None
        prefixo = str(self.tree.item(sel[0], "values")[0])
        for entrada in self.vault:
            if str(entrada.id).startswith(prefixo):
                return entrada
        return None

    def _perguntar(
        self, titulo: str, rotulo: str, inicial: str = "", oculto: bool = False
    ) -> str | None:
        return simpledialog.askstring(
            titulo, rotulo, initialvalue=inicial, show="*" if oculto else None,
            parent=self,
        )

    def adicionar(self) -> None:
        site = self._perguntar("Adicionar", "Site:")
        if site is None:
            return
        username = self._perguntar("Adicionar", "Usuario:")
        if username is None:
            return
        password = self._perguntar("Adicionar", "Senha:", oculto=True)
        if password is None:
            return
        notes = self._perguntar("Adicionar", "Notas (opcional):", "") or ""
        category = self._perguntar("Adicionar", "Categoria (opcional):", "") or ""
        ok, erro = validar_entrada(site, username, password, notes, category)
        if not ok:
            messagebox.showerror("PyTask", erro)
            return
        agora = datetime.now(timezone.utc)
        self.vault.add(
            PasswordEntry(
                site=site, username=username, password=password,
                notes=notes, category=category, created_at=agora, updated_at=agora,
            )
        )
        save_vault(self.vault, self.chave)
        self.atualizar()

    def editar(self) -> None:
        entrada = self._selecionada()
        if entrada is None:
            return
        site = self._perguntar("Editar", f"Site [{entrada.site}]:", entrada.site)
        if site is None:
            return
        username = self._perguntar(
            "Editar", f"Usuario [{entrada.username}]:", entrada.username
        )
        if username is None:
            return
        password = self._perguntar("Editar", "Nova senha (vazio mantem):", oculto=True)
        if password is None:
            return
        notes = self._perguntar("Editar", f"Notas [{entrada.notes}]:", entrada.notes)
        if notes is None:
            return
        category = self._perguntar(
            "Editar", f"Categoria [{entrada.category}]:", entrada.category
        )
        if category is None:
            return
        novos: dict[str, str] = {
            "site": site, "username": username,
            "notes": notes, "category": category,
        }
        if password:
            novos["password"] = password
        ok, erro = validar_entrada(
            novos["site"], novos["username"],
            novos.get("password", entrada.password), novos["notes"], novos["category"],
        )
        if not ok:
            messagebox.showerror("PyTask", erro)
            return
        self.vault.update(entrada.id, **novos)
        save_vault(self.vault, self.chave)
        self.atualizar()

    def excluir(self) -> None:
        entrada = self._selecionada()
        if entrada is None:
            return
        if not messagebox.askyesno(
            "PyTask", f"Excluir {entrada.site} ({entrada.username})?\n\nAcao irreversivel."
        ):
            return
        self.vault.delete(entrada.id)
        save_vault(self.vault, self.chave)
        self.atualizar()

    def gerar_senha(self) -> None:
        tamanho = simpledialog.askinteger(
            "PyTask", "Tamanho da senha (4-128):", initialvalue=16,
            minvalue=4, maxvalue=128, parent=self,
        )
        if tamanho is None:
            return
        senha = gerar_senha_aleatoria(tamanho)
        messagebox.showinfo("PyTask", f"Senha gerada ({tamanho} chars):\n\n{senha}")


def _primeira_execucao_gui() -> tuple[bytes | None, Vault | None]:
    """Setup inicial: senha mestre 2x, salt, hash, vault vazio."""
    senha = simpledialog.askstring("PyTask", "Crie a senha mestre:", show="*")
    if not senha:
        return None, None
    confirmacao = simpledialog.askstring("PyTask", "Confirme a senha mestre:", show="*")
    if senha != confirmacao:
        messagebox.showerror("PyTask", "Senhas nao conferem.")
        return None, None
    salt = secrets.token_bytes(16)
    with open(storage.ARQUIVO_SALT, "wb") as f:
        f.write(salt)
    chave = derivar_chave(senha, salt)
    hash_senha_mestra(senha, salt, storage.ARQUIVO_HASH)
    init_vault(chave)
    return chave, load_vault(chave)


def _login_gui() -> tuple[bytes | None, Vault | None]:
    senha = simpledialog.askstring("PyTask", "Senha mestra:", show="*")
    if not senha:
        return None, None
    try:
        with open(storage.ARQUIVO_SALT, "rb") as f:
            salt = f.read()
        with open(storage.ARQUIVO_HASH, "rb") as f:
            esperado = f.read()
    except OSError:
        messagebox.showerror("PyTask", "Arquivos de autenticacao nao encontrados.")
        return None, None
    chave = derivar_chave(senha, salt)
    import hmac as _hmac

    if not _hmac.compare_digest(hash_senha_mestra(senha, salt, None), esperado):
        messagebox.showerror("PyTask", "Senha mestra incorreta.")
        return None, None
    return chave, load_vault(chave)


def main() -> None:
    if vault_existe():
        chave, vault = _login_gui()
    else:
        chave, vault = _primeira_execucao_gui()
    if chave is None or vault is None:
        sys.exit(1)
    App(vault, chave).mainloop()


if __name__ == "__main__":
    main()
