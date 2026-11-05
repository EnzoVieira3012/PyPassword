# PyTask — Gerenciador de Senhas (CLI)

Projeto de consolidação dos cursos **Python (9 aulas)**, **Lógica de Programação
(16 aulas)** e **SQL (9 aulas)**: cofre de senhas local, criptografado, em Python
puro + `cryptography`.

## Arquitetura (3 camadas + padrões SQL)

```
password_manager/
├── main.py       # Apresentação: menu, fluxos, autenticação
├── crypto.py     # Criptografia: PBKDF2, Fernet, HMAC, hash de senha mestra
├── storage.py    # Persistência: save/load atômico, backup, restore
├── models.py     # Domínio: PasswordEntry + Vault
├── utils.py      # Utilitários: geração de senha, validação, tabelas CLI
├── dados.enc     # Cofre criptografado (equivalente a tablespace)
├── chave.key     # Chave Fernet
├── salt.bin      # Salt PBKDF2
└── hash.bin      # Hash da senha mestra
```

## Domínio (`models.py`)

### `PasswordEntry` — tabela normalizada em 3FN

Uma credencial = uma linha. 7 colunas atômicas, sem grupos repetitivos e sem
dependência transitiva (apenas `id` é PK):

| Coluna | Tipo | Observação |
| --- | --- | --- |
| `id` | `uuid.UUID` | PK (UUID4) |
| `site` | `str` | `strip()` na entrada |
| `username` | `str` | `strip()` na entrada |
| `password` | `str` | texto puro só em memória; **nunca** `strip()` |
| `notes` | `str` | observações |
| `created_at` | `datetime` | UTC |
| `updated_at` | `datetime` | UTC, atualizado pelo "trigger" do `Vault` |

Serialização: `to_dict()` (datetime → ISO 8601) / `from_dict()` (levanta
`ValueError` em dados corrompidos). `__str__` mascara a senha com `***`.

### `Vault` — Repository/DAO + Container Protocol

| Método | Equivalente SQL |
| --- | --- |
| `add(entry)` | `INSERT` + trigger de timestamps |
| `get(id)` | `SELECT ... WHERE id = ?` |
| `list_all()` | `SELECT * ORDER BY created_at DESC` (view pública) |
| `search(termo)` | `WHERE site LIKE %t% OR username LIKE %t%` |
| `update(id, **campos)` | `UPDATE` + trigger `updated_at` + reindexação |
| `delete(id)` | `DELETE` + limpeza de índices |
| `backup()` / `restore()` | `BACKUP` / `RESTORE` (JSON UTF-8) |
| `len()`, `in`, `for` | Container Protocol |

Índices em memória: `_by_id` (PK), `_by_site`, `_by_user` (mantidos em
`add`, `update` e `delete`).

## Rodar

```powershell
python -m unittest -v test_models
python -m mypy --strict models.py test_models.py
```

## Roadmap

- [x] `models.py` — `PasswordEntry` (entidade 3FN)
- [x] `models.py` — `Vault` (CRUD + índices + container + backup/restore)
- [ ] `crypto.py` — PBKDF2, Fernet, HMAC
- [ ] `storage.py` — save/load atômico, backup versionado
- [ ] `utils.py` — geração de senha, validação, tabela CLI
- [ ] `main.py` — menu, autenticação, fluxos
