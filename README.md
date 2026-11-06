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

## Criptografia (`crypto.py`)

Cada função é uma "stored procedure": recebe parâmetros, devolve valor, não
expõe detalhes.

| Função | Algoritmo | Saída |
| --- | --- | --- |
| `derivar_chave(senha, salt, dklen=64)` | PBKDF2-HMAC-SHA256, 100k iterações | 64 bytes (32 enc + 32 hmac) |
| `gerar_chave_fernet(caminho)` | `Fernet.generate_key()` | 44 bytes + arquivo `chave.key` (0o600) |
| `hash_senha_mestra(senha, salt, caminho)` | SHA-256(senha \|\| salt), 1 iteração | 32 bytes + `hash.bin` |
| `_dividir_chave_mestra(chave)` | slice `[:32]` / `[32:64]` | `(chave_enc, chave_hmac)` |
| `encrypt_data(dados, chave)` | Fernet + HMAC-SHA256(ciphertext) | `ciphertext \|\| tag(32)` |
| `decrypt_data(token, chave)` | HMAC timing-safe → Fernet | dados originais |

Fluxo de chaves:

```
senha + salt --PBKDF2(100k, 64B)--> chave mestra
chave mestra --split--> chave_enc(32) + chave_hmac(32)
dados --Fernet(chave_enc)--> ciphertext --HMAC(chave_hmac)--> tag
token = ciphertext || tag        (Encrypt-then-MAC)
```

### Por que 100.000 iterações

SHA-256 puro roda em ~1 µs: um atacante testa bilhões de senhas por segundo.
PBKDF2 com 100k iterações custa ~50-100 ms por tentativa, ou seja ~10-20/s por
núcleo — lento o bastante para inviabilizar força bruta e ainda aceitável no
login (uma vez por sessão). O custo cresce linear com as iterações: aumentar
para 600k (recomendação OWASP atual) multiplica o tempo por 6 e exige rederivar
a chave mestra — por isso a constante `ITERACOES_PBKDF2` fica isolada.

### Por que salt de 16 bytes

16 bytes = 128 bits = 2^128 salts possíveis. Um salt único por cofre impede
rainbow tables: o atacante precisaria pré-calcular uma tabela por salt. É
aleatório (`secrets.token_bytes(16)`), guardado em `salt.bin` e público por
natureza — não precisa de sigilo, só de unicidade.

### Por que 0o600 em `chave.key`

`rw-------` = só o owner lê/escreve. Em máquina multi-usuário (Linux/WSL,
servidor) impede que outro usuário copie a chave e abra o cofre. No Windows o
`os.chmod` só aplica o bit read-only — a proteção real lá vem das ACLs do
perfil do usuário.

### `chave.key` nunca vai para o git

`.gitignore` já cobre `chave.key`, `salt.bin`, `hash.bin`, `dados.enc` e
`dados.enc.bak`. Backup seguro da chave = cópia offline (pendrive/gerenciador
de senhas) ou repositório privado separado — sem ela o cofre é irrecuperável.

### Encrypt-then-MAC

MAC calculado sobre o *ciphertext*, verificado **antes** de descriptografar.
MAC-then-Encrypt é vulnerável a padding oracle; Encrypt-and-MAC vaza padrões do
plaintext. A comparação usa `hmac.compare_digest` (tempo constante).

## Persistência (`storage.py`)

| Função | Equivalente SQL |
| --- | --- |
| `vault_existe()` | `CHECK EXISTS` — decide entre primeira execução e login |
| `init_vault(chave)` | `CREATE TABLE` + commit inicial |
| `save_vault(vault, chave)` | `BEGIN TRAN` → serialize → encrypt → atomic write → `COMMIT` |
| `load_vault(chave)` | `SELECT` com validação de integridade |
| `backup_vault()` | `BACKUP DATABASE` versionado |
| `restore_vault(backup, chave)` | `RESTORE DATABASE` (valida antes de sobrescrever) |

Erros: `FileNotFoundError` (sem cofre), `PermissionError` (sem leitura) e
`VaultCorrompido` (chave errada, arquivo adulterado/truncado ou JSON inválido).
Os três modos de "não abre" colapsam em uma exceção só porque são
indistinguíveis para quem chama — em nenhum caso há o que recuperar sem a chave
ou sem um backup.

### Por que escrita atômica

`save_vault()` grava em `dados.enc.tmp`, chama `flush()` + `os.fsync()` e só
então `os.replace()` no `dados.enc`. Queda de energia ou crash no meio deixa o
arquivo antigo intacto e um `.tmp` órfão, sobrescrito na próxima gravação.
`os.replace` (e não `os.rename`) porque no Windows `rename` falha quando o
destino já existe. Falha em qualquer etapa remove o temporário e repropaga o
erro original — o `ROLLBACK` da analogia SQL.

### Fluxo `save_vault`

```
vault.backup() --JSON UTF-8--> encrypt_data --Encrypt-then-MAC--> dados.enc.tmp
dados.enc.tmp --fsync--> --os.replace--> dados.enc   (COMMIT)
erro --> remove dados.enc.tmp --> re-raise            (ROLLBACK)
```

### Backup versionado

`backup_vault()` copia para `dados.enc.bak.{YYYY-MM-DDTHH-MM-SS-ffffff}`
(microssegundos para dois backups seguidos não colidirem). `restore_vault()`
**valida o backup antes de copiar** — um backup corrompido nunca destrói o
`dados.enc` que ainda estava legível.

## Utilitários (`utils.py`)

| Função | Papel |
| --- | --- |
| `gerar_senha_aleatoria(tamanho=16)` | `secrets` (CSPRNG), 4 tipos garantidos, shuffle com `SystemRandom` |
| `sanitizar_texto(valor)` | remove caracteres de controle e `strip()` |
| `validar_entrada(site, username, password, notes)` | `(valido, erro)` em cascata |
| `formatar_saida(entradas)` | tabela ASCII, largura dinâmica, senha `***` |
| `pausar(msg)` / `limpar_tela()` | UX (Ctrl+C e Ctrl+D propagam) |

### Por que `secrets`, não `random`

`random` é Mersenne Twister: previsível depois de 624 saídas. `secrets` usa
`os.urandom`, entropia do SO. `secrets.choice` garante 1 caractere de cada tipo;
`SystemRandom().shuffle` embaralha depois, senão os quatro garantidos ficariam
sempre nas primeiras posições. Conjuntos: `A-Z`, `a-z`, `0-9` e
`!@#$%^&*()_+-=[]{}|;:,.<>?` (sem `"`, `'`, `\` e espaço, que quebram em
formulários e shells).

### Validação

`sanitizar_texto()` aplica `strip()` e remove `\x00-\x08`, `\x0b`, `\x0c`,
`\x0e-\x1f`, `\x7f` (preserva `\t`, `\n`, `\r`). `validar_entrada()` valida na
ordem site → usuário → senha → notas e para no primeiro erro. **A senha não é
sanitizada**: só é checada contra vazio/`strip()` vazio. Alterar a senha
digitada faria o cofre guardar um valor diferente do que o site espera.
Como a assinatura devolve `(valido, erro)` e não o texto limpo, quem grava chama
`sanitizar_texto()` antes de `Vault.add()`.

### Tabela

`formatar_saida()` monta uma matriz linhas × colunas com largura
`max(header, maior célula) + 2` e separadores `|` / `-+-`. É a VIEW pública do
modelo relacional: `id` truncado em 8 chars, senha sempre `***`.

## Instalação

Única dependência externa:

```powershell
python -m pip install cryptography
```

Python 3.10+ (usa `X | None` em type hints e `match/case` no `main.py`).

## Rodar

```powershell
python -m unittest -v test_models test_crypto test_storage test_utils
python -m mypy --strict models.py crypto.py storage.py utils.py test_models.py test_crypto.py test_storage.py test_utils.py
```


## Testes

`powershell
python -m unittest test_models test_crypto test_storage test_utils test_main test_integracao
python -m mypy --strict main.py models.py crypto.py storage.py utils.py test_main.py test_integracao.py
`

Cobertura: 151 testes (2 skips no Windows para chmod).

## Contribuicao

1. Fork
2. Branch: git checkout -b feature/nova-funcionalidade
3. Commit: git commit -m 'feat: descricao'
4. Push: git push origin feature/nova-funcionalidade
5. Pull Request

Padroes: type hints obrigatorios, docstrings PEP 257, mypy --strict sem erros, unittest passa 100%.
## Roadmap

- [x] `models.py` — `PasswordEntry` (entidade 3FN)
- [x] `models.py` — `Vault` (CRUD + índices + container + backup/restore)
- [x] `crypto.py` — PBKDF2, Fernet, HMAC (Encrypt-then-MAC)
- [x] `storage.py` — save/load atômico, backup/restore versionado
- [x] `utils.py` — geração de senha, validação, tabela CLI, UX
- [ ] `main.py` — menu, autenticação, fluxos
