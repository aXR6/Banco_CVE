# Banco_vetorial_CVE

Automatize a extração e inserção de dados de vulnerabilidades em um banco PostgreSQL, integrando diversas fontes (NVD, CXSecurity, Exploit-DB).

---

## Índice

- [Banco\_vetorial\_CVE](#banco_vetorial_cve)
  - [Índice](#índice)
  - [Visão Geral](#visão-geral)
  - [Pré-requisitos](#pré-requisitos)
  - [Configuração do Ambiente](#configuração-do-ambiente)
  - [Estrutura de Diretórios](#estrutura-de-diretórios)
  - [Como Criar o Banco de Dados](#como-criar-o-banco-de-dados)
  - [Clonar o Repositório Exploit-DB](#clonar-o-repositório-exploit-db)
  - [Variáveis de Ambiente](#variáveis-de-ambiente)
  - [Descrição dos Arquivos Python](#descrição-dos-arquivos-python)
  - [Uso do main.py](#uso-do-mainpy)
  - [Estrutura SQL Atualizada](#estrutura-sql-atualizada)
  - [Exemplos de Execução](#exemplos-de-execução)
  - [Considerações Finais](#considerações-finais)

---

## Visão Geral

Este projeto automatiza a extração e inserção de dados de vulnerabilidades em um banco PostgreSQL, integrando diversas fontes:

- Feeds completos e incrementais de CVE (NVD)
- CVE via API (NVD)
- Vulnerabilidades do CXSecurity
- Metadados e arquivos de exploits/shellcodes (Exploit-DB)

Cada opção busca, processa e insere os dados no banco, evitando duplicatas via chaves primárias e `ON CONFLICT`. O projeto inclui scripts Python para download, parsing e inserção, além de scripts SQL para criação de tabelas, índices, triggers de FTS e views unificadas.

---

## Pré-requisitos

- **Sistema Operacional:** Linux (testado em Ubuntu/Debian)
- **Python:** 3.8+
- **PostgreSQL:** 12+, com permissão para criar extensões (`pg_trgm`, `unaccent`)
- **Dependências Python:**
  - `psycopg2-binary`
  - `ijson`
  - `requests`
  - `beautifulsoup4`, `lxml`
  - `tqdm`
  - `python-dotenv`
  - `python-dateutil`

Instale as dependências:

```bash
pip install psycopg2-binary ijson requests beautifulsoup4 lxml tqdm python-dotenv python-dateutil
```

---

## Configuração do Ambiente

Clone este repositório:

```bash
git clone https://<seu-repositório>/Extract_CVE.git
cd Extract_CVE
```

Crie um arquivo `.env` na raiz do projeto:

```ini
PG_HOST=localhost
PG_PORT=5432
PG_DATABASE=cve
PG_USER=vector_doc
PG_PASSWORD=sua_senha_forte

NVD_API_KEY=SEU_NVD_API_KEY_AQUI

EXPLOITDB_REPO_PATH=/caminho/para/exploitdb

EXPLOITDB_CSV_URL=https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv
SHELLCODES_CSV_URL=https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_shellcodes.csv

CX_RSS_URL=http://cxsecurity.com/wlb/rss/all/
```

Certifique-se de que o PostgreSQL está em execução e o usuário/banco existem.

---

## Estrutura de Diretórios

```
Extract_CVE/
├── config.py
├── db.py
├── fetch_full.py
├── fetch_incremental.py
├── fetch_cve_api.py
├── fetch_cxsecurity.py
├── fetch_exploitdb.py
├── main.py
├── sql/
│   └── setup_vulnerabilidades.sql
├── .env
└── README.md
```

---

## Como Criar o Banco de Dados

Conecte-se ao PostgreSQL como superusuário:

```bash
sudo -u postgres psql
```

Crie o banco e o usuário:

```sql
CREATE DATABASE cve;
CREATE USER vector_doc WITH PASSWORD 'sua_senha_forte';
GRANT CONNECT ON DATABASE cve TO vector_doc;
\c cve
GRANT USAGE ON SCHEMA public TO vector_doc;
GRANT CREATE, SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO vector_doc;
```

Ative as extensões e crie as tabelas:

```bash
psql -U vector_doc -d cve -f sql/setup_vulnerabilidades.sql
```

---

## Clonar o Repositório Exploit-DB

Para extrair exploits/shellcodes completos, clone o Exploit-DB:

```bash
cd /caminho/onde/quer/clonar
git clone https://gitlab.com/exploit-database/exploitdb.git
```

Defina o caminho em `EXPLOITDB_REPO_PATH` no `.env`.

---

## Variáveis de Ambiente

| Variável                | Descrição                                               |
|-------------------------|--------------------------------------------------------|
| PG_HOST                 | Host do PostgreSQL                                     |
| PG_PORT                 | Porta do PostgreSQL                                    |
| PG_DATABASE             | Nome do banco                                          |
| PG_USER                 | Usuário do banco                                       |
| PG_PASSWORD             | Senha do usuário                                       |
| NVD_API_KEY             | Chave de API para NVD                                  |
| EXPLOITDB_REPO_PATH     | Caminho local do Exploit-DB                            |
| EXPLOITDB_CSV_URL       | URL do CSV de exploits                                 |
| SHELLCODES_CSV_URL      | URL do CSV de shellcodes                               |
| CX_RSS_URL              | URL do RSS feed do CXSecurity                          |

---

## Descrição dos Arquivos Python

- **config.py:** Carrega variáveis do `.env` e define constantes.
- **db.py:** Funções de conexão e inserção em lote no PostgreSQL.
- **parser.py:** Extrai campos relevantes do JSON de CVE.
- **fetch_full.py:** Baixa e insere feeds completos de CVE.
- **fetch_incremental.py:** Baixa e insere feeds incrementais de CVE.
- **fetch_cve_api.py:** (Opcional) Busca CVEs via API.
- **fetch_cxsecurity.py:** Extrai vulnerabilidades do CXSecurity.
- **fetch_exploitdb.py:** Extrai exploits e shellcodes do Exploit-DB.
- **main.py:** Menu interativo para executar as extrações.

---

## Uso do main.py

Ajuste o `.env` e execute:

```bash
python3 main.py
```

Escolha uma opção do menu para executar a extração desejada.

---

## Estrutura SQL Atualizada

O script `sql/setup_vulnerabilidades.sql` cria:

- Extensões: `pg_trgm`, `unaccent`
- Tabelas: `cve_full`, `cve_incrementais`, `cxsecurity_vulns`, `exploitdb_exploits`, `exploitdb_shellcodes`, `exploitdb_raw_exploits`, `exploitdb_raw_shellcodes`
- Triggers e índices para FTS
- Views unificadas: `all_cves`, `view_cxsecurity`, `view_exploitdb_metadata`, `view_exploitdb_shellcodes`, `all_vulnerabilities`

---

## Exemplos de Execução

Feed completo de CVE:

```bash
python3 main.py
# Escolha a opção: 1
```

Feed incremental (último dia):

```bash
python3 main.py
# Escolha a opção: 2
# Dias para busca incremental: 1
```

Executar tudo:

```bash
python3 main.py
# Escolha a opção: 7
```

---

## Considerações Finais

- Inserções em lote (`BATCH_SIZE = 5000`) para performance.
- Chaves primárias e `ON CONFLICT` evitam duplicatas.
- Tabelas `raw` armazenam conteúdo completo de exploits/shellcodes.
- Views facilitam consultas unificadas de vulnerabilidades.

---
