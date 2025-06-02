# Extract_CVE

Automatize a extração e inserção de dados de vulnerabilidades em um banco PostgreSQL, integrando diversas fontes:

- **Feeds completos de CVE (NVD)**
- **Feeds incrementais de CVE (NVD)**
- **CVE via API (NVD)**
- **Vulnerabilidades do CXSecurity**
- **Metadados de exploits e shellcodes (Exploit-DB)**

Cada opção busca, processa (JSON, RSS ou CSV) e insere os dados no banco, evitando duplicatas via chaves primárias e `ON CONFLICT`. O projeto inclui:

- Scripts Python para download, parsing e inserção (`fetch_full.py`, `fetch_incremental.py`, `fetch_cve_api.py`, `fetch_cxsecurity.py`, `fetch_exploitdb.py`)
- `main.py`: menu interativo para executar cada extração individualmente ou todas de uma vez
- `db.py`: conexões e funções de inserção em lote (`execute_values`)
- `parser.py`: extração de campos relevantes do JSON de CVE
- `config.py`: variáveis de ambiente e URLs/API keys
- Scripts SQL (`setup_vulnerabilidades.sql`): criação de tabelas, índices, triggers FTS e views unificadas

Ao final, todas as vulnerabilidades ficam disponíveis em views para consultas unificadas.

---

## Tabela de Conteúdos

- [Extract\_CVE](#extract_cve)
  - [Tabela de Conteúdos](#tabela-de-conteúdos)
  - [Pré-requisitos](#pré-requisitos)
  - [Configuração do Ambiente](#configuração-do-ambiente)
  - [Estrutura de Diretórios](#estrutura-de-diretórios)
  - [Como Criar o Banco de Dados](#como-criar-o-banco-de-dados)
  - [Clonar o Repositório Exploit-DB](#clonar-o-repositório-exploit-db)
  - [Variáveis de Ambiente](#variáveis-de-ambiente)
  - [Descrição dos Arquivos Python](#descrição-dos-arquivos-python)
  - [Uso do main.py](#uso-do-mainpy)
  - [Estrutura SQL Atualizada](#estrutura-sql-atualizada)
  - [Banco Vetorial \& Busca Semântica (RAG)](#banco-vetorial--busca-semântica-rag)
    - [Por que usar?](#por-que-usar)
    - [Como implementar](#como-implementar)
  - [Exemplos de Execução](#exemplos-de-execução)
  - [Considerações Finais](#considerações-finais)

---

## Pré-requisitos

- **Sistema Operacional:** Linux (testado em Ubuntu e Debian)
- **Python:** 3.8+
- **PostgreSQL:** 12+, com permissão para criar extensões (`pg_trgm`, `unaccent`)
- **Dependências Python:**
  - `psycopg2-binary`
  - `ijson`
  - `requests`
  - `beautifulsoup4`
  - `lxml`
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

Verifique se o PostgreSQL está em execução e se o usuário/DB definidos em `.env` existem.

---

## Estrutura de Diretórios

```
Extract_CVE/
├── .env
├── config.py
├── db.py
├── parser.py
├── fetch_full.py
├── fetch_incremental.py
├── fetch_cve_api.py
├── fetch_cxsecurity.py
├── fetch_exploitdb.py
├── main.py
├── sql/
│   └── setup_vulnerabilidades.sql
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

Clone o repositório oficial:

```bash
cd /caminho/onde/quer/clonar
git clone https://gitlab.com/exploit-database/exploitdb.git
```

O caminho deve ser igual ao definido em `EXPLOITDB_REPO_PATH` no `.env`.

---

## Variáveis de Ambiente

| Variável                | Descrição                                                        |
|-------------------------|------------------------------------------------------------------|
| PG_HOST                 | Host do PostgreSQL                                               |
| PG_PORT                 | Porta do PostgreSQL                                              |
| PG_DATABASE             | Nome do banco                                                    |
| PG_USER                 | Usuário do banco                                                 |
| PG_PASSWORD             | Senha do usuário                                                 |
| NVD_API_KEY             | Chave de API para NVD                                            |
| EXPLOITDB_REPO_PATH     | Caminho local para o repositório Exploit-DB                      |
| EXPLOITDB_CSV_URL       | URL do CSV de exploits                                           |
| SHELLCODES_CSV_URL      | URL do CSV de shellcodes                                         |
| CX_RSS_URL              | URL do RSS feed do CXSecurity                                    |

---

## Descrição dos Arquivos Python

- **config.py:** Carrega variáveis do `.env` e define constantes.
- **db.py:** Conexão com PostgreSQL e funções de inserção em lote.
- **parser.py:** Função `parse_item()` para extrair campos do JSON de CVE.
- **fetch_full.py:** Baixa e insere feeds completos de CVEs.
- **fetch_incremental.py:** Coleta incremental de CVEs via API/feed modificado.
- **fetch_cve_api.py:** Busca CVEs usando a API v2 do NVD.
- **fetch_cxsecurity.py:** Scraping do RSS e detalhes do CXSecurity.
- **fetch_exploitdb.py:** Coleta CSVs do Exploit-DB e insere metadados e arquivos "raw".
- **main.py:** Menu interativo para executar as extrações.

---

## Uso do main.py

Ajuste seu `.env` e crie o banco conforme instruções. Execute:

```bash
python3 main.py
```

Escolha uma opção do menu, por exemplo:

```
Escolha uma opção: 1
```

Para executar todas as extrações:

```
Escolha uma opção: 7
```

---

## Estrutura SQL Atualizada

O script `sql/setup_vulnerabilidades.sql` cria:

- Extensões: `pg_trgm`, `unaccent`
- Tabelas: `cve_full`, `cve_incrementais`, `cxsecurity_vulns`, `exploitdb_exploits`, `exploitdb_shellcodes`, `exploitdb_raw_exploits`, `exploitdb_raw_shellcodes`
- Triggers e funções para FTS (Full-Text Search)
- Índices GIN e btree
- Views unificadas: `all_cves`, `view_cxsecurity`, `view_exploitdb_metadata`, `view_exploitdb_shellcodes`, `all_vulnerabilities`

---

## Banco Vetorial & Busca Semântica (RAG)

### Por que usar?

Permite buscas semânticas e enriquecimento de consultas, combinando recuperação vetorial e geração de respostas.

### Como implementar

1. **Habilite a extensão pgvector:**

    ```sql
    CREATE EXTENSION IF NOT EXISTS vector;
    ```

2. **Adicione coluna de embedding:**

    ```sql
    ALTER TABLE public.cve_full ADD COLUMN embedding vector(1536);
    ```

3. **Crie índice vetorial:**

    ```sql
    CREATE INDEX idx_cve_full_embedding ON public.cve_full USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
    ```

4. **Preencha embeddings via script Python (exemplo com OpenAI):**

    ```python
    import os
    import psycopg2
    import openai

    openai.api_key = os.getenv("OPENAI_API_KEY")
    conn = psycopg2.connect(
        host=os.getenv("PG_HOST"),
        port=os.getenv("PG_PORT"),
        dbname=os.getenv("PG_DATABASE"),
        user=os.getenv("PG_USER"),
        password=os.getenv("PG_PASSWORD"),
    )
    cur = conn.cursor()
    cur.execute("SELECT cve_id, details FROM public.cve_full WHERE embedding IS NULL;")
    for cve_id, details in cur.fetchall():
        embedding = openai.Embedding.create(
            input=details,
            model="text-embedding-ada-002"
        )["data"][0]["embedding"]
        cur.execute(
            "UPDATE public.cve_full SET embedding = %s WHERE cve_id = %s;",
            (embedding, cve_id)
        )
    conn.commit()
    cur.close()
    conn.close()
    ```

5. **Busca semântica:**

    ```sql
    SELECT cve_id, details
    FROM public.cve_full
    ORDER BY embedding <-> query_embedding
    LIMIT 10;
    ```

---

## Exemplos de Execução

Feed completo de CVE:

```bash
python3 main.py
Escolha uma opção: 1
```

Feed incremental (último dia):

```bash
python3 main.py
Escolha uma opção: 2
Dias para busca incremental (padrão 1): 1
```

CVE via API NVD:

```bash
python3 main.py
Escolha uma opção: 3
Dias para busca via API (padrão 1): 1
```

CXSecurity:

```bash
python3 main.py
Escolha uma opção: 4
```

Exploit-DB Exploits:

```bash
python3 main.py
Escolha uma opção: 5
```

Exploit-DB Shellcodes:

```bash
python3 main.py
Escolha uma opção: 6
```

Executar Tudo (1–6):

```bash
python3 main.py
Escolha uma opção: 7
```

---

## Considerações Finais

- Inserções em lote (`BATCH_SIZE = 5000`) otimizam a performance.
- Chaves primárias e `ON CONFLICT` garantem integridade e atualização.
- Tabelas de metadata não armazenam conteúdo completo dos arquivos.
- Tabelas "raw" guardam o conteúdo completo para análises detalhadas.
- Views facilitam consultas unificadas.
- A seção de Banco Vetorial & Busca Semântica mostra como estender o projeto para pesquisa semântica.

---
