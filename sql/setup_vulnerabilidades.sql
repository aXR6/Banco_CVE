-- ====================================================================================
-- Arquivo: setup_vulnerabilidades.sql
-- Descrição: Criação do banco, usuário, tabelas, triggers, índices e views para:
--            • CVE (NVD completo e incremental)
--            • CXSecurity
--            • Exploit-DB (metadados e “raw”, incluindo conteúdo de arquivo)
--            • Colunas de embedding (vector) para buscas semânticas (RAG) com pgvector
--            • Função e view unificada para busca híbrida (FTS + RAG) em todas as tabelas
-- Observação: Assuma que a extensão pgvector já está instalada no PostgreSQL.
--             A LLM utilizada é “sentence-transformers/all-mpnet-base-v2” (dimensão 768).
-- ====================================================================================


-- 1) Criação do banco de dados e usuário
-- ----------------------------------------------------
-- (Se você ainda não criou, descomente e ajuste conforme necessário)
-- CREATE DATABASE cve;
-- CREATE USER vector_doc WITH PASSWORD 'sua_senha_forte';
-- GRANT CONNECT ON DATABASE cve TO vector_doc;
-- \c cve
-- GRANT USAGE ON SCHEMA public TO vector_doc;
-- GRANT CREATE, SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO vector_doc;


-- 2) Extensões necessárias
-- ----------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pg_trgm;     -- busca fuzzy por trigramas
CREATE EXTENSION IF NOT EXISTS unaccent;    -- remoção de acentos para FTS mais eficiente
CREATE EXTENSION IF NOT EXISTS vector;      -- suporte a embeddings com pgvector


-- 3) Criação das tabelas
-- ----------------------------------------------------

-- 3.1. Feeds completos de CVE (NVD)
CREATE TABLE public.cve_full (
  cve_id             TEXT            PRIMARY KEY,
  published_date     TIMESTAMPTZ     NOT NULL,
  details            TEXT            NOT NULL,
  products           TEXT,
  operating_systems  TEXT,
  embedding          VECTOR(768),    -- coluna para embedding (dimensão 768)
  tsv                TSVECTOR
);

-- 3.2. Feeds incrementais de CVE (NVD)
CREATE TABLE public.cve_incrementais (
  cve_id             TEXT            PRIMARY KEY,
  published_date     TIMESTAMPTZ     NOT NULL,
  details            TEXT            NOT NULL,
  products           TEXT,
  operating_systems  TEXT,
  embedding          VECTOR(768),
  tsv                TSVECTOR
);

-- 3.3. Vulnerabilidades CXSecurity
CREATE TABLE public.cxsecurity_vulns (
  wlb_id             TEXT            PRIMARY KEY,    -- ex: WLB2021050133
  title              TEXT            NOT NULL,      -- Título da vulnerabilidade
  pub_date           TIMESTAMPTZ     NULL,           -- Data de publicação (campo pubDate do RSS)
  description        TEXT,                             -- Descrição breve (campo description do RSS)
  cve_list           TEXT,                             -- Lista de CVEs separadas por ';'
  cwe_list           TEXT,                             -- Lista de CWEs separadas por ';'
  products           TEXT,                             -- Produtos afetados separadas por ';'
  link               TEXT,                             -- URL para detalhes completos
  embedding          VECTOR(768),
  tsv                TSVECTOR
);

-- 3.4. Exploit-DB: Metadados de Exploits (tabela “metadata”)
CREATE TABLE public.exploitdb_exploits (
  edb_id             INTEGER         PRIMARY KEY,   -- ID numérico do exploit no Exploit-DB
  file_path          TEXT,                            -- Caminho relativo para o exploit
  description        TEXT,                            -- Descrição do exploit
  exploit_date       DATE,                            -- Data de publicação do exploit
  author             TEXT,                            -- Autor ou alias
  platform           TEXT,                            -- Plataforma alvo (linux, windows, etc.)
  type               TEXT,                            -- Categoria (webapps, dos, etc.)
  port               TEXT,                            -- Porta alvo (se aplicável)
  embedding          VECTOR(768),
  tsv                TSVECTOR
);

-- 3.5. Exploit-DB: Metadados de Shellcodes (tabela “metadata”)
CREATE TABLE public.exploitdb_shellcodes (
  sc_id              INTEGER         PRIMARY KEY,   -- ID numérico do shellcode
  file_path          TEXT,                            -- Caminho relativo para o shellcode
  description        TEXT,                            -- Descrição do shellcode
  date_posted        DATE,                            -- Data de inclusão do shellcode
  author             TEXT,                            -- Autor ou alias
  platform           TEXT,                            -- Plataforma alvo (linux, windows, etc.)
  type               TEXT,                            -- Tipo de shellcode (exec, bind_tcp, etc.)
  language           TEXT,                            -- Linguagem de implementação (C, Python, etc.)
  embedding          VECTOR(768),
  tsv                TSVECTOR
);

-- 3.6. Exploit-DB Raw: Metadados completos de Exploits, incluindo file_content
CREATE TABLE public.exploitdb_raw_exploits (
  edb_id       INTEGER          PRIMARY KEY,   -- ID numérico único de files_exploits.csv
  file_path    TEXT            NOT NULL,      -- Caminho relativo (ex.: 'exploits/.../8614.py')
  file_content TEXT,                         -- Conteúdo completo do arquivo (texto)
  description  TEXT            NOT NULL,      -- Descrição resumida
  date_posted  DATE,                         -- Data de publicação (YYYY-MM-DD)
  author       TEXT,                         -- Autor ou alias
  platform     TEXT,                         -- Plataforma-alvo
  type         TEXT,                         -- Categoria
  port         TEXT,                         -- Porta associada (se aplicável)
  created_at   TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
  embedding    VECTOR(768),
  tsv          TSVECTOR
);

-- 3.7. Exploit-DB Raw: Metadados completos de Shellcodes, incluindo file_content
CREATE TABLE public.exploitdb_raw_shellcodes (
  sc_id         INTEGER        PRIMARY KEY,   -- ID numérico único de files_shellcodes.csv
  file_path     TEXT           NOT NULL,      -- Caminho relativo (ex.: 'shellcodes/.../39432.c')
  file_content  TEXT,                         -- Conteúdo completo do shellcode (texto)
  description   TEXT           NOT NULL,      -- Descrição resumida
  date_posted   DATE,                         -- Data de inclusão do shellcode
  author        TEXT,                         -- Autor ou alias
  platform      TEXT,                         -- Plataforma-alvo
  type          TEXT,                         -- Tipo de shellcode
  language      TEXT,                         -- Linguagem de implementação
  created_at    TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
  embedding     VECTOR(768),
  tsv           TSVECTOR
);


-- 4) Função e triggers para manter a coluna TSVECTOR atualizada
-- ----------------------------------------------------

-- 4.1. Função genérica para atualizar tsvector em todas as tabelas que possuem coluna tsv
--      Observação: pesos válidos somente 'A','B','C','D'
CREATE OR REPLACE FUNCTION public.update_tsvector_column() RETURNS trigger AS $$
BEGIN
  -- 4.1.1 CVE (cve_full, cve_incrementais): detalhes (A), produtos (B), sistemas operacionais (C)
  IF TG_TABLE_NAME = 'cve_full' OR TG_TABLE_NAME = 'cve_incrementais' THEN
    NEW.tsv :=
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.details, ''))), 'A') ||
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.products, ''))), 'B') ||
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.operating_systems, ''))), 'C');
    RETURN NEW;
  END IF;

  -- 4.1.2 CXSecurity: título (A), descrição (B), lista de CVEs (C), lista de CWEs (D), produtos (D)
  IF TG_TABLE_NAME = 'cxsecurity_vulns' THEN
    NEW.tsv :=
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.title, ''))), 'A') ||
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.description, ''))), 'B') ||
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.cve_list, ''))), 'C') ||
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.cwe_list, ''))), 'D') ||
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.products, ''))), 'D');
    RETURN NEW;
  END IF;

  -- 4.1.3 Exploit-DB Metadata (exploitdb_exploits): descrição (A), autor (B), plataforma (C)
  IF TG_TABLE_NAME = 'exploitdb_exploits' THEN
    NEW.tsv :=
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.description, ''))), 'A') ||
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.author, ''))), 'B') ||
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.platform, ''))), 'C');
    RETURN NEW;
  END IF;

  -- 4.1.4 Exploit-DB Metadata (exploitdb_shellcodes): descrição (A), autor (B), plataforma (C)
  IF TG_TABLE_NAME = 'exploitdb_shellcodes' THEN
    NEW.tsv :=
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.description, ''))), 'A') ||
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.author, ''))), 'B') ||
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.platform, ''))), 'C');
    RETURN NEW;
  END IF;

  -- 4.1.5 Exploit-DB Raw Exploits: descrição (A), autor (B), plataforma (C), conteúdo do arquivo (D)
  IF TG_TABLE_NAME = 'exploitdb_raw_exploits' THEN
    NEW.tsv :=
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.description, ''))), 'A') ||
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.author, ''))), 'B') ||
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.platform, ''))), 'C') ||
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.file_content, ''))), 'D');
    RETURN NEW;
  END IF;

  -- 4.1.6 Exploit-DB Raw Shellcodes: descrição (A), autor (B), plataforma (C), conteúdo do arquivo (D)
  IF TG_TABLE_NAME = 'exploitdb_raw_shellcodes' THEN
    NEW.tsv :=
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.description, ''))), 'A') ||
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.author, ''))), 'B') ||
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.platform, ''))), 'C') ||
      setweight(to_tsvector('simple', unaccent(coalesce(NEW.file_content, ''))), 'D');
    RETURN NEW;
  END IF;

  RETURN NEW;
END
$$ LANGUAGE plpgsql;


-- 4.2. Triggers para cada tabela que possui coluna tsv
CREATE TRIGGER trg_cve_full_tsv
  BEFORE INSERT OR UPDATE ON public.cve_full
  FOR EACH ROW EXECUTE FUNCTION public.update_tsvector_column();

CREATE TRIGGER trg_cve_incr_tsv
  BEFORE INSERT OR UPDATE ON public.cve_incrementais
  FOR EACH ROW EXECUTE FUNCTION public.update_tsvector_column();

CREATE TRIGGER trg_cxsecurity_tsv
  BEFORE INSERT OR UPDATE ON public.cxsecurity_vulns
  FOR EACH ROW EXECUTE FUNCTION public.update_tsvector_column();

CREATE TRIGGER trg_exploitdb_metadata_tsv
  BEFORE INSERT OR UPDATE ON public.exploitdb_exploits
  FOR EACH ROW EXECUTE FUNCTION public.update_tsvector_column();

CREATE TRIGGER trg_exploitdb_shellcodes_tsv
  BEFORE INSERT OR UPDATE ON public.exploitdb_shellcodes
  FOR EACH ROW EXECUTE FUNCTION public.update_tsvector_column();

CREATE TRIGGER trg_exploitdb_raw_exploits_tsv
  BEFORE INSERT OR UPDATE ON public.exploitdb_raw_exploits
  FOR EACH ROW EXECUTE FUNCTION public.update_tsvector_column();

CREATE TRIGGER trg_exploitdb_raw_shellcodes_tsv
  BEFORE INSERT OR UPDATE ON public.exploitdb_raw_shellcodes
  FOR EACH ROW EXECUTE FUNCTION public.update_tsvector_column();


-- 5) Índices para acelerar buscas
-- ----------------------------------------------------

-- 5.1. Índices GIN em coluna TSVECTOR (Full-Text Search)
CREATE INDEX idx_cve_full_tsv               ON public.cve_full               USING GIN(tsv);
CREATE INDEX idx_cve_incr_tsv               ON public.cve_incrementais       USING GIN(tsv);
CREATE INDEX idx_cxsecurity_tsv             ON public.cxsecurity_vulns       USING GIN(tsv);
CREATE INDEX idx_exploitdb_metadata_tsv     ON public.exploitdb_exploits     USING GIN(tsv);
CREATE INDEX idx_exploitdb_shellcodes_tsv   ON public.exploitdb_shellcodes   USING GIN(tsv);
CREATE INDEX idx_exploitdb_raw_exploits_tsv ON public.exploitdb_raw_exploits USING GIN(tsv);
CREATE INDEX idx_exploitdb_raw_shellcodes_tsv ON public.exploitdb_raw_shellcodes USING GIN(tsv);

-- 5.2. Índices trigram em colunas TEXT para busca fuzzy
CREATE INDEX idx_cve_full_details_trgm       ON public.cve_full               USING GIN(details gin_trgm_ops);
CREATE INDEX idx_cve_incr_details_trgm       ON public.cve_incrementais       USING GIN(details gin_trgm_ops);
CREATE INDEX idx_cxsecurity_title_trgm       ON public.cxsecurity_vulns       USING GIN(title gin_trgm_ops);
CREATE INDEX idx_cxsecurity_desc_trgm        ON public.cxsecurity_vulns       USING GIN(description gin_trgm_ops);
CREATE INDEX idx_exploitdb_metadata_desc_trgm    ON public.exploitdb_exploits      USING GIN(description gin_trgm_ops);
CREATE INDEX idx_exploitdb_shellcodes_desc_trgm  ON public.exploitdb_shellcodes    USING GIN(description gin_trgm_ops);
CREATE INDEX idx_exploitdb_raw_exploits_desc_trgm    ON public.exploitdb_raw_exploits    USING GIN(description gin_trgm_ops);
CREATE INDEX idx_exploitdb_raw_shellcodes_desc_trgm  ON public.exploitdb_raw_shellcodes  USING GIN(description gin_trgm_ops);

-- 5.3. Índices adicionais em colunas de data para consultas por período
CREATE INDEX idx_cve_full_publ_date          ON public.cve_full               (published_date);
CREATE INDEX idx_cve_incr_publ_date          ON public.cve_incrementais       (published_date);
CREATE INDEX idx_cxsecurity_pub_date         ON public.cxsecurity_vulns       (pub_date);
CREATE INDEX idx_exploitdb_metadata_date     ON public.exploitdb_exploits     (exploit_date);
CREATE INDEX idx_exploitdb_shellcodes_date   ON public.exploitdb_shellcodes   (date_posted);
CREATE INDEX idx_exploitdb_raw_exploits_date ON public.exploitdb_raw_exploits (date_posted);
CREATE INDEX idx_exploitdb_raw_shellcodes_date ON public.exploitdb_raw_shellcodes (date_posted);

-- 5.4. Índices HNSW em colunas VECTOR (Buscas Semânticas / RAG)
--       Note que usamos “vector_l2_ops” como operator class para HNSW.
--       Ajuste M e efConstruction conforme necessidade de performance e memória.
CREATE INDEX idx_cve_full_embedding_hnsw
  ON public.cve_full USING hnsw (embedding vector_l2_ops);

CREATE INDEX idx_cve_incr_embedding_hnsw
  ON public.cve_incrementais USING hnsw (embedding vector_l2_ops);

CREATE INDEX idx_cxsecurity_embedding_hnsw
  ON public.cxsecurity_vulns USING hnsw (embedding vector_l2_ops);

CREATE INDEX idx_exploitdb_metadata_embedding_hnsw
  ON public.exploitdb_exploits USING hnsw (embedding vector_l2_ops);

CREATE INDEX idx_exploitdb_shellcodes_embedding_hnsw
  ON public.exploitdb_shellcodes USING hnsw (embedding vector_l2_ops);

CREATE INDEX idx_exploitdb_raw_exploits_embedding_hnsw
  ON public.exploitdb_raw_exploits USING hnsw (embedding vector_l2_ops);

CREATE INDEX idx_exploitdb_raw_shellcodes_embedding_hnsw
  ON public.exploitdb_raw_shellcodes USING hnsw (embedding vector_l2_ops);


-- 6) Views unificadas para consulta
-- ----------------------------------------------------

-- 6.1. View para todos os CVEs (full + incrementais)
CREATE OR REPLACE VIEW public.all_cves AS
  SELECT
    'CVE_FULL' AS source,
    cve_id,
    published_date AS pub_date,
    details,
    products,
    operating_systems,
    NULL::TEXT AS extra_info
  FROM public.cve_full
  UNION ALL
  SELECT
    'CVE_INCR' AS source,
    cve_id,
    published_date AS pub_date,
    details,
    products,
    operating_systems,
    NULL::TEXT AS extra_info
  FROM public.cve_incrementais;

-- 6.2. View para todas vulnerabilidades CXSecurity
CREATE OR REPLACE VIEW public.view_cxsecurity AS
  SELECT
    wlb_id,
    title,
    pub_date,
    description,
    cve_list,
    cwe_list,
    products,
    link
  FROM public.cxsecurity_vulns;

-- 6.3. View para todos os exploits do Exploit-DB (metadados)
CREATE OR REPLACE VIEW public.view_exploitdb_metadata AS
  SELECT
    edb_id,
    file_path,
    description,
    exploit_date,
    author,
    platform,
    type,
    port
  FROM public.exploitdb_exploits;

-- 6.4. View para todos os shellcodes do Exploit-DB (metadados)
CREATE OR REPLACE VIEW public.view_exploitdb_shellcodes AS
  SELECT
    sc_id,
    file_path,
    description,
    date_posted AS exploit_date,
    author,
    platform,
    type,
    language AS port   -- mapeamos 'language' para coluna 'port' apenas para unificação
  FROM public.exploitdb_shellcodes;

-- 6.5. View para todos os raw exploits do Exploit-DB
CREATE OR REPLACE VIEW public.view_exploitdb_raw_exploits AS
  SELECT
    edb_id,
    file_path,
    file_content,
    description,
    date_posted,
    author,
    platform,
    type,
    port
  FROM public.exploitdb_raw_exploits;

-- 6.6. View para todos os raw shellcodes do Exploit-DB
CREATE OR REPLACE VIEW public.view_exploitdb_raw_shellcodes AS
  SELECT
    sc_id,
    file_path,
    file_content,
    description,
    date_posted,
    author,
    platform,
    type,
    language
  FROM public.exploitdb_raw_shellcodes;

-- 6.7. View unificada de “todas as vulnerabilidades/metadados” (CVE + CXSecurity + Exploit-DB)
CREATE OR REPLACE VIEW public.all_vulnerabilities AS
  -- CVE Full
  SELECT
    'CVE_FULL' AS source,
    cve_id::TEXT AS vuln_id,
    published_date AS pub_date,
    details AS description,
    products,
    operating_systems,
    NULL::TEXT AS extra_info
  FROM public.cve_full

  UNION ALL

  -- CVE Incrementais
  SELECT
    'CVE_INCR' AS source,
    cve_id::TEXT AS vuln_id,
    published_date AS pub_date,
    details AS description,
    products,
    operating_systems,
    NULL::TEXT AS extra_info
  FROM public.cve_incrementais

  UNION ALL

  -- CXSecurity
  SELECT
    'CXS' AS source,
    wlb_id AS vuln_id,
    pub_date AS pub_date,
    description,
    products,
    NULL::TEXT AS operating_systems,
    cve_list AS extra_info
  FROM public.cxsecurity_vulns

  UNION ALL

  -- Exploit-DB Metadata (exploits)
  SELECT
    'EDB_META_EXP' AS source,
    edb_id::TEXT AS vuln_id,
    exploit_date AS pub_date,
    description,
    platform AS products,
    NULL::TEXT AS operating_systems,
    author AS extra_info
  FROM public.exploitdb_exploits

  UNION ALL

  -- Exploit-DB Metadata (shellcodes)
  SELECT
    'EDB_META_SHC' AS source,
    sc_id::TEXT AS vuln_id,
    date_posted AS pub_date,
    description,
    platform AS products,
    NULL::TEXT AS operating_systems,
    language AS extra_info
  FROM public.exploitdb_shellcodes

  UNION ALL

  -- Exploit-DB Raw Exploits
  SELECT
    'EDB_RAW_EXP' AS source,
    edb_id::TEXT AS vuln_id,
    date_posted AS pub_date,
    description,
    platform AS products,
    NULL::TEXT AS operating_systems,
    NULL::TEXT AS extra_info
  FROM public.exploitdb_raw_exploits

  UNION ALL

  -- Exploit-DB Raw Shellcodes
  SELECT
    'EDB_RAW_SHC' AS source,
    sc_id::TEXT AS vuln_id,
    date_posted AS pub_date,
    description,
    platform AS products,
    NULL::TEXT AS operating_systems,
    language AS extra_info
  FROM public.exploitdb_raw_shellcodes;


-- 7) Função de busca unificada em todas as tabelas relevantes
-- ------------------------------------------------------------
-- Essa função recebe quatro parâmetros:
--   p_cve_ids       TEXT           → JSON array de CVE_IDs (ex: '["CVE-2006-0018","CVE-2006-3433",...]')
--   p_cve_nums      TEXT           → JSON array de números puros (ex: '["0018","3433",...]')
--   p_user_text     TEXT           → Mensagem livre do usuário (para FTS)
--   p_user_embedding VECTOR(768)    → Embedding gerado pela aplicação para busca semântica (RAG)

CREATE OR REPLACE FUNCTION public.search_all_vulnerabilities(
  p_cve_ids       TEXT,
  p_cve_nums      TEXT,
  p_user_text     TEXT,
  p_user_embedding VECTOR(768)
)
  RETURNS TABLE (
    source             TEXT,
    vuln_id            TEXT,
    pub_date           TIMESTAMPTZ,
    description        TEXT,
    products           TEXT,
    operating_systems  TEXT,
    extra_info         TEXT
  )
AS $$
BEGIN
  RETURN QUERY
  SELECT
    source,
    vuln_id,
    pub_date,
    description,
    products,
    operating_systems,
    extra_info
  FROM (
    ---------------------------------------------------------------------
    -- 1) CVE_FULL
    SELECT
      'CVE_FULL'                  AS source,
      cve_id                      AS vuln_id,
      published_date              AS pub_date,
      details                     AS description,
      products,
      operating_systems,
      NULL::TEXT                  AS extra_info,
      tsv                         AS text_vector,
      embedding                   AS vec
    FROM public.cve_full

    UNION ALL

    ---------------------------------------------------------------------
    -- 2) CVE_INCREMENTAIS
    SELECT
      'CVE_INCR'                  AS source,
      cve_id                      AS vuln_id,
      published_date              AS pub_date,
      details                     AS description,
      products,
      operating_systems,
      NULL::TEXT                  AS extra_info,
      tsv                         AS text_vector,
      embedding                   AS vec
    FROM public.cve_incrementais

    UNION ALL

    ---------------------------------------------------------------------
    -- 3) CXSECURITY_VULNS
    SELECT
      'CXS'                       AS source,
      wlb_id                      AS vuln_id,
      pub_date                    AS pub_date,
      description                 AS description,
      products,
      NULL::TEXT                  AS operating_systems,
      cve_list                    AS extra_info,
      tsv                         AS text_vector,
      embedding                   AS vec
    FROM public.cxsecurity_vulns

    UNION ALL

    ---------------------------------------------------------------------
    -- 4) Exploit-DB Metadata (exploits)
    SELECT
      'EDB_META_EXP'               AS source,
      edb_id::TEXT                 AS vuln_id,
      exploit_date                 AS pub_date,
      description                  AS description,
      platform                     AS products,
      NULL::TEXT                   AS operating_systems,
      author                       AS extra_info,
      tsv                          AS text_vector,
      embedding                    AS vec
    FROM public.exploitdb_exploits

    UNION ALL

    ---------------------------------------------------------------------
    -- 5) Exploit-DB Metadata (shellcodes)
    SELECT
      'EDB_META_SHC'               AS source,
      sc_id::TEXT                  AS vuln_id,
      date_posted                  AS pub_date,
      description                  AS description,
      platform                     AS products,
      NULL::TEXT                   AS operating_systems,
      language                     AS extra_info,
      tsv                          AS text_vector,
      embedding                    AS vec
    FROM public.exploitdb_shellcodes

    UNION ALL

    ---------------------------------------------------------------------
    -- 6) Exploit-DB Raw Exploits
    SELECT
      'EDB_RAW_EXP'                AS source,
      edb_id::TEXT                 AS vuln_id,
      date_posted                  AS pub_date,
      description                  AS description,
      platform                     AS products,
      NULL::TEXT                   AS operating_systems,
      NULL::TEXT                   AS extra_info,
      tsv                          AS text_vector,
      embedding                    AS vec
    FROM public.exploitdb_raw_exploits

    UNION ALL

    ---------------------------------------------------------------------
    -- 7) Exploit-DB Raw Shellcodes
    SELECT
      'EDB_RAW_SHC'                AS source,
      sc_id::TEXT                  AS vuln_id,
      date_posted                  AS pub_date,
      description                  AS description,
      platform                     AS products,
      NULL::TEXT                   AS operating_systems,
      language                     AS extra_info,
      tsv                          AS text_vector,
      embedding                    AS vec
    FROM public.exploitdb_raw_shellcodes

  ) AS all_vulns
  WHERE
    (
      -- (A) Filtrar por vuln_id exato (CVE_FULL / CVE_INCR / CXS) ou “número puro” dentro de vuln_id
      vuln_id IN (
        SELECT jsonb_array_elements_text(p_cve_ids::jsonb)
      )
      OR split_part(vuln_id, '-', 3) IN (
        SELECT jsonb_array_elements_text(p_cve_nums::jsonb)
      )
    )
    OR
    (
      -- (B) Para CXSecurity (source = 'CXS'), filtrar dentro de cve_list (separado por ';')
      source = 'CXS'
      AND (
        EXISTS (
          SELECT 1
          FROM unnest(string_to_array(all_vulns.extra_info, ';')) AS x(cv)  -- extra_info em CXS é cve_list
          WHERE cv IN (
            SELECT jsonb_array_elements_text(p_cve_ids::jsonb)
          )
        )
        OR EXISTS (
          SELECT 1
          FROM unnest(string_to_array(all_vulns.extra_info, ';')) AS x(cv)
          WHERE split_part(cv, '-', 3) IN (
            SELECT jsonb_array_elements_text(p_cve_nums::jsonb)
          )
        )
      )
    )
    OR
    (
      -- (C1) Busca por similaridade textual: transforma p_user_text em tsquery e compara com text_vector
      plainto_tsquery('simple', unaccent(p_user_text)) @@ all_vulns.text_vector
    )
    OR
    (
      -- (C2) Busca semântica (vetorial) usando embeddings: compara embedding com p_user_embedding
      -- (Quanto menor o valor de `<->`, mais similar.)
      all_vulns.vec <-> p_user_embedding < 0.3
    )
  ORDER BY
    pub_date DESC;
END;
$$ LANGUAGE plpgsql;


-- ====================================================================================
-- FIM DO ARQUIVO
-- ====================================================================================
