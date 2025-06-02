# db.py

import psycopg2
from psycopg2.extras import execute_values
from config import PG_HOST, PG_PORT, PG_DATABASE, PG_USER, PG_PASSWORD

# Tamanho do lote para inserções em massa
BATCH_SIZE = 5000

def get_connection():
    """Retorna uma conexão ao banco PostgreSQL."""
    return psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        dbname=PG_DATABASE,
        user=PG_USER,
        password=PG_PASSWORD,
        keepalives=1,
        keepalives_idle=30,
        keepalives_interval=10,
        keepalives_count=5
    )

def insert_cves(table: str, records: list[tuple]):
    """
    Insere registros de CVEs (cve_full ou cve_incrementais) em lotes.
    Cada tupla deve ter: (cve_id, published_date, details, products, operating_systems, embedding).
    Usa ON CONFLICT DO NOTHING para evitar duplicados.
    """
    total = len(records)
    idx = 0

    while idx < total:
        batch = records[idx: idx + BATCH_SIZE]
        idx += BATCH_SIZE

        try:
            conn = get_connection()
            with conn:
                with conn.cursor() as cur:
                    # Agora inclui embedding como última coluna
                    sql = f"""
                        INSERT INTO public.{table}
                          (cve_id, published_date, details, products, operating_systems, embedding)
                        VALUES %s
                        ON CONFLICT (cve_id) DO NOTHING
                    """
                    execute_values(cur, sql, batch)
            conn.close()
            print(f"[DB] Inseridos lote de {len(batch)} registros em '{table}' ({idx}/{total})")
        except psycopg2.OperationalError as oe:
            print(f"[DB] OperationalError: {oe}. Reconectando e tentando novamente...")
            idx -= len(batch)
        except Exception as e:
            print(f"[DB] Erro inesperado: {e}. Abortando inserção.")
            break

def insert_cxsecurity(records: list[tuple]):
    """
    Insere registros de vulnerabilidades CXSecurity em lote:
    Cada tupla contém:
      (wlb_id, title, pub_date, description, cve_list, cwe_list, products, link, embedding).
    ON CONFLICT (wlb_id) DO NOTHING.
    """
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                sql = """
                    INSERT INTO public.cxsecurity_vulns
                      (wlb_id, title, pub_date, description, cve_list, cwe_list, products, link, embedding)
                    VALUES %s
                    ON CONFLICT (wlb_id) DO NOTHING
                """
                execute_values(cur, sql, records)
        print(f"[DB CX] Inseridos {len(records)} registros em 'cxsecurity_vulns'.")
    except Exception as e:
        print(f"[DB CX] Erro ao inserir registros: {e}")
    finally:
        conn.close()

def insert_exploitdb_metadata(records: list[tuple]):
    """
    Insere registros de metadados de exploits (exploitdb_exploits).
    Cada tupla deve ter:
      (edb_id, file_path, description, exploit_date, author, platform, type, port, embedding).
    ON CONFLICT (edb_id) DO NOTHING para evitar duplicados.
    """
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                sql = """
                    INSERT INTO public.exploitdb_exploits
                      (edb_id, file_path, description, exploit_date, author, platform, type, port, embedding)
                    VALUES %s
                    ON CONFLICT (edb_id) DO NOTHING
                """
                execute_values(cur, sql, records)
        print(f"[DB EDB_METADATA] Inseridos {len(records)} registros em 'exploitdb_exploits'.")
    except Exception as e:
        print(f"[DB EDB_METADATA] Erro ao inserir registros: {e}")
    finally:
        conn.close()

def insert_exploitdb_shellcodes_metadata(records: list[tuple]):
    """
    Insere registros de metadados de shellcodes (exploitdb_shellcodes).
    Cada tupla deve ter:
      (sc_id, file_path, description, date_posted, author, platform, type, language, embedding).
    ON CONFLICT (sc_id) DO NOTHING para evitar duplicados.
    """
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                sql = """
                    INSERT INTO public.exploitdb_shellcodes
                      (sc_id, file_path, description, date_posted, author, platform, type, language, embedding)
                    VALUES %s
                    ON CONFLICT (sc_id) DO NOTHING
                """
                execute_values(cur, sql, records)
        print(f"[DB EDB_SHELLCODES_METADATA] Inseridos {len(records)} registros em 'exploitdb_shellcodes'.")
    except Exception as e:
        print(f"[DB EDB_SHELLCODES_METADATA] Erro ao inserir registros: {e}")
    finally:
        conn.close()

def insert_exploitdb_raw_exploits(records: list[tuple]):
    """
    Insere registros brutos de exploits (exploitdb_raw_exploits).
    Cada tupla deve ter **exatamente 10 valores** na ordem:
      (edb_id, file_path, file_content, description, date_posted,
       author, platform, type, port, embedding).
    ON CONFLICT (edb_id) DO UPDATE para manter sincronizado.
    """
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                sql = """
                    INSERT INTO public.exploitdb_raw_exploits
                      (
                        edb_id,
                        file_path,
                        file_content,
                        description,
                        date_posted,
                        author,
                        platform,
                        type,
                        port,
                        embedding
                      )
                    VALUES %s
                    ON CONFLICT (edb_id) DO UPDATE
                      SET file_path    = EXCLUDED.file_path,
                          file_content = EXCLUDED.file_content,
                          description  = EXCLUDED.description,
                          date_posted  = EXCLUDED.date_posted,
                          author       = EXCLUDED.author,
                          platform     = EXCLUDED.platform,
                          type         = EXCLUDED.type,
                          port         = EXCLUDED.port,
                          embedding    = EXCLUDED.embedding,
                          updated_at   = NOW()
                """
                execute_values(cur, sql, records)
        print(f"[DB EDB_RAW_EXPLOITS] Inseridos/Atualizados {len(records)} registros em 'exploitdb_raw_exploits'.")
    except Exception as e:
        print(f"[DB EDB_RAW_EXPLOITS] Erro ao inserir/atualizar registros: {e}")
    finally:
        conn.close()

def insert_exploitdb_raw_shellcodes(records: list[tuple]):
    """
    Insere registros brutos de shellcodes (exploitdb_raw_shellcodes).
    Cada tupla deve ter **exatamente 10 valores** na ordem:
      (sc_id, file_path, file_content, description, date_posted,
       author, platform, type, language, embedding).
    ON CONFLICT (sc_id) DO UPDATE para manter sincronizado.
    """
    try:
        conn = get_connection()
        with conn:
            with conn.cursor() as cur:
                sql = """
                    INSERT INTO public.exploitdb_raw_shellcodes
                      (
                        sc_id,
                        file_path,
                        file_content,
                        description,
                        date_posted,
                        author,
                        platform,
                        type,
                        language,
                        embedding
                      )
                    VALUES %s
                    ON CONFLICT (sc_id) DO UPDATE
                      SET file_path    = EXCLUDED.file_path,
                          file_content = EXCLUDED.file_content,
                          description  = EXCLUDED.description,
                          date_posted  = EXCLUDED.date_posted,
                          author       = EXCLUDED.author,
                          platform     = EXCLUDED.platform,
                          type         = EXCLUDED.type,
                          language     = EXCLUDED.language,
                          embedding    = EXCLUDED.embedding,
                          updated_at   = NOW()
                """
                execute_values(cur, sql, records)
        print(f"[DB EDB_RAW_SHELLCODES] Inseridos/Atualizados {len(records)} registros em 'exploitdb_raw_shellcodes'.")
    except Exception as e:
        print(f"[DB EDB_RAW_SHELLCODES] Erro ao inserir/atualizar registros: {e}")
    finally:
        conn.close()
