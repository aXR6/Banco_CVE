#!/usr/bin/env python3
# fetch_cve_api.py

import time
from datetime import datetime, timedelta
import requests
from db import insert_cves
from config import API_URL, NVD_API_KEY, CVE_PAGE_SIZE
from embedder import get_embedding

def fetch_cve_api(days: int = 1):
    """
    Busca CVEs modificadas nos últimos 'days' dias usando a API REST do NVD.
    Pagina enquanto houver novos itens, respeitando 'CVE_PAGE_SIZE'.
    Para cada item, gera embedding e insere em cve_incrementais.
    """
    since = datetime.utcnow() - timedelta(days=days)
    now = datetime.utcnow()
    start_index = 0
    total_results = 1  # Inicialização arbitrária para entrar no loop

    all_records = []
    headers = {"apiKey": NVD_API_KEY}

    while start_index < total_results:
        params = {
            "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "startIndex": start_index,
            "resultsPerPage": CVE_PAGE_SIZE
        }
        try:
            print(f"[API] Buscando CVEs via API (index={start_index})...")
            resp = requests.get(API_URL, params=params, headers=headers, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])
            for e in vulnerabilities:
                cve_id = e["cve"]["id"]
                pub = e["cve"].get("published", "")
                desc = e["cve"]["descriptions"][0]["value"].replace("\n", " ")
                products = ""
                oss = ""
                text_for_emb = f"{desc} {products} {oss}"
                emb = get_embedding(text_for_emb)
                all_records.append((cve_id, pub, desc, products, oss, emb))
            print(f"[API] Obtidos {len(vulnerabilities)} registros (total até agora: {len(all_records)}/{total_results}).")
            start_index += CVE_PAGE_SIZE
            time.sleep(1)  # pausa para evitar rate limit
        except Exception as e:
            print(f"[API] Erro na busca: {e}")
            break

    if all_records:
        insert_cves("cve_incrementais", all_records)
        print(f"[API] Inseridos {len(all_records)} registros em 'cve_incrementais'.")
    else:
        print("[API] Nenhum registro obtido via API.")
