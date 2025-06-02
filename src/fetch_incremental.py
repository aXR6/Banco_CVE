#!/usr/bin/env python3
# fetch_incremental.py

import time
import gzip
from urllib.request import urlretrieve
from datetime import datetime, timedelta
import requests
import ijson
import os
from config import API_URL, NVD_API_KEY, MODIFIED_FEED
from parser import parse_item
from db import insert_cves
from embedder import get_embedding

def fetch_incremental(days: int = 1):
    """
    Busca CVEs modificados há 'days' dias usando a API REST do NVD.
    Se falhar 3 tentativas, baixa o feed 'modified' (nvdcve-modified.json.gz) e insere registros.
    Para cada item, gera embedding e insere.
    """
    since = datetime.utcnow() - timedelta(days=days)
    now = datetime.utcnow()
    params = {
        "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "resultsPerPage": 2000
    }
    headers = {"apiKey": NVD_API_KEY}
    for attempt in range(3):
        try:
            print(f"[Incr] API: tentativa {attempt+1}/3")
            resp = requests.get(API_URL, params=params, headers=headers, timeout=10)
            resp.raise_for_status()
            data = resp.json().get("vulnerabilities", [])
            records = []
            for e in data:
                cve_id = e["cve"]["id"]
                pub = e["cve"].get("published", "")
                desc = e["cve"]["descriptions"][0]["value"].replace("\n", " ")
                # Nos incrementais via API, products e oss ficam vazios
                products = ""
                oss = ""
                text_for_emb = f"{desc} {products} {oss}"
                emb = get_embedding(text_for_emb)
                records.append((cve_id, pub, desc, products, oss, emb))
            if records:
                insert_cves("cve_incrementais", records)
                print(f"[Incr] Inseridos {len(records)} registros via API.")
            else:
                print("[Incr] Nenhum registro obtido via API.")
            return
        except Exception as e:
            print(f"[Incr] Erro: {e}")
            time.sleep(2 ** attempt)

    # fallback para modified feed
    print("[Incr] Usando modified feed como fallback")
    gz = "nvdcve-modified.json.gz"
    urlretrieve(MODIFIED_FEED, gz)
    records = []
    with gzip.open(gz, "rb") as f:
        for item in ijson.items(f, "CVE_Items.item"):
            pub_date = item.get("publishedDate","")
            if pub_date >= since.isoformat():
                cve_id, pub, desc, products, oss = parse_item(item)
                text_for_emb = f"{desc} {products or ''} {oss or ''}"
                emb = get_embedding(text_for_emb)
                records.append((cve_id, pub, desc, products, oss, emb))
    if records:
        insert_cves("cve_incrementais", records)
        print(f"[Incr] Inseridos {len(records)} registros via modified feed.")
    else:
        print("[Incr] Nenhum registro filtrado no modified feed.")
    os.remove(gz)
