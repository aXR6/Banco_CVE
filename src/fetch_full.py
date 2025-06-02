#!/usr/bin/env python3
# fetch_full.py

import os
import gzip
import threading
from urllib.request import urlretrieve
import ijson
from config import YEARS, NVD_BASE
from parser import parse_item
from db import insert_cves
from embedder import get_embedding

def fetch_full_csv_and_insert():
    """
    Baixa todos os feeds completos anuais do NVD (2002–2025), faz parse linha a linha
    usando ijson e, para cada registro, gera embedding e insere em lote.
    """
    records = []
    lock = threading.Lock()

    def worker(year):
        gz_name = f"nvdcve-1.1-{year}.json.gz"
        url     = f"{NVD_BASE}nvdcve-1.1-{year}.json.gz"
        print(f"[Full] Baixando feed de {year}...")
        urlretrieve(url, gz_name)
        with gzip.open(gz_name, "rb") as f:
            for item in ijson.items(f, "CVE_Items.item"):
                rec = parse_item(item)
                # rec: (cve_id, pub, desc, products, oss)
                cve_id, pub, desc, products, oss = rec
                # Concatena texto para embedding
                text_for_emb = f"{desc} {products or ''} {oss or ''}"
                emb = get_embedding(text_for_emb)
                # Monta tupla final: 6 campos + embedding
                tup = (cve_id, pub, desc, products, oss, emb)
                with lock:
                    records.append(tup)
        os.remove(gz_name)

    threads = [threading.Thread(target=worker, args=(y,)) for y in YEARS]
    for t in threads: t.start()
    for t in threads: t.join()

    print(f"[Full] Total de registros: {len(records)}. Inserindo no Postgres em lotes...")
    insert_cves("cve_full", records)
    print("[Full] Todas as inserções concluídas.")
