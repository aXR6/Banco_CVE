# fetch_cxsecurity.py

import requests
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from datetime import datetime
from db import insert_cxsecurity
from config import CX_RSS_URL
from embedder import get_embedding

def fetch_cxsecurity_rss():
    """
    1) Baixa o RSS do CXSecurity (CX_RSS_URL).
    2) Parseia cada <item> para extrair link, title, pubDate, description.
    3) Faz scraping da página de detalhe usando scrape_cxsecurity_detail.
    4) Gera embedding e insere todos os registros em lote via insert_cxsecurity().
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; Python/3.x; +https://example.com/bot)"
    }
    try:
        resp = requests.get(CX_RSS_URL, timeout=10, headers=headers)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[CX] Falha ao baixar RSS: {e}")
        return

    root = ET.fromstring(resp.content)
    items = root.findall(".//item")
    records = []

    for item in items:
        link = item.findtext("link")
        title = item.findtext("title", default="(sem título)")
        pub = item.findtext("pubDate", default="")
        try:
            dt = datetime.strptime(pub, "%a, %d %b %Y %H:%M:%S %Z") if pub else None
        except Exception:
            dt = None

        desc = item.findtext("description", default="")

        # 2) Scraping da página de detalhe para CVEs, CWEs e produtos
        cve_list, cwe_list, products = ([], [], [])
        if link:
            cve_list, cwe_list, products = scrape_cxsecurity_detail(link)

        # Extrair o WLB ID (parte após última '/')
        wlb_id = link.rstrip("/").split("/")[-1] if link else "(sem_id)"

        cve_list_str = ";".join(cve_list)
        cwe_list_str = ";".join(cwe_list)
        products_str = ";".join(products)

        # Concatena texto para embedding
        text_for_emb = f"{title} {desc} {cve_list_str} {cwe_list_str} {products_str}"
        emb = get_embedding(text_for_emb)

        records.append((
            wlb_id,
            title,
            dt,
            desc,
            cve_list_str,
            cwe_list_str,
            products_str,
            link,
            emb
        ))

    try:
        insert_cxsecurity(records)
    except Exception as e:
        print(f"[CX] Erro ao inserir registros: {e}")

def scrape_cxsecurity_detail(url: str):
    """
    Faz scraping da página de detalhe no CXSecurity para extrair:
    - CVEs em <div class="vuln-cve">
    - CWEs em <div class="vuln-cwe">
    - Produtos em <div class="vuln-products"> ou <ul class="vuln-products-list">
    Retorna três listas: (cve_list, cwe_list, products).
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; Python/3.x; +https://example.com/bot)"
    }
    try:
        resp = requests.get(url, timeout=10, headers=headers)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[CX] Falha ao baixar {url}: {e}")
        return [], [], []

    soup = BeautifulSoup(resp.text, "html.parser")

    # 1) Extrair CVE(s) em <div class="vuln-cve">
    cve_list = []
    cve_div = soup.find("div", class_="vuln-cve")
    if cve_div:
        for a in cve_div.find_all("a", href=True):
            text = a.get_text(strip=True)
            if text.startswith("CVE-"):
                cve_list.append(text)

    # 2) Extrair CWE(s) em <div class="vuln-cwe">
    cwe_list = []
    cwe_div = soup.find("div", class_="vuln-cwe")
    if cwe_div:
        raw = cwe_div.get_text(strip=True).replace("CWE:", "").strip()
        parts = raw.split(",")
        cwe_list = [p.strip() for p in parts if p.strip()]

    # 3) Extrair Produtos em <div class="vuln-products"> ou <ul class="vuln-products-list">
    products = []
    prod_div = soup.find("div", class_="vuln-products")
    if prod_div:
        raw = prod_div.get_text(strip=True).replace("Affected Products:", "").strip()
        products = [p.strip() for p in raw.split(",") if p.strip()]
    else:
        ul = soup.find("ul", class_="vuln-products-list")
        if ul:
            for li in ul.find_all("li"):
                products.append(li.get_text(strip=True))

    return cve_list, cwe_list, products
