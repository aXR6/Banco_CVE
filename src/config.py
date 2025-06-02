# config.py

import os
from dotenv import load_dotenv, find_dotenv

# 1) Determina o caminho absoluto do .env na raiz do projeto
base_dir    = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
dotenv_path = os.path.join(base_dir, ".env")

# 2) Carrega o .env mesmo que o script seja executado dentro de src/
load_dotenv(find_dotenv(dotenv_path, usecwd=True))

# 3) Variáveis de conexão Postgres
PG_HOST     = os.getenv("PG_HOST")
PG_PORT     = os.getenv("PG_PORT")
PG_DATABASE = os.getenv("PG_DATABASE")
PG_USER     = os.getenv("PG_USER")
PG_PASSWORD = os.getenv("PG_PASSWORD")

# 4) Configurações NVD (CVE)
NVD_API_KEY   = os.getenv("NVD_API_KEY")
NVD_BASE      = "https://nvd.nist.gov/feeds/json/cve/1.1/"
MODIFIED_FEED = f"{NVD_BASE}nvdcve-1.1-modified.json.gz"
API_URL       = "https://services.nvd.nist.gov/rest/json/cves/2.0"
YEARS         = list(range(2002, 2026))
CVE_PAGE_SIZE = 2000  # Máximo de itens por página ao usar a API

# 5) CXSecurity
CX_RSS_URL    = "http://cxsecurity.com/wlb/rss/all/"

# 6) Exploit-DB (CSV raw)
EXPLOITDB_CSV_URL  = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
SHELLCODES_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_shellcodes.csv"

# 7) Caminho local onde o repositório do Exploit-DB será clonado
EXPLOITDB_REPO_PATH = os.getenv(
    "EXPLOITDB_REPO_PATH",
    os.path.join(base_dir, "exploitdb")
)
