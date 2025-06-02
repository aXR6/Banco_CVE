#!/usr/bin/env python3
"""
main.py – Script principal para coleta e inserção de dados de vulnerabilidades
Fonte: Integra feeds de CVE (NVD), CVE via API, CXSecurity e Exploit-DB (exploits e shellcodes) no PostgreSQL

Para executar:
    python3 main.py

Autor: [Seu Nome]
Data: 2025-XX-XX
"""

import sys

def main():
    print("NVD API Key configurada.\n")
    while True:
        print("""
=== MENU de Vulnerabilidades ===
1) Extrair feeds completos de CVE (NVD) e salvar no Postgres
2) Extrair CVEs incrementais (NVD) e salvar no Postgres
3) Extrair CVEs via API NVD e salvar no Postgres
4) Extrair vulnerabilidades do CXSecurity e salvar no Postgres
5) Extrair metadados de exploits (Exploit-DB) e salvar em 'raw_exploits'
6) Extrair metadados de shellcodes (Exploit-DB) e salvar em 'raw_shellcodes'
7) Executar todas as extrações (1 a 6) com configurações padrão
8) Sair
""")
        choice = input("Escolha uma opção: ").strip()

        if choice == "1":
            # Feed completo de CVEs (NVD)
            try:
                from fetch_full import fetch_full_csv_and_insert
                fetch_full_csv_and_insert()
            except ImportError:
                print("[Erro] Não foi possível importar 'fetch_full.py'. Verifique se o arquivo existe.")
            except Exception as e:
                print(f"[Erro] Problema ao processar feed completo de CVE: {e}")

        elif choice == "2":
            # CVEs incrementais (NVD)
            try:
                days_input = input("Dias para busca incremental (padrão 1): ").strip()
                days = int(days_input) if days_input.isdigit() else 1
                from fetch_incremental import fetch_incremental
                fetch_incremental(days)
            except ImportError:
                print("[Erro] Não foi possível importar 'fetch_incremental.py'. Verifique se o arquivo existe.")
            except Exception as e:
                print(f"[Erro] Problema ao processar CVEs incrementais: {e}")

        elif choice == "3":
            # CVEs via API NVD
            try:
                days_input = input("Dias para busca via API (padrão 1): ").strip()
                days = int(days_input) if days_input.isdigit() else 1
                from fetch_cve_api import fetch_cve_api
                fetch_cve_api(days)
            except ImportError:
                print("[Erro] Não foi possível importar 'fetch_cve_api.py'. Verifique se o arquivo existe.")
            except Exception as e:
                print(f"[Erro] Problema ao processar CVEs via API: {e}")

        elif choice == "4":
            # Vulnerabilidades do CXSecurity
            try:
                from fetch_cxsecurity import fetch_cxsecurity_rss
                fetch_cxsecurity_rss()
            except ImportError:
                print("[Erro] Não foi possível importar 'fetch_cxsecurity.py'. Verifique se o arquivo existe.")
            except Exception as e:
                print(f"[Erro] Problema ao processar CXSecurity: {e}")

        elif choice == "5":
            # Exploit-DB: metadados de exploits (raw_exploits)
            try:
                from fetch_exploitdb import fetch_exploitdb_exploits
                fetch_exploitdb_exploits()
            except ImportError:
                print("[Erro] Não foi possível importar 'fetch_exploitdb.py' (exploits).")
            except Exception as e:
                print(f"[Erro] Problema ao processar Exploit-DB (exploits): {e}")

        elif choice == "6":
            # Exploit-DB: metadados de shellcodes (raw_shellcodes)
            try:
                from fetch_exploitdb import fetch_exploitdb_shellcodes
                fetch_exploitdb_shellcodes()
            except ImportError:
                print("[Erro] Não foi possível importar 'fetch_exploitdb.py' (shellcodes).")
            except Exception as e:
                print(f"[Erro] Problema ao processar Exploit-DB (shellcodes): {e}")

        elif choice == "7":
            # Executar todas as extrações (1 a 6) com valores padrão
            print("=== Iniciando execução de todas as extrações (padrão) ===")

            # 1) CVE completo
            try:
                from fetch_full import fetch_full_csv_and_insert
                print("\n[1/6] Executando feed completo de CVEs (NVD)...")
                fetch_full_csv_and_insert()
            except Exception as e:
                print(f"[1/6] Erro ao processar feed completo de CVE: {e}")

            # 2) CVE incremental (padrão 1 dia)
            try:
                from fetch_incremental import fetch_incremental
                print("\n[2/6] Executando CVEs incrementais (NVD) [último dia]...")
                fetch_incremental(1)
            except Exception as e:
                print(f"[2/6] Erro ao processar CVEs incrementais: {e}")

            # 3) CVE via API (padrão 1 dia)
            try:
                from fetch_cve_api import fetch_cve_api
                print("\n[3/6] Executando CVEs via API NVD [último dia]...")
                fetch_cve_api(1)
            except Exception as e:
                print(f"[3/6] Erro ao processar CVEs via API: {e}")

            # 4) CXSecurity
            try:
                from fetch_cxsecurity import fetch_cxsecurity_rss
                print("\n[4/6] Executando vulnerabilidades do CXSecurity...")
                fetch_cxsecurity_rss()
            except Exception as e:
                print(f"[4/6] Erro ao processar CXSecurity: {e}")

            # 5) Exploit-DB: exploits
            try:
                from fetch_exploitdb import fetch_exploitdb_exploits
                print("\n[5/6] Executando metadados de exploits (Exploit-DB)...")
                fetch_exploitdb_exploits()
            except Exception as e:
                print(f"[5/6] Erro ao processar Exploit-DB (exploits): {e}")

            # 6) Exploit-DB: shellcodes
            try:
                from fetch_exploitdb import fetch_exploitdb_shellcodes
                print("\n[6/6] Executando metadados de shellcodes (Exploit-DB)...")
                fetch_exploitdb_shellcodes()
            except Exception as e:
                print(f"[6/6] Erro ao processar Exploit-DB (shellcodes): {e}")

            print("\n=== Fim da execução de todas as extrações ===")

        elif choice == "8":
            print("Saindo...")
            sys.exit(0)

        else:
            print("Opção inválida. Tente novamente.\n")


if __name__ == "__main__":
    main()
