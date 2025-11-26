# -*- coding: utf-8 -*-
import os
from dotenv import load_dotenv
import whois
import re
import argparse
from urllib.parse import quote
import requests
import json
import csv
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

RESULTS_DIR = "results"
DEFAULT_TIMEOUT = 15
DEFAULT_RETRIES = 3

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

API_KEY_WHOXY = os.getenv("API_KEY_WHOXY")

def get_owner_and_emails(domain):
    domain_info = whois.whois(domain)
    owner = domain_info.get('registrant_name', '') or domain_info.get('name', '') or ''

    email_pattern = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    emails = email_pattern.findall(str(domain_info))

    return owner.strip(), sorted(set(e.strip() for e in emails))

def build_session(max_retries):
    session = requests.Session()
    retry = Retry(
        total=max_retries,
        read=max_retries,
        connect=max_retries,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": "revwhoxy/1.0"})
    return session

def make_request(session, url, timeout):
    try:
        response = session.post(url, timeout=timeout)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        logging.warning(f"Erro na solicitação HTTP: {e}")
        return None

def save_result(filename, content, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, filename), "w", encoding="utf-8") as file:
        file.write(content)

def save_domain_names_txt(filename, domain_names, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, filename), "w", encoding="utf-8") as file:
        for domain_name in domain_names:
            file.write(domain_name + "\n")

def save_domain_names_csv(filename, domain_names, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, filename), "w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["domain"])
        for domain_name in domain_names:
            writer.writerow([domain_name])

def extract_domain_names(results_dir):
    domain_names = []

    # Percorre os arquivos no diretório results/
    for filename in os.listdir(results_dir):
        filepath = os.path.join(results_dir, filename)

        if os.path.isfile(filepath) and filename.endswith("_result.json"):
            with open(filepath, "r", encoding="utf-8") as file:
                try:
                    data = json.load(file)
                    search_result = data.get("search_result", [])
                    for entry in search_result:
                        domain_name = entry.get("domain_name")
                        if domain_name:
                            domain_names.append(domain_name)
                except json.JSONDecodeError as e:
                    logging.warning(f"Erro ao decodificar JSON em {filename}: {e}")

    # Deduplica e ordena
    unique_sorted = sorted(set(domain_names))
    return unique_sorted

def sanitize_filename(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)

def main():
    parser = argparse.ArgumentParser(description="Consulta WHOIS e reverse WHOIS (Whoxy) para descobrir domínios relacionados.")
    parser.add_argument("-d", "--domain", required=True, help="Domínio para consulta WHOIS (ex.: exemplo.com)")
    parser.add_argument("-e", "--email", action="append", dest="emails", help="Email(s) para buscar no Whoxy (pode ser usado múltiplas vezes)")
    parser.add_argument("--out-dir", default=RESULTS_DIR, help=f"Diretório de saída (padrão: {RESULTS_DIR})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Timeout (s) por requisição (padrão: {DEFAULT_TIMEOUT})")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help=f"Número de tentativas (padrão: {DEFAULT_RETRIES})")
    parser.add_argument("--no-owner-search", action="store_true", help="Não pesquisar por name/company/keyword do owner")
    parser.add_argument("--no-email-search", action="store_true", help="Não pesquisar por e-mails encontrados no WHOIS")
    parser.add_argument("--csv", action="store_true", help="Exportar domains.csv além do domains.txt")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verboso")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    DOMAIN = args.domain.strip()
    if not re.match(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?:[A-Za-z]{2,}|[A-Za-z0-9-]{2,})", DOMAIN):
        logging.error("Domínio inválido informado.")
        return

    out_dir = args.out_dir

    # Cria o diretório de saída
    os.makedirs(out_dir, exist_ok=True)

    owner, emails_from_whois = get_owner_and_emails(DOMAIN)

    # Combina emails do WHOIS com emails fornecidos manualmente
    all_emails = set()
    if not args.no_email_search and emails_from_whois:
        all_emails.update(emails_from_whois)
    if args.emails:
        # Valida emails fornecidos manualmente
        email_pattern = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
        for email in args.emails:
            email = email.strip()
            if email_pattern.match(email):
                all_emails.add(email)
            else:
                logging.warning(f"Email inválido ignorado: {email}")

    all_emails = sorted(all_emails)

    print("\n" + "="*60)
    print("RESULTADOS DA CONSULTA WHOIS")
    print("="*60)
    print(f"Domínio: {DOMAIN}")
    print(f"Owner: {owner or '(desconhecido)'}")
    print("\nE-mails encontrados:")
    if emails_from_whois:
        for i, email in enumerate(emails_from_whois, 1):
            print(f"  [{i}] {email}")
    else:
        print("  (nenhum email encontrado no WHOIS)")
    
    if args.emails:
        print("\nE-mails fornecidos manualmente:")
        for i, email in enumerate(args.emails, 1):
            email = email.strip()
            email_pattern = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
            status = "✓" if email_pattern.match(email) else "✗ (inválido)"
            print(f"  [{i}] {email} {status}")
    
    print(f"\nTotal de e-mails para buscar no Whoxy: {len(all_emails)}")
    if all_emails:
        print("E-mails que serão pesquisados:")
        for i, email in enumerate(all_emails, 1):
            print(f"  [{i}] {email}")
    print("="*60 + "\n")

    if not API_KEY_WHOXY:
        logging.warning("API_KEY_WHOXY não definido no ambiente (.env). Pulando consultas à API Whoxy.")
    else:
        session = build_session(args.retries)

        if all_emails:
            logging.info(f"Buscando domínios por email no Whoxy...")
            for email in all_emails:
                logging.info(f"Buscando por: {email}")
                encoded_email = quote(email)
                url = f"https://api.whoxy.com/?key={API_KEY_WHOXY}&reverse=whois&mode=micro&email={encoded_email}"
                result = make_request(session, url, timeout=args.timeout)
                if result is not None:
                    save_result(f"{sanitize_filename(email)}_result.json", result, out_dir)
                    logging.info(f"Resultado salvo para {email}")
                else:
                    logging.warning(f"Falha ao buscar por {email}")

        if not args.no_owner_search and owner:
            encoded_owner = quote(owner)
            for prefix in ['name', 'company', 'keyword']:
                url = f"https://api.whoxy.com/?key={API_KEY_WHOXY}&reverse=whois&mode=micro&{prefix}={encoded_owner}"
                result = make_request(session, url, timeout=args.timeout)
                if result is not None:
                    save_result(f"{prefix}_result.json", result, out_dir)

    # Carrega os domínios extraídos dos resultados
    extracted_domain_names = extract_domain_names(out_dir)

    # Salva os domain_names
    save_domain_names_txt("domains.txt", extracted_domain_names, out_dir)
    if args.csv:
        save_domain_names_csv("domains.csv", extracted_domain_names, out_dir)
    
    # Exibe resumo final no terminal
    print("\n" + "="*60)
    print("RESUMO FINAL")
    print("="*60)
    print(f"Total de domínios encontrados (únicos): {len(extracted_domain_names)}")
    print(f"Total de e-mails pesquisados: {len(all_emails)}")
    print(f"Arquivos salvos em: {out_dir}/")
    if extracted_domain_names:
        print(f"\nTodos os domínios encontrados (sem repetições):")
        for i, domain in enumerate(extracted_domain_names, 1):
            print(f"  [{i:3d}] {domain}")
    else:
        print("\nNenhum domínio encontrado.")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
