# -*- coding: utf-8 -*-
import os
from dotenv import load_dotenv
import whois
import re
import argparse
from urllib.parse import quote
import requests
import json

RESULTS_DIR = "results"

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

API_KEY_WHOXY = os.getenv("API_KEY_WHOXY")

def get_owner_and_emails(domain):
    domain_info = whois.whois(domain)
    owner = domain_info.get('registrant_name', '')

    # Use regular expression to find emails in the WHOIS response
    email_pattern = re.compile(r'[\w\.-]+@[\w\.-]+')
    emails = email_pattern.findall(str(domain_info))

    return owner, emails

def make_request(url):
    try:
        response = requests.post(url)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Erro na solicitação HTTP: {e}")
        return None

def save_result(filename, content):
    with open(os.path.join(RESULTS_DIR, filename), "w", encoding="utf-8") as file:
        file.write(content)

def save_domain_names(filename, domain_names):
    with open(os.path.join(RESULTS_DIR, filename), "w", encoding="utf-8") as file:
        for domain_name in domain_names:
            file.write(domain_name + "\n")

def extract_domain_names(results_dir):
    domain_names = []

    # Percorre os arquivos no diretório results/
    for filename in os.listdir(results_dir):
        filepath = os.path.join(results_dir, filename)

        # Verifica se o arquivo é um arquivo JSON
        if os.path.isfile(filepath) and filename.endswith("_result.json"):
            with open(filepath, "r") as file:
                try:
                    data = json.load(file)
                    search_result = data.get("search_result", [])
                    for entry in search_result:
                        domain_name = entry.get("domain_name")
                        print(domain_name)
                        if domain_name:
                            domain_names.append(domain_name)
                except json.JSONDecodeError as e:
                    print(f"Erro ao decodificar JSON em {filename}: {e}")

    return domain_names

def main():
    parser = argparse.ArgumentParser(description="Script para consultar informações WHOIS e fazer solicitações HTTP para URLs relacionadas.")
    parser.add_argument("-d", "--domain", required=True, help="Domínio para consulta WHOIS")

    args = parser.parse_args()
    DOMAIN = args.domain

    # Cria o diretório results/ se não existir
    os.makedirs(RESULTS_DIR, exist_ok=True)

    owner, emails = get_owner_and_emails(DOMAIN)

    print("\nResultados:")
    print(f"Owner: {owner}")
    print(f"E-mails: {', '.join(emails)}")

    for email in emails:
        encoded_email = quote(email)
        url = f"http://api.whoxy.com/?key={API_KEY_WHOXY}&reverse=whois&mode=micro&email={encoded_email}"
        result = make_request(url)
        if result is not None:
            save_result(f"{email}_result.json", result)

    encoded_owner = quote(owner)

    for prefix in ['name', 'company', 'keyword']:
        url = f"http://api.whoxy.com/?key={API_KEY_WHOXY}&reverse=whois&mode=micro&{prefix}={encoded_owner}"
        result = make_request(url)
        if result is not None:
            save_result(f"{prefix}_result.json", result)

    # Carrega os domínios extraídos dos resultados
    extracted_domain_names = extract_domain_names(RESULTS_DIR)

    # Salva os domain_names em results/domains.txt
    save_domain_names("domains.txt", extracted_domain_names)

if __name__ == "__main__":
    main()
