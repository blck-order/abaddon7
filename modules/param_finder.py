# modules/param_finder_v2.py
import requests, re, json
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs

def find_params(url, retry_get_func):
    params = set()

    try:
        r = retry_get_func(url)
        if not r:
            return []

        soup = BeautifulSoup(r.text, 'html.parser')

        # 1. Formulários
        for form in soup.find_all('form'):
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if name:
                    params.add(name)

        # 2. JS dinâmico (fetch, axios, window.location, etc.)
        js_patterns = [
            r'["\'`]([^"\']+)[\'"]\s*:\s*["\'`].*?["\'`]',  # key: "value"
            r'fetch\(["\'`]([^"\']+)["\'`]',                # fetch("/api?param=...")
            r'axios\.(get|post)\(["\'`]([^"\']+)["\'`]',   # axios.post("/path")
            r'window\.location\.href\s*=\s*["\'`]([^"\']+)["\'`]',  # redirecionamento
        ]
        for pattern in js_patterns:
            matches = re.findall(pattern, r.text)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[-1]
                if '?' in match:
                    params.update(parse_qs(urlparse(match).query).keys())

        # 3. JSON embutido em <script>
        for script in soup.find_all('script'):
            if script.string:
                try:
                    data = json.loads(script.string)
                    if isinstance(data, dict):
                        params.update(data.keys())
                except:
                    pass

        # 4. Query strings em <a href>
        for a in soup.find_all('a', href=True):
            href = a.get('href', '')
            if '?' in href:
                params.update(parse_qs(urlparse(href).query).keys())

        # 5. Wordlist de parâmetros comuns (fallback agressivo)
        common_params = [
            'id', 'user', 'token', 'key', 'email', 'uid', 'page', 'limit', 'offset',
            'search', 'q', 'query', 'debug', 'admin', 'role', 'callback', 'next',
            'redirect', 'return', 'continue', 'state', 'code', 'auth', 'session'
        ]
        params.update(common_params)

    except:
        pass

    return list(params)
