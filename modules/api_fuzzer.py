HEADERS = {
    'User-Agent': 'Mozilla/5.0',
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

def fuzz_api(base_url, retry_func, wordlists):
    routes, params = wordlists
    found = []

    for route in routes:
        url = f"{base_url.rstrip('/')}/{route}"
        for method in ['GET', 'POST', 'PUT', 'DELETE']:
            for param in params:
                payload = {param: 'FUZZ'}
                try:
                    if method == 'GET':
                        r = retry_func(url, params=payload, headers=HEADERS)
                    else:
                        r = retry_func(url, json=payload, headers=HEADERS, method=method)

                    if r and r.status_code in [200, 201, 400, 422]:
                        found.append({
                            'url': url,
                            'param': param,
                            'method': method,
                            'status': r.status_code
                        })
                        print(f"[+] Encontrado: {method} {url} ?{param} ({r.status_code})")
                except:
                    pass
    return found
