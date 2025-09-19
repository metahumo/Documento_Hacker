#!/usr/bin/env python3
# fuzzer.py
# Fuzzer PoC (v4) — endpoints & subdominios recursivo, headers personalizados, métodos HTTP, logging
# Autor: Metahumo
# Contacto: metahumo@outlook.com — https://github.com/metahumo
# Licencia: MIT (proyectos de PoC/educativos) 
# Copyright (c) 2025 Metahumo

import requests
import argparse
import os
import sys
import signal
import time
import random
import hashlib
from urllib.parse import urlparse, urljoin
from datetime import datetime

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(0)
signal.signal(signal.SIGINT, def_handler)

CHECK_CODES = [200, 301, 302, 403]
tested_urls = {}
tested_paths = set()
endpoints_found = []
subdomains_found = []

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/116.0.5845.97 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
}

log_file = f"fuzzer_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

def get_hash(content):
    return hashlib.md5(content).hexdigest()

def log_result(url, status, kind):
    with open(log_file, "a") as f:
        f.write(f"[{status}] {url} ({kind})\n")

def print_result(url, status, kind):
    print(f"[{status}] {url} ({kind})")
    log_result(url, status, kind)

def fuzzer_endpoints(url, wordlist, delay=0, recursive=True, max_depth=2, depth=0, methods=["GET"], data=None, headers=None):
    if depth > max_depth:
        return
    if not os.path.isfile(wordlist):
        print(f"[!] No se ha encontrado la Wordlist: {wordlist}")
        return
    if headers is None:
        headers = HEADERS
    with open(wordlist, "r") as f:
        lines = f.readlines()
    queue = [url.rstrip('/')]
    while queue:
        base = queue.pop(0)
        for line in lines:
            endpoint = line.strip()
            if not endpoint:
                continue
            full_url = urljoin(base + '/', endpoint)
            path = urlparse(full_url).path
            if path in tested_paths:
                continue
            tested_paths.add(path)
            for method in methods:
                try:
                    r = requests.request(method, full_url, timeout=5, headers=headers, data=data)
                    if r.status_code in CHECK_CODES:
                        content_hash = get_hash(r.content)
                        if full_url in tested_urls and tested_urls[full_url] == content_hash:
                            continue
                        tested_urls[full_url] = content_hash
                        endpoints_found.append((full_url, r.status_code))
                        print_result(full_url, r.status_code, "Endpoint")
                        if recursive and full_url.endswith('/'):
                            queue.append(full_url)
                    if delay > 0:
                        time.sleep(delay + random.random())
                except requests.RequestException:
                    continue

def fuzzer_subdomains(url, wordlist, delay=0, recursive=True, max_depth=2, depth=0, methods=["GET"], data=None, headers=None):
    if depth > max_depth:
        return
    parsed = urlparse(url)
    domain = parsed.netloc
    if not os.path.isfile(wordlist):
        print(f"[!] No se ha encontrado la Wordlist: {wordlist}")
        return
    if headers is None:
        headers = HEADERS
    with open(wordlist, "r") as f:
        lines = f.readlines()
    queue = [domain]
    while queue:
        base_domain = queue.pop(0)
        for line in lines:
            sub = line.strip()
            if not sub:
                continue
            sub_url = f"{parsed.scheme}://{sub}.{base_domain}"
            if sub_url in tested_urls:
                continue
            for method in methods:
                try:
                    r = requests.request(method, sub_url, timeout=5, headers=headers, data=data)
                    if r.status_code in CHECK_CODES:
                        content_hash = get_hash(r.content)
                        if sub_url in tested_urls and tested_urls[sub_url] == content_hash:
                            continue
                        tested_urls[sub_url] = content_hash
                        subdomains_found.append((sub_url, r.status_code))
                        print_result(sub_url, r.status_code, "Subdominio")
                        if recursive:
                            fuzzer_endpoints(sub_url, wordlist, delay=delay, recursive=True, max_depth=max_depth, depth=depth+1, methods=methods, data=data, headers=headers)
                    if delay > 0:
                        time.sleep(delay + random.random())
                except requests.RequestException:
                    continue

def main():
    parser = argparse.ArgumentParser(description="Fuzzer Prototipo v4 (c) 2025 Metahumo - Pentesting Web Avanzado")
    parser.add_argument("url", help="URL objetivo, ej: http://objetivo.com")
    parser.add_argument("-e", "--endpoints", dest="endpoints", help="Wordlist de endpoints")
    parser.add_argument("-s", "--subdomains", dest="subdomains", help="Wordlist de subdominios")
    parser.add_argument("-w", "--wordlist", dest="wordlist", help="Wordlist combinada (dominios y subdominios)")
    parser.add_argument("-t", "--time", dest="delay", type=float, default=0, help="Tiempo entre peticiones (segundos) para reducir ruido")
    parser.add_argument("--max-depth", dest="max_depth", type=int, default=2, help="Profundidad máxima recursiva")
    parser.add_argument("-m", "--methods", dest="methods", nargs='+', default=["GET"], help="Métodos HTTP a usar, ej: GET HEAD POST")
    parser.add_argument("-d", "--data", dest="data", help="Datos a enviar en métodos POST/PUT")
    parser.add_argument("-H", "--header", dest="headers", nargs='+', help='Headers adicionales: "Header: Valor"')
    args = parser.parse_args()

    custom_headers = HEADERS.copy()
    if args.headers:
        for h in args.headers:
            if ':' in h:
                k, v = h.split(':', 1)
                custom_headers[k.strip()] = v.strip()

    if not any([args.endpoints, args.subdomains, args.wordlist]):
        parser.print_help()
        sys.exit(1)

    if args.endpoints:
        fuzzer_endpoints(args.url, args.endpoints, delay=args.delay, max_depth=args.max_depth, methods=args.methods, data=args.data, headers=custom_headers)
    if args.subdomains:
        fuzzer_subdomains(args.url, args.subdomains, delay=args.delay, max_depth=args.max_depth, methods=args.methods, data=args.data, headers=custom_headers)
    if args.wordlist:
        fuzzer_endpoints(args.url, args.wordlist, delay=args.delay, max_depth=args.max_depth, methods=args.methods, data=args.data, headers=custom_headers)
        fuzzer_subdomains(args.url, args.wordlist, delay=args.delay, max_depth=args.max_depth, methods=args.methods, data=args.data, headers=custom_headers)

    print("\n=== Endpoints encontrados ===")
    for code in sorted(CHECK_CODES):
        for url, status in sorted([e for e in endpoints_found if e[1]==code], key=lambda x: x[0]):
            print(f"[{status}] {url}")

    print("\n=== Subdominios encontrados ===")
    for code in sorted(CHECK_CODES):
        for url, status in sorted([s for s in subdomains_found if s[1]==code], key=lambda x: x[0]):
            print(f"[{status}] {url}")

    print(f"\n[!] Log guardado en {log_file}")

if __name__ == "__main__":
    main()
