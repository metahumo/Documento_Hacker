
---

# Fuzzer PoC Tutorial 2

Este documento describe la evolución del **fuzzer de endpoints y subdominios**, partiendo del PoC anterior (`fuzzer_v1.4.py`) y mostrando cómo se fueron añadiendo mejoras progresivas. El objetivo es que un principiante pueda comprender la ejecución y los cambios introducidos.

---

## Referencia inicial

El fuzzer anterior (`fuzzer_v1.4.py`) permitía: [Ver Fuzzer parte 1](./Fuzzer_PoC_tutorial_parte_1.md)

- Probar endpoints de una URL base usando una **wordlist**.
- Filtrar las respuestas para mostrar solo códigos HTTP "interesantes" (200, 301, 302, 403).
- Soporte de wordlist de endpoints.
- Ejemplo de uso:

```bash
python3 fuzzer_v4.py http://192.168.1.77 -w fuzzing.txt
````

---

## Versión v2.1 – Fuzzer básico con wordlist opcional

**Archivo:** `fuzzer_v2.1.py`

### Script completo:

```python
#!/usr/bin/env python3

import requests
import argparse
import os

# Check list codes
check_codes = [200, 301, 302, 403]

def print_result(r):
    if r.status_code in check_codes:
        print(f"[{r.status_code}] {r.url}")

def fuzzer_endpoints(url, endpoints):
    if not os.path.isfile(endpoints):
        print(f"[!] No se ha encontrado la Wordlist: {endpoints}")
        return

    with open(endpoints, "r") as f:
        for line in f:
            endpoint = line.strip()
            if not endpoint:
                continue
            full_url = f"{url.rstrip('/')}/{endpoint.lstrip('/')}"
            try:
                r = requests.get(full_url, timeout=3)
                print_result(r)
            except requests.RequestException:
                continue

def main():
    parser = argparse.ArgumentParser(description="Fuzzer V2.1")
    parser.add_argument("url", help="URL objetivo, ej: http://ejemplo")
    parser.add_argument("-e", "--endpoints", dest="endpoints", help="Wordlist de endpoints (opcional)", required=False)
    args = parser.parse_args()
    fuzzer_endpoints(args.url, args.endpoints)

if __name__ == '__main__':
    main()
```

### Ejemplo de ejecución:

```bash
python3 fuzzer_v2.1.py http://192.168.1.77 -e fuzzing.txt
```

**Salida:**

```
[200] http://192.168.1.77/index.php
[200] http://192.168.1.77/info.php
[403] http://192.168.1.77/.htaccess
[403] http://192.168.1.77/.htpasswd
[200] http://192.168.1.77/index.html
[403] http://192.168.1.77/.htaccess.bak
[403] http://192.168.1.77/.htpasswd.bak
[403] http://192.168.1.77/css/
```

---

## Versión v2.2 – Manejo de interrupciones y corrección de excepciones

**Archivo:** `fuzzer_v2.2.py`

### Script completo:

```python
#!/usr/bin/env python3

import requests
import argparse
import os
import sys, signal

def def_handler(sig, frame):
    print(f"\n[!] Saliendo...\n")
    sys.exit(0)

signal.signal(signal.SIGINT, def_handler)

# Check list codes
check_codes = [200, 301, 302, 403]

def print_result(r):
    if r.status_code in check_codes:
        print(f"[{r.status_code}] {r.url}")

def fuzzer_endpoints(url, endpoints):
    if not os.path.isfile(endpoints):
        print(f"[!] No se ha encontrado la Wordlist: {endpoints}")
        return

    with open(endpoints, "r") as f:
        for line in f:
            endpoint = line.strip()
            if not endpoint:
                continue
            full_url = f"{url.rstrip('/')}/{endpoint.lstrip('/')}"
            try:
                r = requests.get(full_url, timeout=3)
                print_result(r)
            except requests.RequestException:
                continue

def main():
    parser = argparse.ArgumentParser(description="Fuzzer V2.2")
    parser.add_argument("url", help="URL objetivo, ej: http://ejemplo")
    parser.add_argument("-e", "--endpoints", dest="endpoints", help="Wordlist de endpoints (opcional)", required=False)
    args = parser.parse_args()
    if not args.url or not args.endpoints:
        parser.print_help()
        sys.exit(1)
    fuzzer_endpoints(args.url, args.endpoints)

if __name__ == '__main__':
    main()
```

### Ejemplo de ejecución:

```bash
python3 fuzzer_v2.2.py http://192.168.1.77 -e fuzzing.txt
```

**Salida:**

```
[200] http://192.168.1.77/index.php
[200] http://192.168.1.77/info.php
[403] http://192.168.1.77/.htaccess
[403] http://192.168.1.77/.htpasswd
^C
[!] Saliendo...
```

---

## Versión v2.3 – Soporte de subdominios opcional

**Archivo:** `fuzzer_v2.3.py`

### Script completo:

```python
#!/usr/bin/env python3

import requests
import argparse
import os
import sys, signal
from urllib.parse import urlparse

def def_handler(sig, frame):
    print(f"\n[!] Saliendo...\n")
    sys.exit(0)

signal.signal(signal.SIGINT, def_handler)

# Check list codes
check_codes = [200, 301, 302, 403]

def print_result(r):
    if r.status_code in check_codes:
        print(f"[{r.status_code}] {r.url}")

def fuzzer_endpoints(url, endpoints):
    if not os.path.isfile(endpoints):
        print(f"[!] No se ha encontrado la Wordlist: {endpoints}")
        return

    with open(endpoints, "r") as f:
        for line in f:
            endpoint = line.strip()
            if not endpoint:
                continue
            full_url = f"{url.rstrip('/')}/{endpoint.lstrip('/')}"
            try:
                r = requests.get(full_url, timeout=3)
                print_result(r)
            except requests.RequestException:
                continue

def fuzzer_subdomains(url, subdomains):
    parsed = urlparse(url)
    domain = parsed.netloc
    if not os.path.isfile(subdomains):
        print(f"[!] No se ha encontrado la Wordlist: {subdomains}")
        return
    with open(subdomains, "r") as f:
        for line in f:
            sub = line.strip()
            if not sub:
                continue
            subdomain_url = f"{parsed.scheme}://{sub}.{domain}"
            try:
                r = requests.get(subdomain_url, timeout=3)
                print_result(r)
            except requests.RequestException:
                continue

def main():
    parser = argparse.ArgumentParser(description="Fuzzer V2.3")
    parser.add_argument("url", help="URL objetivo, ej: http://ejemplo")
    parser.add_argument("-e", "--endpoints", dest="endpoints", help="Wordlist de endpoints (opcional)", required=False)
    parser.add_argument("-s", "--subdomains", dest="subdomains", help="Wordlist de subdominions (opcional)", required=False)
    args = parser.parse_args()
    if not args.url:
        parser.print_help()
        sys.exit(1)
    if args.endpoints:
        fuzzer_endpoints(args.url, args.endpoints)
    if args.subdomains:
        fuzzer_subdomains(args.url, args.subdomains)

if __name__ == '__main__':
    main()
```

### Ejemplo de ejecución combinada:

```bash
python3 fuzzer_v2.3.py http://192.168.1.77 -e endpoints.txt -s subdomains.txt
```

**Salida:**

```
[200] http://192.168.1.77/index.php
[200] http://192.168.1.77/info.php
[403] http://192.168.1.77/.htaccess
[403] http://192.168.1.77/.htpasswd
[200] http://192.168.1.77/index.html
[403] http://192.168.1.77/.htaccess.bak
[403] http://192.168.1.77/.htpasswd.bak
[403] http://192.168.1.77/css/
^C
[!] Saliendo...
```

### Observaciones:

- Se mantiene la misma lógica de filtrado de la versión v2.2.
    
- Se puede ejecutar en **cualquier combinación**:
    
    - Solo endpoints: `-e fuzzing.txt`
        
    - Solo subdominios: `-s fuzzing.txt`
        
    - Ambos: `-e fuzzing.txt -s fuzzing.txt`
        
- El script es robusto frente a URLs inexistentes o errores de conexión.
    


---

## Versión v2.4 – Soporte de control time

**Archivo:** `fuzzer_v2.4.py`


```python
#!/usr/bin/env python3

import requests
import argparse
import os
import sys, signal
import time
from urllib.parse import urlparse

def def_handler(sig, frame):
    print(f"\n[!] Saliendo...\n")
    sys.exit(0)

signal.signal(signal.SIGINT, def_handler)

# Check list codes
check_codes = [200, 301, 302, 403]

def print_result(r):
    if r.status_code in check_codes:
        print(f"[{r.status_code}] {r.url}")

def fuzzer_endpoints(url, endpoints, delay):
    if not os.path.isfile(endpoints):
        print(f"[!] No se ha encontrado la Wordlist: {endpoints}")
        return

    with open(endpoints, "r") as f:
        for line in f:
            endpoint = line.strip()
            if not endpoint:
                continue

            full_url = f"{url.rstrip('/')}/{endpoint.lstrip('/')}"
            
            try:
                r = requests.get(full_url, timeout=3)
                print_result(r)
            except requests.RequestException:
                continue
            time.sleep(delay)  # retraso entre requests

def fuzzer_subdomains(url, subdomains, delay):
    parsed = urlparse(url)
    domain = parsed.netloc

    if not os.path.isfile(subdomains):
        print(f"[!] No se ha encontrado la Wordlist: {subdomains}")
        return

    with open(subdomains, "r") as f:
        for line in f:
            sub = line.strip()
            if not sub:
                continue
            subdomain_url = f"{parsed.scheme}://{sub}.{domain}"
            try:
                r = requests.get(subdomain_url, timeout=3)
                print_result(r)
            except requests.RequestException:
                continue
            time.sleep(delay)  # retraso entre requests

def main():
    parser = argparse.ArgumentParser(description="Fuzzer V2.3 con retardo entre requests")
    parser.add_argument("url", help="URL objetivo, ej: http://ejemplo")
    parser.add_argument("-e", "--endpoints", dest="endpoints", help="Wordlist de endpoints (opcional)", required=False)
    parser.add_argument("-s", "--subdomains", dest="subdomains", help="Wordlist de subdominions (opcional)", required=False)
    parser.add_argument("-t", "--time", dest="delay", type=float, default=0, help="Tiempo de espera entre requests (segundos, default=0)")
    args = parser.parse_args()

    if not args.url:
        parser.print_help()
        sys.exit(1)
    
    if args.endpoints:
        fuzzer_endpoints(args.url, args.endpoints, args.delay)
    if args.subdomains:
        fuzzer_subdomains(args.url, args.subdomains, args.delay)

if __name__ == '__main__':
    main()
```

**Cambios principales**:

1. Añadido parámetro `-t / --time` que define el retardo en segundos (`float`), default 0.
    
2. Se usa `time.sleep(delay)` entre cada request en `fuzzer_endpoints` y `fuzzer_subdomains`.
    
3. Permite mantener la compatibilidad con `-e` y `-s` como antes.
    

Ejemplo de escaneo “tranquilo”:

```bash
python3 fuzzer_v2.3.py http://192.168.1.77 -e fuzzing.txt -s fuzzing_sub.txt -t 1.5
```

Esto hará que entre cada request espere 1.5 segundos.

No hay un valor universal, porque depende mucho del servidor, su capacidad, reglas de firewall y WAF, pero aquí  damos **una guía práctica basada en experiencia ofensiva y pentesting ético**:

---

### 1️ Servidores pequeños / locales / de laboratorio

- Retardo muy pequeño: **0.2 – 0.5 segundos** suele ser suficiente para no saturar y simular tráfico humano.
    
- Más alto solo ralentiza la prueba innecesariamente.
    

### 2️ Servidores públicos / WAF / detección básica

- Retardo medio: **1 – 2 segundos** entre peticiones.
    
- Reduce el riesgo de bloqueos automáticos y falsas alertas en logs.
    

### 3️ Servidores con WAF avanzados / IDS

- Retardo alto: **3 – 5 segundos** o incluso más.
    
- A veces conviene mezclar con otras técnicas: cambiar User-Agent, rotar IPs, limitar número de endpoints probados por sesión.


---

## Versión prototipo v2.4 → v3 – Recursividad y wordlist combinada

### Script completo: `fuzzer_prototipo_v3.py`

```python
#!/usr/bin/env python3

import requests
import argparse
import os
import sys, signal
import time
from urllib.parse import urlparse, urljoin

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(0)

signal.signal(signal.SIGINT, def_handler)

CHECK_CODES = [200, 301, 302, 403]

tested_urls = {}
tested_paths = set()
endpoints_found = []
subdomains_found = []

def print_result(url, status, kind):
    print(f"[{status}] {url} ({kind})")

def fuzzer_endpoints(url, wordlist, delay=0, recursive=True):
    if not os.path.isfile(wordlist):
        print(f"[!] No se ha encontrado la Wordlist: {wordlist}")
        return

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

            try:
                r = requests.get(full_url, timeout=3)
                if r.status_code in CHECK_CODES:
                    size = len(r.content)
                    if full_url in tested_urls and tested_urls[full_url] == size:
                        continue
                    tested_urls[full_url] = size
                    endpoints_found.append((full_url, r.status_code))
                    print_result(full_url, r.status_code, "Endpoint")

                    if recursive and full_url.endswith('/'):
                        queue.append(full_url)

                if delay > 0:
                    time.sleep(delay)

            except requests.RequestException:
                continue

def fuzzer_subdomains(url, wordlist, delay=0, recursive=True):
    if not os.path.isfile(wordlist):
        print(f"[!] No se ha encontrado la Wordlist: {wordlist}")
        return

    parsed = urlparse(url)
    domain = parsed.netloc

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

            try:
                r = requests.get(sub_url, timeout=3)
                if r.status_code in CHECK_CODES:
                    size = len(r.content)
                    if sub_url in tested_urls and tested_urls[sub_url] == size:
                        continue
                    tested_urls[sub_url] = size
                    subdomains_found.append((sub_url, r.status_code))
                    print_result(sub_url, r.status_code, "


Subdominio")


                if recursive and sub_url.endswith('/'):
                    fuzzer_endpoints(sub_url, wordlist, delay=delay)

            if delay > 0:
                time.sleep(delay)

        except requests.RequestException:
            continue


def main():  
parser = argparse.ArgumentParser(description="Fuzzer Prototipo v3 - Endpoints y Subdominios Recursivo")  
parser.add_argument("url", help="URL objetivo, ej: [http://ejemplo.com](http://ejemplo.com/)")  
parser.add_argument("-e", "--endpoints", dest="endpoints", help="Wordlist de endpoints (opcional)")  
parser.add_argument("-s", "--subdomains", dest="subdomains", help="Wordlist de subdominios (opcional)")  
parser.add_argument("-w", "--wordlist", dest="wordlist", help="Wordlist combinada (opcional)")  
parser.add_argument("-t", "--time", dest="delay", type=float, default=0, help="Tiempo en segundos entre peticiones")  
args = parser.parse_args()


if not any([args.endpoints, args.subdomains, args.wordlist]):
    parser.print_help()
    sys.exit(1)

if args.endpoints:
    fuzzer_endpoints(args.url, args.endpoints, delay=args.delay)
if args.subdomains:
    fuzzer_subdomains(args.url, args.subdomains, delay=args.delay)
if args.wordlist:
    fuzzer_endpoints(args.url, args.wordlist, delay=args.delay)
    fuzzer_subdomains(args.url, args.wordlist, delay=args.delay)

# Resumen final ordenado
print("\n=== Endpoints encontrados ===")
for code in sorted(CHECK_CODES):
    for url, status in sorted([e for e in endpoints_found if e[1]==code], key=lambda x: x[0]):
        print(f"[{status}] {url}")

print("\n=== Subdominios encontrados ===")
for code in sorted(CHECK_CODES):
    for url, status in sorted([s for s in subdomains_found if s[1]==code], key=lambda x: x[0]):
        print(f"[{status}] {url}")


if **name** == "**main**":  
main()

```

### Qué añade esta versión:

- **Recursividad:** los endpoints tipo directorio (`/admin/`) vuelven a ser explorados con la misma wordlist.
- **Wordlist combinada** (`-w`) para probar dominios y subdominios desde un único archivo.
- Filtrado de duplicados usando path y tamaño de contenido.
- Mejora la organización de resultados finales, separando **Endpoints** y **Subdominios**.
- Mantiene soporte de `-t` para controlar la velocidad.

---

## Resumen final de la evolución

1. **v2.3:** Subdominios opcionales, impresión básica, Ctrl+C seguro.
2. **v2.4:** Añadido `-t` para retrasos entre requests y evitar detección.
3. **v2.4-v3:** Recursividad, wordlist combinada `-w`, filtrado de duplicados, resumen final ordenado, soporte completo de endpoints y subdominios.
4. **v3.2 (prototipo final):** Añade control de profundidad, headers realistas, logging a archivo, métodos HTTP adicionales, filtrado avanzado de falsos positivos, modularidad y robustez para pentesting. [Ver Fuzzer parte 3](./Fuzzer_PoC_tutorial_parte_3.md)

---
