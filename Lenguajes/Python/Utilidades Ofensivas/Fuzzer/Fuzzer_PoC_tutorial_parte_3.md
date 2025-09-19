
---

# Fuzzer Prototipo v3.2 – Explicación Completa

Este documento describe el **script final de fuzzer prototipo v3.2**, explicando cómo funciona, qué añade respecto a versiones anteriores, y cómo usar cada parámetro.

[Ver Fuzzer parte 2](./Fuzzer_PoC_tutorial_parte_2.md)

---

## 1. Script completo

```python
#!/usr/bin/env python3

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

# ------------------------
# Manejo Ctrl+C
# ------------------------
def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(0)
signal.signal(signal.SIGINT, def_handler)

# ------------------------
# Configuración global
# ------------------------
CHECK_CODES = [200, 301, 302, 403]  # Códigos HTTP de interés
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

# ------------------------
# Función utilitaria: hash de contenido
# ------------------------
def get_hash(content):
    return hashlib.md5(content).hexdigest()

# ------------------------
# Logging
# ------------------------
def log_result(url, status, kind):
    with open(log_file, "a") as f:
        f.write(f"[{status}] {url} ({kind})\n")

# ------------------------
# Imprimir resultados inmediatos
# ------------------------
def print_result(url, status, kind):
    print(f"[{status}] {url} ({kind})")
    log_result(url, status, kind)

# ------------------------
# Función fuzzer de endpoints
# ------------------------
def fuzzer_endpoints(url, wordlist, delay=0, recursive=True, max_depth=2, depth=0, methods=["GET"]):
    if depth > max_depth:
        return

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

            for method in methods:
                try:
                    r = requests.request(method, full_url, timeout=5, headers=HEADERS)
                    if r.status_code in CHECK_CODES:
                        content_hash = get_hash(r.content)
                        if full_url in tested_urls and tested_urls[full_url] == content_hash:
                            continue
                        tested_urls[full_url] = content_hash
                        endpoints_found.append((full_url, r.status_code))
                        print_result(full_url, r.status_code, "Endpoint")

                        # Recursividad
                        if recursive and full_url.endswith('/'):
                            queue.append(full_url)

                    if delay > 0:
                        time.sleep(delay + random.random())

                except requests.RequestException:
                    continue

# ------------------------
# Función fuzzer de subdominios
# ------------------------
def fuzzer_subdomains(url, wordlist, delay=0, recursive=True, max_depth=2, depth=0, methods=["GET"]):
    if depth > max_depth:
        return

    parsed = urlparse(url)
    domain = parsed.netloc

    if not os.path.isfile(wordlist):
        print(f"[!] No se ha encontrado la Wordlist: {wordlist}")
        return

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
                    r = requests.request(method, sub_url, timeout=5, headers=HEADERS)
                    if r.status_code in CHECK_CODES:
                        content_hash = get_hash(r.content)
                        if sub_url in tested_urls and tested_urls[sub_url] == content_hash:
                            continue
                        tested_urls[sub_url] = content_hash
                        subdomains_found.append((sub_url, r.status_code))
                        print_result(sub_url, r.status_code, "Subdominio")

                        # Recursividad: probar endpoints en este subdominio
                        if recursive:
                            fuzzer_endpoints(sub_url, wordlist, delay=delay, recursive=True, max_depth=max_depth, depth=depth+1, methods=methods)

                    if delay > 0:
                        time.sleep(delay + random.random())

                except requests.RequestException:
                    continue

# ------------------------
# Función principal
# ------------------------
def main():
    parser = argparse.ArgumentParser(description="Fuzzer Prototipo v3.2 - Pentesting Web Avanzado")
    parser.add_argument("url", help="URL objetivo, ej: http://ejemplo.com")
    parser.add_argument("-e", "--endpoints", dest="endpoints", help="Wordlist de endpoints")
    parser.add_argument("-s", "--subdomains", dest="subdomains", help="Wordlist de subdominios")
    parser.add_argument("-w", "--wordlist", dest="wordlist", help="Wordlist combinada (dominios y subdominios)")
    parser.add_argument("-t", "--time", dest="delay", type=float, default=0, help="Tiempo entre peticiones (segundos) para reducir ruido")
    parser.add_argument("--max-depth", dest="max_depth", type=int, default=2, help="Profundidad máxima recursiva")
    parser.add_argument("-m", "--methods", dest="methods", nargs='+', default=["GET"], help="Métodos HTTP a usar, ej: GET HEAD POST")
    args = parser.parse_args()

    if not any([args.endpoints, args.subdomains, args.wordlist]):
        parser.print_help()
        sys.exit(1)

    if args.endpoints:
        fuzzer_endpoints(args.url, args.endpoints, delay=args.delay, max_depth=args.max_depth, methods=args.methods)
    if args.subdomains:
        fuzzer_subdomains(args.url, args.subdomains, delay=args.delay, max_depth=args.max_depth, methods=args.methods)
    if args.wordlist:
        fuzzer_endpoints(args.url, args.wordlist, delay=args.delay, max_depth=args.max_depth, methods=args.methods)
        fuzzer_subdomains(args.url, args.wordlist, delay=args.delay, max_depth=args.max_depth, methods=args.methods)

    # ------------------------
    # Resumen final ordenado
    # ------------------------
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
````

---

## 2. Qué añade respecto al script anterior

|Función/Elemento|Añadido / Mejora|Beneficio|
|---|---|---|
|`get_hash()`|Genera hash MD5 del contenido de cada URL|Evita falsos positivos, no se repiten URLs con mismo contenido|
|`HEADERS`|User-Agent y Accept realistas|Reduce bloqueos por WAF o filtros básicos|
|`delay` y `random.random()`|Tiempo de espera aleatorio entre peticiones|Reduce la posibilidad de detección y bloqueo|
|`recursive` con `max_depth`|Control de profundidad recursiva|Evita ciclos infinitos y controla el alcance del fuzzing|
|`methods`|Soporte para múltiples métodos HTTP|Permite probar GET, HEAD, POST, etc.|
|Logging (`log_file`)|Guardado de resultados con fecha/hora|Permite análisis posterior y comparaciones entre ejecuciones|
|Distinción endpoints / subdominios|Separación clara y recursiva|Mejora la organización y lectura de resultados|

---

## 3. Explicación detallada de cada función

### 3.1 `def_handler()`

Manejo de Ctrl+C para detener el script sin errores.

### 3.2 `get_hash(content)`

Genera hash MD5 del contenido para evitar repetir URLs que devuelven el mismo contenido.

### 3.3 `log_result()` y `print_result()`

Muestran los resultados en pantalla y los escriben en el log.

### 3.4 `fuzzer_endpoints()`

- Prueba todos los endpoints de la wordlist.
    
- Evita repetidos por hash.
    
- Permite recursividad en endpoints con `/`.
    
- Admite múltiples métodos HTTP.
    
- Control de retraso entre peticiones.
    

### 3.5 `fuzzer_subdomains()`

- Construye subdominios desde la wordlist.
    
- Aplica control de duplicados y hash.
    
- Para cada subdominio encontrado, recursivamente prueba endpoints.
    
- Compatible con métodos HTTP y control de retraso.
    

### 3.6 `main()`

- Configura argparse y valida parámetros.
    
- Llama a las funciones según los parámetros indicados (`-e`, `-s`, `-w`).
    
- Al final imprime resumen final ordenado y log.
    

---

## 4. Ejemplo de uso de parámetros

El script admite distintos tipos de fuzzing: endpoints, subdominios, o ambos, y permite ajustar la recursividad, los métodos HTTP y el tiempo entre peticiones para evitar detección por WAF o servidores sensibles.

### Ejemplos prácticos

```bash
# 1. Probar únicamente endpoints
python3 fuzzer_v3.2.py http://objetivo.com -e endpoints.txt
```

- `-e endpoints.txt`: especifica la wordlist de endpoints.
    
- Resultado: solo se prueban rutas dentro del dominio objetivo.
    
- Salida: lista de endpoints detectados con código HTTP.
    

---

```bash
# 2. Probar únicamente subdominios
python3 fuzzer_v3.2.py http://objetivo.com -s subdomains.txt
```

- `-s subdomains.txt`: especifica la wordlist de subdominios.
    
- Resultado: detecta subdominios válidos.
    
- Salida: lista de subdominios con su código HTTP.
    

---

```bash
# 3. Probar endpoints y subdominios usando una wordlist combinada
python3 fuzzer_v3.2.py http://objetivo.com -w combined.txt
```

- `-w combined.txt`: contiene tanto rutas de endpoints como subdominios.
    
- Resultado: realiza fuzzing completo sobre ambos tipos.
    
- Salida: se separa en endpoints y subdominios detectados.
    

---

```bash
# 4. Ajustando tiempo entre peticiones y profundidad recursiva
python3 fuzzer_v3.2.py http://objetivo.com -w combined.txt -t 1.5 --max-depth 3
```

- `-t 1.5`: tiempo en segundos entre cada petición.
    
    - Sirve para **reducir el "ruido"**, evitando bloquearse por el servidor o por WAF.
        
    - Puede usarse un valor decimal, por ejemplo `0.5` para medio segundo o `2` para 2 segundos.
        
- `--max-depth 3`: controla hasta qué nivel se aplica la recursividad.
    
    - Nivel 0: URL inicial
        
    - Nivel 1: endpoints/subdominios encontrados en la URL inicial
        
    - Nivel 2: endpoints/subdominios encontrados en los resultados del nivel 1
        
    - Nivel 3: endpoints/subdominios encontrados en el nivel 2
        
- Resultado: fuzzing más lento y controlado, evitando sobrecargar el servidor.
    

---

```bash
# 5. Usando múltiples métodos HTTP
python3 fuzzer_v3.2.py http://objetivo.com -e endpoints.txt -m GET HEAD POST
```

- `-m GET HEAD POST`: indica los métodos HTTP que se usarán para probar cada URL.
    
    - GET: obtiene el recurso normalmente.
        
    - HEAD: obtiene solo los encabezados (útil para detectar existencia de recursos sin descargar contenido completo).
        
    - POST: permite probar rutas que aceptan datos.
        
- Puede combinar cualquier lista de métodos según la necesidad de pentesting.
    

---

### Resumen de parámetros clave

|Parámetro|Descripción|Ejemplo|
|---|---|---|
|`-e`|Wordlist de endpoints|`-e endpoints.txt`|
|`-s`|Wordlist de subdominios|`-s subdomains.txt`|
|`-w`|Wordlist combinada (endpoints + subdominios)|`-w combined.txt`|
|`-t`|Tiempo entre peticiones en segundos|`-t 1.5`|
|`--max-depth`|Profundidad máxima recursiva|`--max-depth 3`|
|`-m`|Métodos HTTP a usar|`-m GET HEAD POST`|


---

Este script combina **robustez, recursividad y control de ruido**, siendo ideal para pentesting web avanzado, y permite a principiantes entender claramente la lógica de fuzzing de endpoints y subdominios.

---
Resumen final de la evolución
- v2.3: Subdominios opcionales, impresión básica, Ctrl+C seguro.
- v2.4: Añadido -t para retrasos entre requests y evitar detección.
- v2.4-v3: Recursividad, wordlist combinada -w, filtrado de duplicados, resumen final ordenado, soporte completo de endpoints y subdominios.
- v3.2 (prototipo final): Añade control de profundidad, headers realistas, logging a archivo, métodos HTTP adicionales, filtrado avanzado de falsos positivos, modularidad y robustez para pentesting.
- v4 Versión final: añade últimos parámetros de utilidad [Ver Fuzzer parte 4](./Fuzzer_PoC_tutorial_parte_4.md)
