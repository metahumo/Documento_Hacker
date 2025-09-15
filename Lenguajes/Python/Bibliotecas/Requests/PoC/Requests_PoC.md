
---
# PoC — Requests (Python)

---

## Resumen

Pequeña guía práctica (PoC) de la biblioteca **`requests`** orientada a uso en pruebas de seguridad, reconocimiento HTTP y desarrollo rápido de herramientas. Incluye instalación, ejemplos básicos de peticiones (`GET`, `POST`), manejo de sesiones y cookies, control de cabeceras, timeouts y reintentos, subida de ficheros, streaming de respuestas, uso de proxies y TLS, y buenas prácticas para integrar `requests` en flujos de pentesting (enumeración de endpoints, fuzzing ligero, extracción de cabeceras).


---

## Requisitos

- Python 3.8+ (preferible en un entorno virtual)
    
- `pip` actualizado
    
- Conocimientos básicos HTTP (métodos, headers, status codes)
    

Instalación de `requests`:

```bash
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install requests
```

> Nota: para escenarios más avanzados (async / alto rendimiento) considera `httpx` o `aiohttp`, pero `requests` es la opción más simple y estable para PoC y scripting rápido.

---

## 1) Import básico y peticiones simples

`requests` hace que enviar una petición HTTP sea directo:

```python
import requests

resp = requests.get("https://example.com")
print(resp.status_code)     # 200
print(resp.headers.get("Server"))
print(resp.text[:200])      # primeros 200 bytes del body
```

### Cómo extraer programáticamente lo que me interesa

```python
# URL y parámetros
r = requests.get("https://example.com/search", params={"q": "inurl:admin"})
print(r.url)                # URL completa con query string
print(r.status_code)        # Código de estado
print(r.headers["Content-Type"])
if r.headers.get("Content-Type", "").startswith("application/json"):
    data = r.json()         # parse JSON automáticamente
else:
    body = r.text           # contenido como string

# Acceso a cookies
print(r.cookies.get_dict())
```

Usa `.raise_for_status()` para que falle con excepción en códigos >=400 si lo necesitas:

```python
r = requests.get("https://example.com/endpoint")
r.raise_for_status()
```

---

## 2) POST y envío de datos / formularios

```python
# application/x-www-form-urlencoded
data = {"username": "admin", "password": "password"}
r = requests.post("https://target/login", data=data)
print(r.status_code)

# application/json
import json
r = requests.post("https://target/api/login", json={"user":"admin","pw":"pw"})
print(r.json())
```

### Subida de ficheros (multipart/form-data)

```python
files = {"file": ("exploit.txt", open("exploit.txt", "rb"))}
r = requests.post("https://target/upload", files=files)
print(r.status_code, r.text)
```

---

## 3) Sesiones, cookies y persistencia

`requests.Session()` mantiene cookies y ciertas cabeceras entre peticiones, muy útil para flujos de login/uso posterior.

```python
s = requests.Session()
s.headers.update({"User-Agent": "PoC-Scanner/1.0"})
login = s.post("https://target/login", data={"user":"admin","pw":"pw"})
# ahora s mantiene cookies de sesión
resp = s.get("https://target/admin")
print(resp.status_code)
```

---

## 4) Timeouts, reintentos y control de errores

Siempre usar `timeout` (no bloquear scripts). Para reintentos, usa `urllib3.util.retry` con `HTTPAdapter`.

```python
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

session = requests.Session()
retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[429,500,502,503,504])
adapter = HTTPAdapter(max_retries=retries)
session.mount("http://", adapter)
session.mount("https://", adapter)

try:
    r = session.get("https://target", timeout=5)
except requests.Timeout:
    print("Timeout")
except requests.RequestException as e:
    print("Error:", e)
```

---

## 5) Cabeceras personalizadas y manipulación de User-Agent

Modificar cabeceras para evadir filtros simples o simular navegadores:

```python
headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) PoC/1.0",
    "Accept-Language": "en-US,en;q=0.9"
}
r = requests.get("https://target", headers=headers, timeout=4)
```

---

## 6) Proxies, SOCKS y tráfico a través de Tor

Usar proxies (por ejemplo para enrutar tráfico por proxy HTTP/SOCKS o Tor):

```python
proxies = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050"
}
r = requests.get("http://ifconfig.me/ip", proxies=proxies, timeout=5)
print(r.text)
```

> Para SOCKS necesitas instalar `requests[socks]` (`pip install requests[socks]`) y `PySocks`.

---

## 7) TLS/SSL — control de verificación y certificados

Por defecto `requests` verifica TLS. Para entornos de laboratorio con certificados auto-firmados:

```python
# Desactivar verificación (NO recomendado en producción)
r = requests.get("https://intranet.local", verify=False)

# Usar certificado CA personalizado
r = requests.get("https://internal", verify="/ruta/ca_bundle.pem")
```

`verify=False` genera un warning — puedes silenciarlo explícitamente si lo deseas en PoC controlado.

---

## 8) Streaming de respuestas (descarga grande / lectura por chunks)

```python
r = requests.get("https://target/largefile", stream=True, timeout=10)
with open("largefile.bin", "wb") as f:
    for chunk in r.iter_content(chunk_size=4096):
        if chunk:
            f.write(chunk)
```

Útil para manejar respuestas grandes sin agotar memoria.

---

## 9) Autenticación HTTP básica / digest / tokens

```python
# Basic Auth
r = requests.get("https://target/protected", auth=("user","pw"))

# Bearer Token
r = requests.get("https://api.target", headers={"Authorization":"Bearer <TOKEN>"})
```

Para Digest auth usa `requests.auth.HTTPDigestAuth`.

---

## 10) Fuzzing ligero y enumeración de endpoints

Ejemplo básico de enumeración con lista de paths:

```python
paths = ["/admin", "/backup", "/.git/", "/robots.txt"]
for p in paths:
    url = f"https://target{p}"
    r = requests.get(url, timeout=3)
    if r.status_code < 400:
        print(f"[{r.status_code}] {url}")
```

Combina con `Session`, custom headers y reintentos para mayor robustez.

---

## 11) Buenas prácticas y recomendaciones

- **Usa `timeout` siempre** para evitar que tu script se bloquee.
    
- **No uses `verify=False`** en entornos reales; en laboratorios ok.
    
- **Maneja excepciones** (`requests.RequestException`) para mantener la ejecución estable.
    
- **Respeta el objetivo**: solo realizar pruebas en entornos controlados o con autorización.
    
- **Evita paralelizar sin control**: para muchos requests usa `ThreadPoolExecutor` o `async` con `httpx` para eficiencia.
    
- **Registrar y auditar**: guarda respuestas y encabezados relevantes (sin almacenar datos sensibles sin control).
    
- **Rate limiting**: introduce delays/backoff para no saturar servicios o activar WAFs innecesarios.
    

---

## 12) Fragmentos útiles (cheat-sheet)

- GET con params: `requests.get(url, params={"q":"test"})`
    
- POST JSON: `requests.post(url, json={"k":"v"})`
    
- Subida archivo: `requests.post(url, files={"f": open("a","rb")})`
    
- Sesión: `s = requests.Session(); s.get(...)`
    
- Timeout: `requests.get(url, timeout=5)`
    
- Reintentos: `HTTPAdapter + Retry` (ver arriba)
    
- Proxies SOCKS: `proxies={"http":"socks5h://127.0.0.1:9050"}`
    

---

## Recursos y enlaces rápidos

- Documentación oficial: [https://docs.python-requests.org/](https://docs.python-requests.org/)
    
- Ejemplos y adapters: `requests.adapters`, `urllib3.util.retry`
    
- Para async / performance: investigar `httpx` o `aiohttp` cuando se necesite concurrencia real.
    

---

## Ejemplo PoC completo — reconocimiento básico con `requests`

```python
#!/usr/bin/env python3
import requests, sys
from concurrent.futures import ThreadPoolExecutor

target = "https://target"
paths = ["/", "/admin", "/login", "/robots.txt", "/.git/"]

def probe(path):
    url = target.rstrip("/") + path
    try:
        r = requests.get(url, timeout=4, allow_redirects=True)
        if r.status_code < 400:
            print(f"[{r.status_code}] {url} - {len(r.text)} bytes - {r.headers.get('Server')}")
    except requests.RequestException:
        pass  # PoC: ignoramos errores para salida limpia

if __name__ == "__main__":
    with ThreadPoolExecutor(max_workers=10) as ex:
        ex.map(probe, paths)
```

Este mini PoC hace una enumeración ligera de endpoints, reportando solo respuestas con status < 400 y mostrando longitud y header `Server`. Es perfecto como paso inicial en un pipeline de reconocimiento HTTP.

---
