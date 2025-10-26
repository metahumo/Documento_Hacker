
---
# PoC — `requests_get.py`

---

## Resumen

Pequeña guía práctica (PoC) que muestra el uso básico de la biblioteca **`requests`** para realizar una petición **GET** con parámetros (`params`) y cómo leer la URL final y el cuerpo de la respuesta. Es útil para entender cómo `requests` construye la query string, cómo inspeccionar la respuesta (texto/JSON) y cómo usar esta técnica en tareas de reconocimiento HTTP y automatización.

---

## Requisitos

- Python 3.8+
    
- `pip` y paquete `requests`
    

Instalación rápida:

```bash
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install requests
```

---

## Script: `requests_get.py`

```python
#!/usr/bin/env python3

import requests

values = {'value1': 'test_a', 'value2': 'test_b', 'value3': 'test_c'}

response = requests.get("https://httpbin.org/get", params=values)

print(f"\n[+] URL final: {response.url}\n")
print(response.text)
```


---

## ¿Qué hace el script? — Paso a paso

1. `import requests`  
    Importa la librería `requests` para realizar peticiones HTTP de forma sencilla.
    
2. `values = {...}`  
    Define un diccionario con pares clave/valor que se convertirán en los parámetros de la query string (GET).
    
3. `response = requests.get("https://httpbin.org/get", params=values)`  
    Envía una petición GET a `https://httpbin.org/get`. `requests` se encarga de serializar `params` en la URL final:
    
    ```
    https://httpbin.org/get?value1=test_a&value2=test_b&value3=test_c
    ```
    
4. `print(f"\n[+] URL final: {response.url}\n")`  
    Muestra la URL exacta que se ha solicitado (útil para verificar cómo se codifican parámetros).
    
5. `print(response.text)`  
    Imprime el cuerpo de la respuesta como texto (en este caso JSON formateado por httpbin).
    

---

## Ejecución y salida de ejemplo

Comando usado:

```bash
python3 requests_get.py
[sudo] contraseña para metahumo:
```

Salida producida (tal y como la mostraste):

```
[+] URL final: https://httpbin.org/get?value1=test_a&value2=test_b&value3=test_c

{
  "args": {
    "value1": "test_a", 
    "value2": "test_b", 
    "value3": "test_c"
  }, 
  "headers": {
    "Accept": "*/*", 
    "Accept-Encoding": "gzip, deflate, br", 
    "Host": "httpbin.org", 
    "User-Agent": "python-requests/2.28.1", 
    "X-Amzn-Trace-Id": "Root=1-68c7da65-7fd58fe75e0dae2f1efb7545"
  }, 
  "origin": "<IP_Pública>", 
  "url": "https://httpbin.org/get?value1=test_a&value2=test_b&value3=test_c"
}
```

### Interpretación rápida de la salida

- `"args"`: parámetros que el servidor recibió en la query string (coinciden con `values`).
    
- `"headers"`: cabeceras que `requests` envió (por defecto incluye `User-Agent: python-requests/...`).
    
- `"origin"`: IP pública desde la que httpbin recibió la petición.
    
- `"url"`: URL completa con query string — confirma exactamente lo que se solicitó.
    

---

## Uso práctico en ciberseguridad ofensiva / reconocimiento HTTP

- **Enumeración de parámetros**: útil para comprobar endpoints que aceptan parámetros y ver respuestas del servidor.
    
- **Fingerprinting de aplicaciones**: `headers` y `Server` (cuando exista) ayudan a identificar tecnología y versiones.
    
- **Automatización de queries**: insertar listas de parámetros para detectar endpoints, parámetros vulnerables o comportamiento distinto según valores.
    
- **Pruebas de comportamiento**: comparar respuestas (status, longitud, JSON) con distintos inputs para detectar rutas, errores o filtrado.
    

---

## Mejoras recomendadas (PoC más robusto)

1. **Corregir el shebang**:
    
    ```bash
    #!/usr/bin/env python3
    ```
    
2. **Comprobar y parsear JSON de forma segura**:
    
    ```python
    try:
        data = response.json()
        # trabajar con data['args']...
    except ValueError:
        print("Respuesta no es JSON")
    ```
    
3. **Agregar timeout y manejo de excepciones**:
    
    ```python
    try:
        r = requests.get(url, params=values, timeout=5)
        r.raise_for_status()
    except requests.RequestException as e:
        print("Error:", e)
    ```
    
4. **Personalizar cabeceras (User-Agent, Accept, etc.)**:
    
    ```python
    headers = {"User-Agent": "PoC-Requests/1.0"}
    r = requests.get(url, params=values, headers=headers)
    ```
    
5. **Usar `Session` para realizar múltiples peticiones con persistencia de cookies**:
    
    ```python
    s = requests.Session()
    s.headers.update({"User-Agent": "PoC/1.0"})
    s.get("https://example.com", params=values)
    ```
    
6. **Imprimir salida limpia / JSON formateado**:
    
    ```python
    import json
    print(json.dumps(response.json(), indent=2))
    ```
    

---

## PoC extendido — ejemplo mejorado

Ejemplo breve que incluye timeout, parseo JSON y salida formateada:

```python
#!/usr/bin/env python3
import requests, json

values = {'value1': 'test_a', 'value2': 'test_b', 'value3': 'test_c'}
try:
    r = requests.get("https://httpbin.org/get", params=values, timeout=5)
    r.raise_for_status()
    print(f"[+] URL final: {r.url}\n")
    print(json.dumps(r.json(), indent=2))
except requests.RequestException as e:
    print("[!] Error en la petición:", e)
```

---

## Buenas prácticas / seguridad

- Usa `timeout` para evitar bloqueos de scripts.
    
- No uses `verify=False` salvo en entornos controlados (evita validar TLS).
    
- Maneja excepciones para no dejar el PoC silencioso ante errores de red.
    
- Registra resultados (JSON/CSV) si vas a automatizar y procesar grandes volúmenes de respuestas.
    
- Respeta la legalidad y sólo prueba sobre objetivos autorizados o entornos de laboratorio.
    

---

## Recursos rápidos

- Documentación `requests`: [https://docs.python-requests.org/](https://docs.python-requests.org/)
    
- `httpbin.org` es excelente para probar y visualizar peticiones/encabezados/respuestas.
    

---

En resumen: este PoC demuestra cómo `requests` construye la URL final a partir de `params`, cómo se ve la respuesta JSON devuelta por `httpbin`, y cuáles son las mejoras típicas para convertir este ejemplo en una utilidad más robusta para reconocimiento HTTP.

---
