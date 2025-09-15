
---

# PoC: Sondeo básico HTTP con `requests` y ThreadPoolExecutor

## Introducción

En este PoC mostramos un script sencillo en Python que realiza un sondeo (probe) de varias rutas HTTP de un objetivo usando la librería `requests` y ejecución concurrente con `concurrent.futures.ThreadPoolExecutor`.

El objetivo pedagógico es entender cómo construir peticiones HTTP automatizadas, procesar respuestas, y paralelizar tareas para acelerar reconocimiento web. Usamos un ejemplo reducido y seguro para aprendizaje; **solo** lo ejecutamos contra objetivos que tenemos permiso de probar.

## Código (requests_basic.py)

```python
#!/usr/bin/env python3
import requests, sys
from concurrent.futures import ThreadPoolExecutor

target = "https://github.com/metahumo"
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

## Paso a paso

### Importación de módulos

- `requests`: librería HTTP de alto nivel que facilita realizar `GET`, `POST`, etc.
    
- `sys`: importado aunque en este PoC no lo usamos (queda para extensiones como argumentos CLI).
    
- `ThreadPoolExecutor` desde `concurrent.futures`: nos permite ejecutar las sondas en paralelo con un pool de hilos.
    

### Definición del objetivo y rutas

- `target` contiene la URL base del objetivo. En el ejemplo es `https://github.com/metahumo`.
    
- `paths` es una lista de rutas comunes que nos interesa comprobar: raíz, `/admin`, `/login`, `/robots.txt` y `/.git/`.
    

### Construcción de la URL

```python
url = target.rstrip("/") + path
```

- `rstrip("/")` evita `//` accidental cuando concatenamos.
    
- Concatenamos la ruta para formar la URL completa a consultar.
    

### Envío de la petición y manejo de la respuesta

```python
r = requests.get(url, timeout=4, allow_redirects=True)
if r.status_code < 400:
    print(...)
```

- `timeout=4` limita el tiempo de espera a 4 segundos por petición para no bloquear indefinidamente.
    
- `allow_redirects=True` sigue redirecciones 3xx (útil cuando la ruta redirige a otra URL).
    
- Comprobamos `r.status_code < 400` para filtrar respuestas exitosas (2xx/3xx) y evitar imprimir errores 4xx/5xx.
    
- Mostramos: código HTTP, URL, tamaño del cuerpo (`len(r.text)`) y la cabecera `Server` si existe.
    

### Manejo de errores

- Capturamos `requests.RequestException` y la ignoramos (`pass`) para mantener la salida limpia en este PoC.
    
- En un entorno real de pruebas conviene registrar o contar los fallos para diagnóstico.
    

### Concurrencia: acelerar sondeos

```python
with ThreadPoolExecutor(max_workers=10) as ex:
    ex.map(probe, paths)
```

- Creamos un pool de hasta 10 hilos para ejecutar `probe` sobre cada ruta.
    
- `ex.map` aplica `probe` a cada elemento de `paths` de forma concurrente.
    
- Esto reduce el tiempo total frente a ejecutar las peticiones de manera secuencial.
    

## Ejecución del PoC

Ejecutamos el script con Python 3:

```
python3 requests_basic.py
```

Salida de ejemplo (del entorno donde se probó):

```
[200] https://github.com/metahumo/ - 176422 bytes - github.com
```

Interpretación: recibimos código `200` en la raíz del objetivo, la respuesta tiene ~176 KB y la cabecera `Server` indica `github.com`.

## Importancia en ciberseguridad ofensiva

- **Reconocimiento web básico**: este tipo de sondas nos permite detectar páginas y rutas interesantes (p. ej. `/admin`, `/.git/`) que pueden contener información o vectores de explotación.
    
- **Enumeración rápida**: combinar una lista de rutas más amplia con concurrencia acelera la fase de reconocimiento.
    
- **Información útil**: tamaño de respuesta y cabeceras (como `Server`) ayudan a identificar tecnologías y posibles puntos de interés.
    

## Riesgos y consideraciones legales

- No ejecutamos este PoC contra objetivos sin permiso explícito. El escaneo y reconocimiento sin autorización puede ser ilegal.
    
- Ajustar la velocidad (concurrency y timeouts) para evitar impactar negativamente al objetivo y para reducir detectabilidad por IDS.
    
- Respetar la política del cliente o del entorno de pruebas y registrar permisos por escrito.
    

## Mejoras y extensiones sugeridas

1. **Argumentos CLI**: usar `argparse` para pasar `target`, `paths` (o un archivo de wordlist) y `max_workers` desde la línea de comandos.
    
2. **Registro y métricas**: guardar resultados en CSV/JSON y contar códigos HTTP, tiempos de respuesta y errores.
    
3. **Detección de contenido real**: comprobar cabeceras `Content-Type`, buscar firmas en el cuerpo (p. ej. paneles de administración) y diferenciar respuestas vacías.
    
4. **Fuzzing de rutas**: integrar con wordlists más grandes (ej. `common.txt`) y controlar la velocidad para no saturar.
    
5. **Paralelismo avanzado**: usar `asyncio` + `httpx` para un cliente asíncrono más ligero que hilos para miles de peticiones.
    
6. **Manejo de redirecciones y normalización**: analizar destinos de redirección y normalizar URLs para evitar duplicados.
    

## Conclusión

Este PoC nos permite entender de forma práctica cómo automatizar sondas HTTP básicas y cómo paralelizarlas para reconocimiento. Es una pieza útil en la fase de enumeración durante pruebas de ciberseguridad ofensiva, siempre que la ejecutemos con autorización y buenas prácticas.

---
