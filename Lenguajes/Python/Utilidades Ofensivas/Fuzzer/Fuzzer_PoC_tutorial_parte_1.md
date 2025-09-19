
---
# Fuzzer_PoC_tutorial 1

## Evolución del Fuzzer en Python

A lo largo de las diferentes versiones, hemos construido un fuzzer básico que permite probar endpoints de un servidor web usando una wordlist. Cada versión agrega funcionalidades mínimas para que un principiante pueda entender paso a paso cómo se desarrolla la herramienta.

---

### Primer script: fuzzer_v1.1.py — Petición básica con input()

```python
#!/usr/bin/env python3
import requests

url = input(f"\n[+] Introduzca URL: ")

resp = requests.get(url, timeout=2)
print(resp)
print(f"Codigo de respuesta: {resp.status_code}")
```

**¿Qué hace?**

- Pide al usuario la URL objetivo mediante `input()`.
    
- Realiza una petición HTTP GET básica con `requests.get()`.
    
- Muestra el objeto `Response` y el código HTTP.
    

**Por qué es útil:**

- Base mínima para entender cómo hacer peticiones HTTP en Python.
    
- Permite probar una URL sin parámetros adicionales.
    

---

### Segundo script: fuzzer_v1.2.py — Uso de argparse y función

```python
#!/usr/bin/env python3
import requests
import argparse

def fuzzer(url):
    resp = requests.get(url, timeout=2)
    print(resp)
    print(f"Codigo de respuesta: {resp.status_code}")   

def main():
    parser = argparse.ArgumentParser(description="Fuzzer v2")
    parser.add_argument("url", help="URL ojetivo, ej: http://ejemplo")
    args = parser.parse_args()
    
    fuzzer(args.url)

if __name__ == '__main__':
    main()
```

**¿Qué añade respecto a v1.1?**

- Introduce `argparse` para pasar la URL como argumento de línea de comandos.
    
- Organiza la lógica en una función `fuzzer(url)` para futuras extensiones.
    

**Por qué es útil:**

- Evita depender de `input()` y permite automatizar ejecuciones.
    
- Sienta la base para añadir más parámetros (como wordlists).
    

---

### Tercer script: fuzzer_v1.3.py — Wordlist y validación de archivo

```python
#!/usr/bin/env python3
import requests
import argparse
import os

def fuzzer(url, wordlist):
    if not os.path.isfile(wordlist):
        print(f"[!] No se ha encontrado la Wordlist: {wordlist}")
        return

    with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            endpoint = line.strip()
            if not endpoint:
                continue

            full_url = f"{url.rstrip('/')}/{endpoint.lstrip('/')}"
            print(f"[+] Probando: {full_url}")

            try:
                r = requests.get(full_url, timeout=5)
                print(f"[{r.status_code}] {full_url}")
            except requests.RequestException as e:
                print(f"[ERROR] {full_url} -> {e}")

def main():
    parser = argparse.ArgumentParser(description="Fuzzer v3 - añade wordlist")
    parser.add_argument("url", help="URL objetivo, ej: http://example.com")
    parser.add_argument("-w", "--wordlist", dest="wordlist", help="Archivo con endpoints", required=True)
    args = parser.parse_args()

    fuzzer(args.url, args.wordlist)

if __name__ == '__main__':
    main()
```

**¿Qué añade respecto a v1.2?**

- Permite pasar un archivo de endpoints (`wordlist`) mediante `-w/--wordlist`.
    
- Valida que el archivo exista antes de iterar.
    
- Itera sobre cada línea de la wordlist y construye la URL completa.
    
- Maneja errores de conexión con `try/except`.
    

**Por qué es útil:**

- Permite probar múltiples endpoints automáticamente.
    
- Enseña cómo abrir y validar archivos en Python.
    

---

### Cuarta versión: fuzzer_v1.4.py — Descriptor de archivo y limpieza de líneas

```python
#!/usr/bin/env python3
import requests
import argparse
import os

def fuzzer(url, wordlist):
    if not os.path.isfile(wordlist):
        print(f"[!] No se ha encontrado la Wordlist: {wordlist}")
        return

    with open(wordlist, "r") as f:
        for line in f:
            endpoint = line.strip()  # Quita saltos de línea y espacios

            if not endpoint:
                continue

            full_url = f"{url.rstrip('/')}/{endpoint.lstrip('/')}"
            print(f"[+] Probando: {full_url}")

            try:
                r = requests.get(full_url, timeout=2)
                print(f"[{r.status_code}] {full_url}")
            except requests.RequestException as e:
                print(f"[ERROR] {full_url} -> {e}")

def main():
    parser = argparse.ArgumentParser(description="Fuzzer v4")
    parser.add_argument("url", help="URL objetivo, ej: http://ejemplo")
    parser.add_argument("-w", "--wordlist", dest="wordlist", help="Archivo con endpoints", required=True)
    args = parser.parse_args()

    fuzzer(args.url, args.wordlist)

if __name__ == '__main__':
    main()
```

**¿Qué añade respecto a v1.3?**

- Usa `line.strip()` para eliminar saltos de línea y espacios al leer cada endpoint.
    
- Mantiene el descriptor de archivo `f` abierto con `with`, mostrando buenas prácticas de manejo de archivos.
    

**Por qué es útil:**

- Evita errores de URLs mal construidas que devolvían 404.
    
- Enseña cómo trabajar correctamente con archivos y limpiar entradas.
    

---

## Nota sobre filtrado de salida

Cuando se ejecuta el fuzzer con una wordlist, muchas URLs pueden devolver códigos de estado HTTP 404 o simplemente indicar que están siendo probadas. Para centrarnos únicamente en los endpoints “válidos” o interesantes, se recomienda **parsear la salida usando `grep`**.

Por ejemplo, ejecutando:

```bash
python3 fuzzer_v4.py http://192.168.1.77 -w endpoints.txt | grep -vE "404|Probando"
````

Podemos filtrar la salida y obtener únicamente los endpoints que devuelven códigos útiles. Con la wordlist `fuzzing.txt`, la salida real sería algo como:

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

Explicación:

- `grep -v` → invierte la selección, mostrando solo las líneas que **no coinciden** con el patrón.
    
- `-E` → permite usar **expresiones regulares extendidas**.
    
- `"404|Probando"` → excluye cualquier línea que contenga `"404"` **o** `"Probando"`.
    

Con este método, la salida se limita a endpoints que devuelven códigos útiles como **200, 301, 403, etc.**, simplificando el análisis y permitiendo identificar rápidamente recursos accesibles en el servidor.

> Nota: Esta técnica es útil para pruebas rápidas desde línea de comandos y puede integrarse en scripts más avanzados para procesamiento automático.


---

### Conclusión de la evolución

1. **v1**: prueba básica de una URL introducida manualmente.
    
2. **v2**: añade `argparse` y encapsula la lógica en una función.
    
3. **v3**: soporte de wordlist, validación de archivo y manejo de errores.
    
4. **v4**: limpieza de líneas y uso correcto del descriptor de archivo.
    

Este flujo nos deja con un **prototipo funcional** de fuzzer que puede ser extendido en el futuro para:

- Reconocimiento de subdominios.
    
- Concurrencia para acelerar fuzzing.
    
- Manejo avanzado de respuestas HTTP y filtros.
    

---

[Ver Fuzzer parte 2](./Fuzzer_PoC_tutorial_parte_2.md)
