
---
# Uso de `urllib.parse` para manipulación de URLs en Python

En Python, la biblioteca estándar `urllib.parse` permite descomponer y analizar URLs de manera sencilla. Esto es especialmente útil en herramientas de **fuzzing**, **scraping** o cuando queremos probar subdominios de un dominio base.

## 1. Importación de la librería

```python
from urllib.parse import urlparse
````

## 2. Descomposición de una URL

La función `urlparse(url)` divide la URL en sus componentes principales:

- `scheme`: protocolo (http, https)
    
- `netloc`: dominio y puerto
    
- `path`: ruta dentro del dominio
    
- `params`, `query`, `fragment`: otros elementos opcionales
    

### Ejemplo:

```python
url = "http://sub.example.com:8080/path/to/page"
parsed = urlparse(url)

print(parsed.scheme)  # http
print(parsed.netloc)  # sub.example.com:8080
print(parsed.path)    # /path/to/page
```

## 3. Extracción del dominio para subdominios

En fuzzers que prueban subdominios, necesitamos separar el dominio base para concatenar los subdominios:

```python
base_url = "http://example.com"
parsed = urlparse(base_url)
domain = parsed.netloc  # example.com

subdomain = "admin"
subdomain_url = f"{parsed.scheme}://{subdomain}.{domain}"
print(subdomain_url)  # http://admin.example.com
```

Esto permite probar múltiples subdominios de forma automática.

## 4. Uso en un fuzzer de subdominios

En un script de fuzzing, se puede recorrer una wordlist de subdominios:

```python
subdomains_list = ["admin", "test", "dev"]
for sub in subdomains_list:
    subdomain_url = f"{parsed.scheme}://{sub}.{domain}"
    # aquí se haría requests.get(subdomain_url)
```

### Beneficio

- Permite separar el **dominio base** del protocolo y la ruta.
    
- Facilita la creación dinámica de URLs de subdominios.
    
- Evita errores de concatenación al manejar correctamente `http://` y `/`.
    

---
