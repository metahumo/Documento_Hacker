
---

# Gobuster: Fuerza Bruta para Rutas, Subdominios y más

> Gobuster es una herramienta que utilizamos para realizar ataques de fuerza bruta contra rutas web, subdominios, directorios virtuales, archivos y otros recursos ocultos que pueden estar disponibles en un servidor.

Nos resulta especialmente útil en fases de reconocimiento y enumeración durante un pentest. Como esta escrita en lenguaje de programación *Go*, funciona muy bien con *Sockets* y *conexiones*. 

---

## Modos de Uso

### 1. Enumeración de Directorios y Archivos Web

Para este uso, atacamos un servidor web buscando rutas comunes (por ejemplo: `/admin`, `/backup`, `/robots.txt`).

```bash
gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html
````

- `dir`: indica que queremos buscar directorios o archivos.
    
- `-u`: URL del objetivo.
    
- `-w`: diccionario a utilizar.
    
- `-x`: extensiones de archivo que queremos probar.
    

También podemos añadir:

- `-t`: número de hilos.
    
- `-k`: para ignorar errores de certificado SSL (en caso de HTTPS).
    
- `-o`: para guardar el resultado en un archivo.
    

### 2. Enumeración de Subdominios

Para descubrir subdominios, utilizamos el modo `dns`.

```bash
gobuster dns -d example.com -w subdomains.txt -t 50
```

- `dns`: modo de enumeración de DNS.
    
- `-d`: dominio objetivo.
    
- `-w`: diccionario con posibles subdominios.
    
- `-t`: número de hilos.
    

Este ataque intenta resolver subdominios como `admin.example.com`, `test.example.com`, etc.

### 3. Enumeración de Buckets S3

Podemos usar Gobuster para buscar buckets de Amazon S3 que podrían estar mal configurados:

```bash
gobuster s3 -w wordlist.txt
```

- `s3`: modo específico para fuzzing de buckets.
    

---

## Filtros y Opciones Avanzadas

Al igual que en otras herramientas de fuerza bruta, también podemos filtrar las respuestas para mejorar la visibilidad:

- `-s 200,204,301,302,307,403`: muestra solo respuestas con códigos específicos.
    
- `--wildcard`: detecta y ajusta cuando el servidor responde igual a cualquier petición (wildcard DNS).
    
- `-r`: no sigue redirecciones.
    

---

## Ejemplo Práctico

```bash
gobuster dir -u http://192.168.1.100 -w common.txt -x php,txt -s 200,204,301,302 -t 20
```

En este caso:

- Atacamos un servidor HTTP en `192.168.1.100`.
    
- Usamos el diccionario `common.txt`.
    
- Buscamos archivos `.php` y `.txt`.
    
- Mostramos solo respuestas relevantes (`200`, `204`, `301`, `302`).
    
- Utilizamos 20 hilos para acelerar el escaneo.
    

---

## Preguntas clave

- ¿Cuándo usamos `-x`?
    
    - Cuando sospechamos que los archivos están ocultos bajo extensiones específicas.
        
- ¿Qué modo usamos para subdominios?
    
    - Usamos `dns`.
        
- ¿Cómo evitamos ruido en los resultados?
    
    - Usamos `-s` para filtrar por códigos HTTP relevantes y `--wildcard` si es necesario.
        

---

## Recomendaciones

- Usar diccionarios relevantes al contexto (por ejemplo, `big.txt`, `common.txt`, `apache-user-enum.txt`).
    
- Comparar con los resultados de otras herramientas como FFUF o Dirsearch para validar hallazgos.
    
- No fiarnos solo de respuestas `404`, ya que algunos servidores devuelven `200 OK` falsos.
    

---
