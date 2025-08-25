
---

# FFUF: Fuzzing rápido para directorios, parámetros y más

> **FFUF** (Fuzz Faster U Fool) es una herramienta rápida y versátil que utilizamos para realizar fuzzing de directorios, subdominios, parámetros, y mucho más. Es especialmente útil cuando queremos descubrir recursos ocultos en aplicaciones web.

---

## Uso básico: Enumeración de directorios

Realizamos fuzzing sobre rutas para descubrir directorios o archivos escondidos.

```bash
ffuf -u http://10.10.10.10/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
````

- `-u`: URL objetivo. Usamos la palabra clave `FUZZ` para indicar el punto de inyección.
    
- `-w`: diccionario con palabras para probar.
    

Podemos añadir:

- `-e`: extensiones como `.php`, `.html`, etc.
    
- `-fc`: filtra códigos HTTP (por ejemplo, filtrar los 404).
    
- `-mc`: muestra solo códigos HTTP concretos.
    
- `-t`: número de hilos.
    

---

## Fuzzing de archivos con extensiones

```bash
ffuf -u http://target.com/FUZZ -w files.txt -e .php,.html,.bak
```

Esto probará rutas como:

- `/admin.php`
    
- `/admin.html`
    
- `/admin.bak`
    

---

## Fuzzing de subdominios

Para esto modificamos la cabecera `Host` como en Wfuzz:

```bash
ffuf -u http://example.com -H "Host: FUZZ.example.com" -w subdomains.txt -fs 4242
```

- `-H`: modificamos la cabecera `Host`.
    
- `-fs`: filtra por tamaño de respuesta (por ejemplo, si todos los errores devuelven 4242 bytes).
    

---

## Fuzzing de parámetros GET

```bash
ffuf -u http://example.com/page.php?param=FUZZ -w payloads.txt
```

Podemos usar esto para detectar parámetros vulnerables a inyecciones o para forzar rutas ocultas.

---

## Fuzzing de parámetros POST

```bash
ffuf -X POST -d "username=admin&password=FUZZ" -u http://example.com/login.php -w passwords.txt -H "Content-Type: application/x-www-form-urlencoded"
```

Este comando prueba diferentes contraseñas para el usuario "admin" por POST.

---

## Filtros y opciones útiles

- `-mc 200,403`: muestra solo respuestas con códigos 200 o 403.
    
- `-fc 404`: filtra las respuestas con código 404.
    
- `-fs 1024`: filtra por tamaño de respuesta (bytes).
    
- `-fw 30`: filtra por número de palabras.
    
- `-fl 12`: filtra por número de líneas.
    

---

## Ejemplo práctico completo

```bash
ffuf -u http://192.168.1.100/FUZZ -w common.txt -e .php,.txt -mc 200,403 -t 40 -o resultado.txt
```

- Atacamos un servidor en `192.168.1.100`.
    
- Usamos el diccionario `common.txt`.
    
- Buscamos archivos `.php` y `.txt`.
    
- Mostramos solo respuestas 200 y 403.
    
- Usamos 40 hilos.
    
- Guardamos el resultado en `resultado.txt`.
    

---

## Preguntas clave

- ¿Cuándo usamos `-e`?
    
    - Cuando sospechamos que los archivos tienen extensiones específicas.
        
- ¿Cómo eliminamos respuestas irrelevantes?
    
    - Con `-fc`, `-fs`, `-fw`, etc.
        
- ¿Cómo forzamos fuzzing sobre parámetros?
    
    - Usando `FUZZ` en la URL o en el cuerpo con `-d`.
        

---

## Recomendaciones

- Siempre observar el tamaño de respuestas (con `-v`) para identificar patrones.
    
- Comparar con herramientas como Gobuster o Dirsearch.
    
- Automatizar fuzzing con `ffuf` en scripts para grandes superficies de ataque.
    

---

