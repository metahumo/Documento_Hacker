# Unión de registros entre dos tablas en MySQL (employees & departments)

## Objetivo

Conectarse a una base de datos remota mediante el cliente `mysql` y encontrar el **número total de registros** resultantes al realizar una **UNIÓN** entre las tablas `employees` y `departments`.

**Nota:** más información en [[UNION SELECT]]

---

## Paso 1: Conexión al servidor remoto

Nos conectamos con la herramienta `mysql` usando los siguientes parámetros:

```bash
mysql -h 94.237.55.96 -P 33524 -u root -p
````

- `-h`: Dirección IP del servidor MySQL.
    
- `-P`: Puerto utilizado por el servicio MySQL.
    
- `-u`: Nombre de usuario (`root`).
    
- `-p`: Solicita la contraseña (se introduce después).
    

---

## Paso 2: Exploración inicial

Una vez conectados, listamos las bases de datos disponibles:

```sql
SHOW DATABASES;
```

Resultado (resumen):

- `employees`
    
- `mysql`
    
- `information_schema`
    
- `performance_schema`
    
- `sys`
    

Seleccionamos la base de datos `employees`:

```sql
USE employees;
```

---

## Paso 3: Ver tablas disponibles

Dentro de la base de datos:

```sql
SHOW TABLES;
```

Resultado:

- `employees`
    
- `departments`
    
- `dept_emp`
    
- `dept_manager`
    
- `salaries`
    
- (entre otras)
    

---

## Paso 4: Inspeccionar estructura de las tablas

### Tabla `employees`:

```sql
DESCRIBE employees;
```

|Campo|Tipo|
|---|---|
|emp_no|int(11)|
|birth_date|date|
|first_name|varchar(14)|
|last_name|varchar(16)|
|gender|enum('M','F')|
|hire_date|date|

---

### Tabla `departments`:

```sql
DESCRIBE departments;
```

|Campo|Tipo|
|---|---|
|dept_no|char(4)|
|dept_name|varchar(40)|

---

## Paso 5: Realizar la unión

Ya que ambas tablas tienen columnas diferentes, pero podemos seleccionar columnas compatibles para realizar una unión. Elegimos:

- `emp_no` (de `employees`)
    
- `dept_no` (de `departments`)
    

Ambos representan identificadores únicos (aunque de tipo diferente: `int` vs `char`). Como MySQL permite conversiones implícitas, podemos realizar la unión sin problemas.

### Consulta final:

```sql
SELECT COUNT(*) FROM (
  SELECT emp_no FROM employees
  UNION
  SELECT dept_no FROM departments
) AS total_union;
```

> **Nota:** `UNION` elimina duplicados por defecto.

---

## Resultado

```text
+----------+
| COUNT(*) |
+----------+
|      663 |
+----------+
```

---

## Explicación

- `UNION` combina los resultados de dos consultas y elimina los duplicados automáticamente.
    
- Al seleccionar sólo una columna (`emp_no` y `dept_no`), nos aseguramos de que la estructura sea válida para la unión.
    
- En este caso, el total de registros combinados **sin duplicados** es **663**.
    

---

## Alternativa: Usar UNION ALL

Si quieres contar todos los registros sin eliminar duplicados:

```sql
SELECT COUNT(*) FROM (
  SELECT emp_no FROM employees
  UNION ALL
  SELECT dept_no FROM departments
) AS total_union;
```

Esto te dará el total exacto de filas unidas, sin filtrado.

---

## Conclusión

Este ejercicio demuestra cómo realizar una unión entre dos tablas diferentes usando columnas compatibles, incluso si tienen distintos tipos de datos, y cómo contar los registros resultantes usando funciones de agregación como `COUNT(*)`.

---
