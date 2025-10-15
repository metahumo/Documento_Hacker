
---
# Extracción de cookies con HttpOnly true

En algunos escenarios nos encontramos con un XSS reflejado que muestra en pantalla el resultado de `document.cookie`. Eso solo nos da las cookies cuyo atributo `HttpOnly` está en `false`. No obstante, existen malas prácticas y ciertas configuraciones que hacen que información de sesión —que debería estar protegida— esté accesible por otros medios, por ejemplo en `localStorage`, en la renderización del código fuente, en el archivo `phpinfo.php`, etc.. 


---

## Local Storage

> `localStorage` es un almacenamiento clave/valor en el navegador que persiste entre sesiones. No tiene el atributo `HttpOnly`: cualquier script que se ejecute en el contexto de la página puede leerlo. Por eso almacenar tokens de sesión o identificadores sensibles en `localStorage` es una práctica de riesgo cuando la aplicación puede ser vulnerable a XSS.


---

### ¿Qué buscar?

- Claves que contengan `token`, `session`, `auth`, `permutive-id`, `permutive-app`, `sharedId`, `session_id`, etc.
    
- Valores que sean JWT, UUIDs, o JSON con campos `user_id`, `session_id`, `access_token`.
    
- Entradas grandes (objetos JSON) que incluyan `eventPublication`, `user_id`, `segments`, `cohorts` (como en SDKs de analítica/segmentación).


---

### Cómo inspeccionar `localStorage` de forma segura (DevTools)

1. Abrimos DevTools → **Application / Storage** → **Local Storage** para ver claves y valores.
    
2. En **Console**, los comandos más útiles para auditoría son:

```console
localStorage
localStorage.<etiqueta>
localStorage["<etiqueta>"]
```


---

### XSS - `localStorage`

Podemos trasladar esto a código JavaScript de la siguiente forma:

```js
<script>alert(localStorage.<etiqueta>)</script>
```

A veces es necesario generar un delay o retraso en la ejecución del script, ya que este normalmente se ejecuta antes que la página procese el contenido y por tanto las cookies. Para generar un pequeño retraso en el código JavaScript hacemos lo siguiente:

```js
<script>setTimeout(()=>alert(localStorage),5000)</script>
```

```js
<script>setTimeout(()=>alert(localStorage.getItem('<etiqueta>')),5000)</script>
```

```js
<script>setTimeout(()=>alert(localStorage.getItem('<etiqueta>')||'no_localStorage'),5000)</script>
```

```js
<script>setTimeout(()=>console.log(localStorage.getItem('<etiqeuta>') || 'no_localStorage'),5000);</script>
```

Este payload se ejecutará trascurrido 5 segundos ( `setTimeout(), 5000`). El segundo payload hace lo mismo, solo que en caso de no encontrar contenido en la ruta de Almacenamiento Local mostrará en la ventana emergente que se ejecutará pasado 5 segundos un mensaje de ' no_localStorage'


---

## Código fuente


En ocasiones, una mala configuración por parte de los desarrolladores, puede hacer que las cookies se rendericen en alguna página web asociada al servidor. Esto puede hacer que mediante código JavaScript podamos acceder a cookies que están bajo el control de `HttpOnly true` pero se muestran por ejemplo en el código fuente de la página web.

Primero hacemos comprobaciones desde la página web en la que estamos logueados y tenemos nuestras propias cookies. Entonces vamos a DevTools y en Storage copiamos la parte final o toda la cookie si se prefiere, para posteriormente buscarla con `ctrl+f` en el código fuente de la página web. Si encontramos una coincidencia quiere decir que se esta renderizando las cookies en la página web y es algo a lo que podemos acceder con código JavaScript.

Una vez sabemos el valor en el que se almacena la cookie, podemos usar el siguiente código para obtenerla. 

**Nota:** aquí tomamos como valor de ejemplo `secret-token`, podría ser `session`, `Authorized` o el que sea.

```js
<script>setTimeout(function(){ alert(document.getElementById('secret-token').value); },5000)</script>
```

**Lo que hace:** espera 5 segundos y luego busca en el DOM un elemento con `id="secret-token"` y muestra su `value` en una `alert`.

**Importante:** ejecutamos este código con la instrucción de delay `setTimeout` ya que el código JS se ejecuta antes que el renderizado de la página y por lo tanto antes que nuestras cookies estén visibles para hacer esta extracción. El tiempo de espera de `setTimeout` aquí lo ajustamos a 5 segundos con `5000` pero puede ser adaptado según necesidad.


---

### ¿Por qué `HttpOnly` no impide esto?

- `HttpOnly` evita que JavaScript lea la cookie con `document.cookie`.
    
- **Pero** si el servidor **reimprime** la cookie dentro del HTML (por ejemplo, en el `value` de un `<input>` o en texto), ese HTML es accesible por `fetch`/DOM y por por scripts que se ejecuten en la página. Entonces `HttpOnly` no protege contra fugas causadas por el propio servidor al **mostrar** la cookie.
    
- Conclusión: la protección `HttpOnly` actúa en el lado cliente frente a `document.cookie`, pero no protege contra malas prácticas del servidor que exponen el valor.

---

## Archivo phpinfo.php

Cuando veamos que el servidor esta usando como lenguaje `php` podemos tratar de fuzzear el archivo de configuración por defecto que trae este lenguaje, este es el `phpinfo.php`. Para ello es importante hacer una exhaustiva fase de reconocimiento y enumeración.

Un comando útil para encontrar este tipo de archivos es el siguiente:

```bash
ffuf -u "http://<dominio_objetivo/FUZZ.php" -w /usr/share/Seclists/Discovery/Web-Content/raft-medium-directories.txt -ac -mc 200,301,302,403,401
```

```bash
ffuf -u "http://target/FUZZ" -w /usr/share/SecLists/Discovery/Web-Content/raft-medium-directories.txt -t 40 -ac -mc all -o ffuf_output.json -of json
```

`-ac`  
**Auto-calibrate**. `ffuf` hace una serie de comprobaciones automáticas para intentar detectar y eliminar falsos positivos causados por filtros de la aplicación (por ejemplo páginas de error que devuelven 200 OK con contenido estático). Ayuda a reducir ruido en los resultados.

`-mc 200,301,302,403,401` 
**Match codes**. Le indica a `ffuf` que muestre resultados para los códigos HTTP (200, 301, 302,403). Es decir, filtra por código. 

`-o resultados.json -of json` 
**Salida de fichero**. Para guardar y analizar después.

Ejemplo de salida:

```bash
/phpinfo.php           Status: 200   Size: 4521   Words: 300   Lines: 40
/uploads.php           Status: 403   Size: 123    Words: 12    Lines: 3
/old/backup.php        Status: 301   Size: 0      Location: /backup/
```

Si vamos al endpoint encontrado y podemos visualizar el archivo `phpinfo.php`. Tenemos la posibilidad de que las cookies estén reflejadas en el apartado `HTTP Headers Information`.

![Captura](phpinfo.png)

![Captura](phpinfo_2.png)

Ahora con el siguiente payload podemos extraer la información de la cookie de este archivo:

```js
<script>fetch('/phpinfo.php').then(r=>r.text()).then(t=>alert((/HTTP_COOKIE\s*<\/td>\s*<td class="v">(.*?)<\/td>/.exec(t)||[])[1]||'No encontrada'));</script>
```

### 1) Flujo general (qué hace en alto nivel)

1. El navegador ejecuta el `<script>`.
    
2. `fetch('/phpinfo.php')` solicita la página `/phpinfo.php` del mismo origen.
    
3. Cuando llega la respuesta, `r.text()` convierte el cuerpo HTTP en texto (HTML).
    
4. Se aplica una expresión regular sobre ese HTML para buscar la sección donde `phpinfo()` muestra la cabecera `HTTP_COOKIE`.
    
5. Si la regex encuentra un valor, lo muestra con `alert(...)`; si no, muestra `No encontrada`.
    

Esto sirve para **extraer** (mostrar) el contenido que `phpinfo()` imprime en la página acerca de las cookies que el servidor recibió en la petición.

---

### 2) Detalle línea a línea

### `fetch('/phpinfo.php')`

- Hace una petición GET a `/phpinfo.php`.
    
- **Credenciales/cookies:** para **mismo origen**, el `fetch` envía las cookies automáticamente (valor por defecto `credentials: "same-origin"`). Por tanto la petición lleva las cookies de la víctima si el script corre en el contexto del sitio objetivo.
    
- Si fuese cross-origin, habría que usar `fetch(url, { credentials: 'include' })` y además el servidor tendría que permitir CORS con `Access-Control-Allow-Credentials`, etc. Aquí no hace falta porque es un laboratorio same-origin.
    

### `.then(r => r.text())`

- Obtiene el body de la respuesta como texto (el HTML generado por `phpinfo()`).
    

### Regex `(/HTTP_COOKIE\s*<\/td>\s*<td class="v">(.*?)<\/td>/.exec(t) || [])[1]`

- Aplica una **expresión regular** sobre el HTML `t`.
    
    - `HTTP_COOKIE` es el texto fí­sico que `phpinfo()` usa para etiquetar la fila donde aparece la cookie recibida (esto depende de la versión/idioma/tema de `phpinfo()`).
        
    - `\s*<\/td>\s*<td class="v">` busca la estructura HTML típica de la tabla de `phpinfo()` (cierre de la celda del nombre y apertura de la celda que contiene el valor).
        
    - `(.*?)` es un **grupo capturador** no codicioso que captura el contenido entre `<td class="v">` y `</td>` — sería el valor de la cookie (toda la cadena enviada en la cabecera `Cookie:`).
        
    - `/.exec(t)` devuelve un array si hay coincidencia; en posición `[1]` está el contenido capturado por `(.*?)`.
        
- `|| []` evita que `.exec` devuelva `null` y provoque un error; en caso de no coincidencia, el índice `[1]` será `undefined`.
    
- Finalmente `|| 'No encontrada'` muestra un mensaje por defecto si no hay captura.
    

### Comando `alert(...)`

- Muestra en ventana emergente el valor de la cookie encontrada o el texto `'No encontrada'`.
    

---

### 3) Por qué funciona (y cuándo NO funciona)

#### Por qué funciona:

- `phpinfo()` por defecto imprime variables de servidor (incluida la cabecera `HTTP_COOKIE`) en una tabla HTML. Si esa tabla contiene la cookie que el navegador envió, el HTML resultante contendrá esa cadena.
    
- `fetch` en mismo-origen envía cookies y puede leer la respuesta, por tanto el script obtiene el HTML que contiene el valor de la cookie.
    

#### Limitaciones y situaciones donde puede fallar:

- **Si `/phpinfo.php` no existe** o no está accesible -> `fetch` falla o devuelve 404.
    
- **Si phpinfo no imprime `HTTP_COOKIE`** (por ejemplo configuraciones personalizadas o idioma distinto que cambia el label) la regex no encontrará nada.
    
- **Si la salida de phpinfo está en otro formato** (plantilla, diferente estructura de tabla), la regex puede no coincidir.
    
- **Si hay protección CSP** (Content-Security-Policy) que impide ejecución de scripts inline o bloquea fetch hacia esa URL, el payload puede fallar.
    
- **Si la página requiere autenticación** o el recurso no es accesible para el contexto en el que se ejecuta el script, no funcionará.
    
- **Si el servidor no incluye el valor de la cookie en la salida** (p. ej. se filtra/oculta la cabecera), no hay dato que extraer.
    

#### Sobre HttpOnly

- **Importante**: la bandera `HttpOnly` evita que `document.cookie` sea leído por JS en el cliente. **Pero** si el servidor _imprime_ la cabecera `Cookie:` dentro de la respuesta (como lo hace `phpinfo()`), ese texto está en el HTML y el script lo puede leer con `fetch` y extraerlo.  
    En otras palabras: **`HttpOnly` protege el acceso vía `document.cookie`, pero no protege si el servidor reimprime las cookies en la respuesta que JS puede leer.** Por eso es mala práctica que una página muestre cabeceras sensibles.
    

---

### 4) Ejemplo de fragmento de `phpinfo()` y cómo captura la regex

Imagina parte del HTML generado por `phpinfo()`:

```html
<tr>
  <td>HTTP_COOKIE</td>
  <td class="v">SESSIONID=abc123; theme=dark</td>
</tr>
```

La regex `/HTTP_COOKIE\s*<\/td>\s*<td class="v">(.*?)<\/td>/` capturará `SESSIONID=abc123; theme=dark` en el grupo 1.

---

