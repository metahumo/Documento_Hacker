# XSS en JavaScript URL con caracteres limitados

## Introducción

En este laboratorio analizamos una vulnerabilidad de XSS que se produce dentro de un esquema `javascript:`. Aunque podría parecer un caso sencillo, la aplicación bloquea espacios y varios caracteres clave, dificultando la construcción de un payload tradicional. Para superar estas restricciones recurrimos a técnicas avanzadas del propio lenguaje JavaScript, como funciones flecha, el uso creativo de excepciones y la activación indirecta de `alert` mediante el manejador global `onerror`.

El objetivo del laboratorio es ejecutar `alert` incluyendo el número **1337** dentro del mensaje, respetando todas las limitaciones impuestas.

[Ver laboratorio Portswigger](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-url-some-characters-blocked)

---

## Entorno del laboratorio

El comportamiento de la aplicación presenta las siguientes características:

- Refleja la entrada del usuario dentro de una URL con esquema JavaScript.
    
- Filtra caracteres esenciales, incluyendo los espacios.
    
- Impide el uso de paréntesis en muchas construcciones.
    
- Exige que el usuario pulse **"Back to blog"** para activar el vector.
    

Estas restricciones obligan a construir expresiones válidas que no dependan de caracteres bloqueados.

---

## Superficie de ataque

Como no podemos ejecutar directamente `alert(1337)`, necesitamos encadenar elementos del lenguaje que permitan:

1. **Asignar** la función `alert` al manejador `onerror`.
    
2. **Forzar** una excepción que active dicho manejador.
    
3. **Evitar** los espacios mediante comentarios `/**/`.
    
4. **Ejecutar** el código sin paréntesis utilizando conversiones implícitas a cadena.
    

Para lograr esto, empleamos:

- Una **función flecha**, que permite crear un bloque `{}` incluso sin espacios.
    
- La sentencia `throw`, que genera un error ejecutable dentro del bloque.
    
- La asignación `onerror=alert,1337`, que fija `alert` como manejador global.
    
- La sobrescritura de `toString` en `window`, de modo que convertir `window` a cadena desencadene nuestro código.
    

---

## Payload final

Payload de PortSwigger:

```
%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27
```

Usado mediante:

```
https://YOUR-LAB-ID.web-security-academy.net/post?postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27
```

La ejecución ocurre al pulsar **"Back to blog"**, momento en que el navegador realiza la conversión de `window` a cadena.

---

## Explicación del payload

- `%27}` — rompe la estructura inicial permitiendo la inyección.
    
- `x=x=>{...}` — define una función flecha sin necesidad de espacios.
    
- `throw/**/onerror=alert,1337` — genera el error y asigna `alert` al manejador.
    
- `toString=x` — reemplaza el método `toString` por nuestra función.
    
- `window+''` — fuerza la conversión del objeto a cadena, desencadenando la ejecución.
    

---

## Creación del payload 

### 1. Análisis del código fuente

En el HTML encontramos:

```html
<a href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d3'}).finally(_ => window.location = '/')">Back to Blog</a>
```

Este enlace ejecuta un `fetch()` y después redirige a la raíz. Si modificamos el contenido reflejado en la URL, podemos **inyectar código dentro de este JavaScript**.

### 2. Descubrimiento con WFUZZ

Al fuzzear el parámetro que se refleja en el atributo `body`, comprobamos que el carácter **`&` está permitido**. Esto es importante porque nos permite **salir del valor original del parámetro** y añadir nuevas expresiones dentro de la llamada JavaScript.

Este comportamiento sirve como primitivo de escape del contexto.

### 3. Primera versión del payload

Podemos intentar algo como:

```html
<a href="javascript:fetch('/analytics', {method:'post',body:'/post?postId=3&'},alert(1),{x:').finally(_ => window.location = '/')">Back to Blog</a>
```

Donde las comillas simples internas se codifican como `%27`:

```html
<a href="javascript:fetch('/analytics', {method:'post',body:'/post?postId=3&%27},alert(1),{x:%27).finally(_ => window.location = '/')">Back to Blog</a>
```

Esto se consigue enviando en la URL:

```
https://YOUR-LAB-ID.web-security-academy.net/post?postId=3&%27,alert(1),{x:%27
```

Al cargar la página y situar el cursor sobre **"Back to Blog"**, vemos que el atributo `href` se ha modificado con nuestro contenido malicioso.

### 4. Eliminando los paréntesis (ya que están bloqueados)

El laboratorio requiere evitar el uso de paréntesis. Para ello empleamos el mismo patrón del payload oficial, basado en funciones flecha y conversiones implícitas:

```html
<script>x=x=>{throw/**/onerror=alert,1337},toString=x,window + ''</script>
```

Podemos inyectarlo en la URL así:

```
https://YOUR-LAB-ID.web-security-academy.net/post?postId=3&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window%2b'',{x:'
```

### 5. Conceptos clave usados en este método

#### Funciones flecha
Permiten definir funciones sin espacios y encapsular un bloque `{}` donde podemos usar `throw`. Ejemplo:

```

x=x=>{throw/**/onerror=alert,1337}

```

#### Escape mediante `&`
El carácter `&` permite **cerrar el valor original del parámetro** y escribir nuevas expresiones dentro del JavaScript del enlace.

#### Sobrescritura de `toString`
Al asignar nuestra función a `toString`, cualquier conversión del objeto provoca la ejecución del payload.

#### Conversión implícita de `window`
`window+''` obliga a llamar a `window.toString()`, que ahora contiene nuestro código.

### 6. Resultado

Este payload alternativo también ejecuta `alert(1337)` cumpliendo todas las restricciones.

---

## Conclusión

Este laboratorio demuestra que incluso con restricciones severas —filtros de caracteres, ausencia de espacios y prohibición de paréntesis— es posible ejecutar JavaScript manipulando constructores del lenguaje. El uso de funciones flecha, excepciones, conversión implícita de objetos y técnicas de fuzzing como WFUZZ permite encontrar rutas alternativas de ejecución. Ambos enfoques, tanto el oficial como el alternativo, muestran la importancia de una sanitización estricta, especialmente cuando los valores se inyectan en contextos JavaScript sensibles.

---
