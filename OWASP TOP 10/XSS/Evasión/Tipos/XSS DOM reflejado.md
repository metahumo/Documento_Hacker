
---

# Reflected DOM XSS con `eval()` y `location.search`

## Contexto general

Este laboratorio demuestra una vulnerabilidad reflejada **DOM**. El servidor procesa datos de la petición y refleja esos datos en la respuesta (en formato JSON). Un script en la página toma esa respuesta y la procesa de forma insegura, escribiéndola con `eval()` en un _sink_ peligroso, lo que permite ejecutar código arbitrario en el contexto de la página.

El objetivo del reto es inyectar una carga que ejecute `alert()` aprovechando que el parámetro de búsqueda se **refleja** en la respuesta.

[Ver laboratorio Portswigger](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected)


---

## Código vulnerable (cliente)

El fragmento JavaScript vulnerable es este:

```js
function search(path) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            eval('var searchResultsObj = ' + this.responseText);
            displaySearchResults(searchResultsObj);
        }
    };
    xhr.open("GET", path + window.location.search);
    xhr.send();
}
```

Más abajo, la página invoca la función con:

```html
<script>search('search-results')</script>
```

Es decir, la función solicita `search-results` concatenando `window.location.search` —que es controlable por el atacante— y luego **evalúa directamente** la respuesta (`this.responseText`) con una concatenación dentro de `eval()`.

---

## Por qué esto es peligroso

- `this.responseText` contiene JSON devuelto por el servidor, por ejemplo:
    
    ```json
    {"results":[],"searchTerm":"testing"}
    ```
    
- El cliente hace `eval('var searchResultsObj = ' + this.responseText);`. Si `responseText` es exactamente un JSON válido, esto actúa como un `var` que asigna un objeto y luego `displaySearchResults` lo usa.
    
- Sin embargo, si el valor reflejado dentro del JSON no está correctamente escapado por el servidor, un atacante puede hacer que `responseText` termine conteniendo **código JavaScript adicional** (no solo JSON). Dado que `eval()` concatena y evalúa directamente, ese código se ejecutará.
    

El punto clave es que **se usa `eval()` sobre contenido que proviene de la red**, y el servidor deja escapar caracteres (por ejemplo comillas) que permiten al atacante salir de la estructura JSON y añadir JavaScript.

---

## Petición y reflected (ejemplo)

Petición del servidor (sin ataque):

```
{"results":[],"searchTerm":"testing"}
```

Si se intenta escapar/inyectar desde el parámetro `searchTerm` y el servidor no lo sanitiza correctamente, la respuesta puede acabar siendo algo como:

```
{"results":[],"searchTerm":"testing\"*alert(0)}//"}
```

o, como en el laboratorio, la forma enviada por el atacante:

```
{"results":[],"searchTerm":"probando\"*alert(0)}//"}
```

El payload enviado por el atacante en el parámetro de búsqueda fue:

```
probando\"*alert(0)}//
```

(dependiendo de cómo el servidor construya la respuesta, la sintaxis exacta necesaria para romper la estructura JSON puede variar; la clave es que el servidor no neutraliza las comillas y permite terminar la cadena/objeto y añadir código).

---

## ¿Cómo se convierte esto en ejecución de código?

1. Suponiendo que el `responseText` resultante (tal como el servidor lo devuelve) contiene código adicional tras la parte JSON, entonces la línea:
    
    ```js
    eval('var searchResultsObj = ' + this.responseText);
    ```
    
    deja de ser únicamente una asignación y pasa a ejecutar lo que venga después del JSON.
    
2. Por ejemplo, si el servidor devolviera literalmente (simplificado para ilustrar):
    
    ```
    {"results":[],"searchTerm":"probando"};alert(0);//
    ```
    
    entonces tras concatenar en `eval()` quedaría:
    
    ```js
    eval('var searchResultsObj = ' + '{"results":[],"searchTerm":"probando"};alert(0);//');
    ```
    
    que es equivalente a ejecutar:
    
    ```js
    var searchResultsObj = {"results":[],"searchTerm":"probando"};
    alert(0);
    // resto comentado por //
    ```
    
    y por tanto `alert(0)` se ejecuta.
    
3. En el laboratorio concreto, el servidor refleja el valor del parámetro sin el escaping correcto, por eso un payload del tipo `probando\"*alert(0)}//` puede provocar que el `eval()` ejecute `alert(0)` (los detalles exactos de cómo se transforman las comillas/backslashes dependen de la implementación del servidor).
    

---

## Payload entregado (ejemplo del laboratorio)

Payload usado para demostrar la XSS:

```
probando\"*alert(0)}//
```

Este payload está diseñado para romper la estructura del JSON que el servidor devuelve y añadir la llamada a `alert(0)` después de la asignación que hace `eval()`.

Nota: en entornos reales la cadena exacta necesaria suele ser algo como:

```
"} ; alert(0); //
```

 o

```
"\"};alert(0);// 
```

Dependiendo de si el servidor escapa o no las comillas (`"`) en el valor reflejado. La idea es siempre la misma: introducir caracteres que cierren la literal JSON y luego añadir instrucciones JS.

---

## Pasos para reproducir

1. Construir una URL que incluya en la query string el valor malicioso para `searchTerm` (o el parámetro que el servidor refleje).
    
2. Cargar la página que ejecuta `search('search-results')` (o disparar la función `search` que hace la petición XHR).
    
3. Observar la respuesta del servidor (`responseText`) en la pestaña Network del navegador o con una proxy (Burp) y verificar cómo queda exactamente el JSON reflejado.
    
4. Si `responseText` contiene código JavaScript añadido, `eval()` lo ejecutará y se verá la `alert()`.
    

---

## Mitigaciones

1. **Eliminar `eval()`**: NO usar `eval()` para parsear JSON. Reemplazar por:
    
    ```js
    var searchResultsObj = JSON.parse(this.responseText);
    ```
    
    `JSON.parse` solo acepta JSON válido y no ejecuta código arbitrario.
    
2. **Sanitizar / escapar en el servidor**: el servidor debe producir JSON válido y asegurarse de escapar correctamente valores (o, mejor aún, construir la respuesta usando funciones/serializadores JSON en servidor que garanticen validez y escapado).
    
3. **Validación por whitelist**: controlar los parámetros de entrada en el servidor (p. ej. limitar longitud, caracteres permitidos, o aceptar sólo valores esperados).
    
4. **Evitar concatenar datos no confiables en código ejecutable**: si por alguna razón hay que serializar datos en el cliente, hacerlo como datos (JSON) y no como código fuente.
    
5. **Usar CSP**: una política de seguridad de contenido puede ayudar a mitigar el impacto (p. ej. bloquear `eval` y `inline-script`), aunque no sustituye correcciones de fondo.
    
6. **Revisar `displaySearchResults`**: además del parseo, asegurar que cualquier inserción en el DOM se haga usando `textContent` o métodos que escapen correctamente, nunca `innerHTML` con datos sin sanitizar.
    

---

## Resumen

- El vector explota la combinación **reflejo en el servidor** + **`eval()` inseguro en el cliente**.
    
- El servidor devuelve JSON que incluye datos controlados por el usuario; el cliente hace `eval('var ... = ' + responseText)` y por ello cualquier código añadido en `responseText` se ejecuta.
    
- Solución inmediata y prioritaria: reemplazar `eval(...)` por `JSON.parse(...)` y, en general, no ejecutar código construido a partir de respuestas de red.
    

---
