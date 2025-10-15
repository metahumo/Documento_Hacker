
---

# Reflected XSS en una cadena JavaScript con paréntesis angulares codificados

## Contexto del laboratorio

- Laboratorio: Reflected XSS into a JavaScript string with angle brackets HTML encoded.
    
- Descripción: existe una vulnerabilidad de Cross-Site Scripting reflejado en la funcionalidad de seguimiento de consultas de búsqueda. Los caracteres `<` y `>` aparecen codificados en la salida HTML, y la reflexión ocurre dentro de una cadena JavaScript. El objetivo es romper la cadena JavaScript y ejecutar `alert(0)`.
    

[Ver laboratorio Portswigger](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded)


---

## Código vulnerable observado

```html
<script>
    var searchTerms = 'test';
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
</script>

<!-- Resultado visible desde DevTools/Console -->
<img src="/resources/images/tracker.gif?searchTerms=test">
```

En este patrón, el valor proveniente de la entrada de búsqueda se inserta directamente dentro de una cadena literal en JavaScript delimitada por comillas simples. Aunque los signos `<` y `>` se codifican (por ejemplo `&lt;` / `&gt;`), esto no impide que una comilla o secuencia de control cierre la cadena y permita la inyección de código.

## Objetivo del exploit

Romper la cadena JavaScript donde se asigna `searchTerms`, ejecutar `alert(0)` y evitar romper la sintaxis del resto del script para que la página continúe funcionando tras la inyección.

## Payload que resuelve el laboratorio

```
test';alert(0); var test='probando
```

Este payload cierra la cadena original, inyecta la llamada a `alert(0);` y añade una re-declaración/atribución posterior para evitar errores de sintaxis o referencias rotas en el resto del código.

## Cómo funciona el exploit (ejecución paso a paso)

1. El servidor refleja el parámetro de búsqueda dentro del literal JS:
    
    ```js
    var searchTerms = '...USER_INPUT...';
    ```
    
2. Si el parámetro `search` contiene `test';alert(0); var test='probando`, la línea resultante será:
    
    ```js
    var searchTerms = 'test';alert(0); var test='probando';
    ```
    
    - La primera comilla simple `'` cierra la cadena original.
        
    - `;alert(0);` ejecuta la alerta inmediatamente.
        
    - `var test='probando';` intenta restaurar el flujo del script creando una variable que mitigue errores posteriores derivados del cierre de la cadena.
        
3. A continuación, el resto del script continúa ejecutándose. La llamada a `document.write('<img src="...'+encodeURIComponent(searchTerms)+'">');` usará el identificador `searchTerms` tal como quedó declarado en el contexto (dependiendo del payload de restauración puede evitar excepciones). El objetivo del laboratorio es cumplir la ejecución de `alert(0)`, que ya habrá ocurrido.
    
4. Los caracteres `<` y `>` codificados no impiden esta técnica, porque la inyección no usa etiquetas HTML sino que rompe la sintaxis de la cadena JavaScript.
    

## Pasos para reproducir (entorno de laboratorio)

1. Abrir la página del laboratorio.
    
2. Realizar una petición GET con el parámetro `search` cuyo valor sea exactamente `test';alert(0); var test='probando`.
    
3. Inspeccionar el código fuente generado o la consola para confirmar que la línea `var searchTerms = '...';` contiene la inyección.
    
4. Verificar que al cargar la página se ejecuta `alert(0)`.
    


## Por qué esta técnica funciona aunque `<` y `>` estén codificados

- La codificación de `<` y `>` protege contra inyecciones que dependan de construir nuevas etiquetas HTML (por ejemplo `<script>`), pero no evita que se rompa una cadena JavaScript con comillas adecuadas (`'` o `"`) ni que se inyecten operadores y llamadas a funciones.
    
- La inyección en contexto de cadena JavaScript requiere escapar o neutralizar comillas y caracteres especiales del lenguaje, por lo que la mitigación debe aplicarse con escaping contextual en el momento de renderizar la cadena dentro del script.
    

## Mitigaciones recomendadas

1. Escapar correctamente el contenido cuando se inserte dentro de literales JavaScript. Para cadenas delimitadas por comillas simples, escapar apóstrofes y caracteres especiales (por ejemplo reemplazar `'` por `\'`).
    
    - Ejemplo (servidor): antes de renderizar en una cadena JS, aplicar una función que haga JavaScript string escaping.
        
2. Evitar insertar directamente datos no confiables dentro de scripts. En su lugar, serializar los datos como JSON y usar `JSON.stringify` o asignar valores mediante APIs DOM seguras.
    
    - Ejemplo seguro:
        
        ```html
        <script>
            var searchTerms = JSON.parse('"' + JSON.stringify(userInput) + '"');
            // o mejor aún, inyectar como data attribute y leerlo con JS
        </script>
        ```
        
    - Alternativa: renderizar el valor en un atributo `data-*` y leerlo con `element.dataset`.
        
3. Validación por whitelist del parámetro de búsqueda: permitir únicamente caracteres esperados (letras, números, espacios y signos seguros) y rechazar o sanitizar el resto.
    
4. Evitar `document.write` para construir HTML con datos no confiables. Usar métodos de creación de nodos (DOM) y asignaciones seguras (`textContent`, `setAttribute`) que gestionen el escaping automáticamente.
    
5. Aplicar Content Security Policy (CSP) para limitar la ejecución de scripts inyectados, aunque CSP no sustituye a un correcto escaping contextual.
    

## Ejemplo de corrección

- Opción 1: escapar la cadena para uso en JavaScript:
    

```js
function jsStringEscape(str) {
    return str.replace(/\\/g, '\\\\')
              .replace(/'/g, "\\'")
              .replace(/\n/g, '\\n')
              .replace(/\r/g, '\\r');
}

var safe = jsStringEscape(user_input_from_server);
// render: var searchTerms = '" + safe + "';
```

- Opción 2: inyectar el valor como JSON seguro desde el servidor y parsearlo en cliente:
    

```html
<script>
    // suponiendo que server_json contiene la cadena correctamente JSON-encoded
    var searchTerms = JSON.parse('"' + server_json + '"');
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
</script>
```

## Recomendaciones finales

- Aplicar escaping contextual siempre que se inserten datos en archivos JavaScript.
    
- Preferir JSON o atributos `data-*` sobre la interpolación directa en literales JS.
    
- Validar entradas en el servidor con una whitelist cuando sea posible.
    
- Evitar `document.write` y otras prácticas inseguras para ensamblar HTML en tiempo de ejecución.
    

---
