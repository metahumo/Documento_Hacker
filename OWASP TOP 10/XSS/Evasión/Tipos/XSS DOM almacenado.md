
---

# Stored DOM XSS en la funcionalidad de comentarios del blog

En este documento describimos  cómo funciona la vulnerabilidad almacenada (stored) de tipo DOM XSS en la funcionalidad de comentarios, por qué el payload suministrado explota la falla y qué mitigaciones aplicar. 

[Ver laboratorio Portswigger](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-stored)

## Contexto del laboratorio

- Descripción: el laboratorio muestra una vulnerabilidad **stored DOM XSS** en la funcionalidad de comentarios del blog. Un comentario malicioso que se almacena en el servidor se devuelve posteriormente y es procesado por código cliente de forma insegura, permitiendo la ejecución de `alert()` en los navegadores de los usuarios que carguen la página.
    
- Objetivo: explotar la vulnerabilidad almacenada para ejecutar `alert()`.
    

## Fragmento de código vulnerable (cliente)

```js
function loadComments(postCommentPath) {
    let xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            let comments = JSON.parse(this.responseText);
            displayComments(comments);
        }
    };
    xhr.open("GET", postCommentPath + window.location.search);
    xhr.send();

    function escapeHTML(html) {
        return html.replace('<', '&lt;').replace('>', '&gt;');
    }

    function displayComments(comments) {
        let userComments = document.getElementById("user-comments");

        for (let i = 0; i < comments.length; ++i)
            // ... continúa ...
```

Observaciones iniciales:

- La respuesta del servidor se parsea con `JSON.parse`, lo cual es correcto para obtener datos estructurados.
    
- Existe una función `escapeHTML(html)` definida, pero su implementación es insuficiente: usa `String.prototype.replace` sin expresiones regulares globales y solo reemplaza la **primera** ocurrencia de `<` y la **primera** de `>` en la cadena.
    
- El fragmento no muestra cómo `displayComments` inserta realmente cada comentario en el DOM; si `displayComments` usa `innerHTML` (o construye HTML concatenando strings) con los contenidos del comentario, y no aplica `escapeHTML` correctamente o no la aplica en absoluto, entonces un comentario almacenado puede contener HTML/JS ejecutable.
    

## Por qué es vulnerable

1. **Stored (almacenada)**: el payload maligno se envía como comentario y el servidor lo guarda. No es necesario que el atacante convenza a otro usuario para que lo visite inmediatamente; cualquier visualización posterior del comentario ejecutará el payload en los navegadores de los usuarios.
    
2. **DOM XSS**: aunque el servidor devuelve JSON y el cliente usa `JSON.parse`, la ejecución ocurre cuando el cliente inserta el contenido del comentario en el DOM usando una operación insegura (por ejemplo `element.innerHTML = ...` o concatenación en `document.write`). `JSON.parse` por sí mismo no impide XSS si el contenido textual resultante se trata como HTML.
    
3. **Escape insuficiente**: la función `escapeHTML` definida:
    
    ```js
    return html.replace('<', '&lt;').replace('>', '&gt;');
    ```
    
    solo reemplaza la primera aparición de `<` y la primera de `>` en la cadena, y no escapa otros caracteres importantes (`&`, `"`, `'`, `/`). Además, si `displayComments` no llama a `escapeHTML` o lo hace de forma incorrecta, el comentario permanece con sus etiquetas intactas.
    
4. **Payload**: el payload propuesto
    
    ```
    <><img src=0 onerror=alert(0)>
    ```
    
    funciona porque:
    
    - Las `<>` escapan la sanitización, `<img ...>` introduce una etiqueta `img` con un `onerror` inline que ejecuta JavaScript cuando el navegador intenta cargar la imagen (src inválido `0`).
        
    - Dependiendo de cómo `displayComments` inserte el comentario (por ejemplo `userComments.innerHTML += '<div class="comment">' + comment.text + '</div>'`), el navegador interpretará la porción `<img src=0 onerror=alert(0)>` como HTML real y ejecutará `alert(0)` en la etapa de procesamiento del DOM.
        
    - El `<>` inicial puede servir para romper estructuras previsibles o para lidiar con ciertos sanitizadores ingenuos; el vector concreto depende del procesamiento exacto en `displayComments`.
        

En resumen: la combinación de contenido almacenado por el servidor + inserción insegura en el DOM por el cliente + escape incompleto permite la ejecución de JS arbitrario en los navegadores que muestran el comentario.

## Pasos para reproducir

1. En el formulario de comentarios del laboratorio, enviar como contenido del comentario:
    
    ```
    <><img src=0 onerror=alert(0)>
    ```
    
2. Asegurarse de que el servidor acepta y almacena el comentario.
    
3. Cargar (o recargar) la página de visualización del post donde aparecen los comentarios. Si `displayComments` inserta el texto sin escapar correctamente, al procesar el HTML inyectado se ejecutará `alert(0)`.
    
4. Verificar en la pestaña Network / Response que el servidor devuelve el comentario dentro del JSON; inspeccionar también el DOM para ver cómo se ha renderizado el contenido.
    

## Mitigaciones y buenas prácticas

Para corregir la vulnerabilidad hay que aplicar defensas en varias capas:

1. **Escape contextual y completo en cliente**:
    
    - No usar `innerHTML` para insertar contenido controlado por usuarios. En su lugar, crear nodos DOM y asignar contenido con `textContent`:
        
        ```js
        let div = document.createElement('div');
        div.textContent = commentText; // seguro: se inserta como texto, no HTML
        userComments.appendChild(div);
        ```
        
    - Si por alguna razón se necesita insertar HTML permitido, usar una librería de sanitización (DOMPurify u otra) y un whitelist de etiquetas/atributos.
        
2. **Corregir `escapeHTML`**:
    
    - Si se decide mantener una función de escape, que haga el escaping correcto y global de los caracteres especiales:
        
        ```js
        function escapeHTML(html) {
            return html
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }
        ```
        
    - Pero preferimos `textContent` porque evita errores de escaping manual.
        
3. **Validación en el servidor (defensa en origen)**:
    
    - Validar y/o normalizar comentarios antes de almacenarlos (por ejemplo, limitar longitud, filtrar ciertos patrones, o almacenar solo texto plano).
        
    - Evitar almacenar HTML suministrado por el usuario a menos que se confíe explícitamente y se sanitice con librerías server-side seguras.
        
4. **Política de seguridad de contenido (CSP)**:
    
    - Implementar CSP que restrinja `script-src` y bloquee `unsafe-inline` si es posible. CSP no sustituye el escape correcto, pero reduce la gravedad de XSS que dependen de inline scripts.
        
5. **Auditoría y pruebas**:
    
    - Revisar todas las rutas donde datos almacenados se reflejan en el DOM.
        
    - Incluir pruebas automáticas para inyección de HTML/JS en pipelines de QA.
        

## Resumen

- La vulnerabilidad surge porque un comentario almacenado por el servidor se inserta en el DOM por el cliente sin escape seguro o con escape incompleto.
    
- El payload `<><img src=0 onerror=alert(0)>` aprovecha esa inserción insegura para ejecutar `alert(0)` en el navegador de cualquier usuario que vea el comentario.
    
- Las correcciones correctas son: no usar `innerHTML` con datos no confiables, usar `textContent` o sanitizadores robustos, y validar/sanitizar también en servidor.
    


---
