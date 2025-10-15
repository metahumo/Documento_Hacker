
---

# Explicación: XSS DOM con `hashchange` y jQuery

En este documento explicamos paso a paso el siguiente script y su riesgo en el contexto de una XSS DOM basada en el evento `hashchange` y jQuery. 

[Ver laboratorio Portswigger](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event)

```html
<script>
    $(window).on('hashchange', function(){
        var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
        if (post) post.get(0).scrollIntoView();
    });
</script>
```

## Contexto general

En una **XSS DOM** el _sink_ vulnerable está en el lado cliente: el código JavaScript del navegador manipula el DOM usando datos controlados por el usuario (por ejemplo `window.location.hash`, `document.cookie`, o valores en el DOM) sin una correcta validación o escape. El evento `hashchange` se dispara cuando cambia el fragmento `#` de la URL (la parte después de `#`).

## Qué hace el script (línea por línea)

1. `$(window).on('hashchange', function(){ ... });`
    
    - Registramos un listener con jQuery sobre `window` para el evento `hashchange`.
        
    - Cada vez que cambia el fragmento hash en la URL, se ejecuta la función interna.
        
2. `window.location.hash.slice(1)`
    
    - `window.location.hash` devuelve el fragmento con `#` (por ejemplo `#post1`).
        
    - `.slice(1)` elimina el `#`, quedando solo el texto (ej. `post1`).
        
3. `decodeURIComponent(...)`
    
    - Decodifica componentes codificados en la URL (`%20` → espacio, `%3C` → `<`, etc.).
        
    - Esto permite que caracteres especiales y signos `<`/`>` lleguen sin codificar al siguiente paso.
        
4. `$('section.blog-list h2:contains(' + ... + ')')`
    
    - Construimos dinámicamente un selector jQuery que usa el pseudo-selector `:contains(text)` para buscar `<h2>` dentro de `section.blog-list` cuyo texto contenga la cadena proporcionada.
        
    - Ejemplo: `$('section.blog-list h2:contains(Hola)')` selecciona `<h2>` que contengan "Hola".
        
5. `if (post) post.get(0).scrollIntoView();`
    
    - Si `post` existe, usamos `scrollIntoView()` para desplazar la página hasta ese elemento.
        
    - Funcionalmente, esto sirve para que al abrir `#titulo` la página se desplace automáticamente al post correspondiente.
        

## Punto peligroso: concatenación sin escape

El riesgo principal está en **concatenar directamente** el contenido del `hash` dentro del selector jQuery **sin escapar ni poner comillas**. Al usar `decodeURIComponent` antes, un atacante puede inyectar caracteres o etiquetas especiales en el fragmento.

Ejemplo de URL manipulada por un atacante:

```
https://victima.com/#<img src=x onerror=alert(1)>
```

El código intentará construir internamente algo equivalente a:

```js
$('section.blog-list h2:contains(<img src=x onerror=alert(1)>)')
```

Según la versión de jQuery y cómo se evalúe el selector, esto puede provocar:

- Selectores malformados que desencadenen excepciones o comportamientos inesperados.
    
- En versiones antiguas/ vulnerables de jQuery, ejecución de código o interpretación de HTML con posibilidad de DOM XSS.
    

## Flujo de datos (resumen)

1. Origen: `window.location.hash` (controlado por el usuario).
    
2. Transformación: `decodeURIComponent()` (decodifica caracteres codificados).
    
3. Sink inseguro: concatenación en el selector jQuery `:contains(...)` sin escape.
    
4. Acción final: `scrollIntoView()` aplicada al elemento encontrado.
    

## Por qué esto puede ser una XSS DOM

- El fragmento `#` es totalmente controlable por un atacante (se puede enviar un enlace con el hash malicioso).
    
- La falta de escape/validación permite inyectar caracteres especiales que alteren el selector o, en implementaciones vulnerables, permitan ejecutar contenido HTML/JS.
    
- jQuery en versiones anteriores a 3.5 tenía varios problemas relacionados con cómo se manejaban selectores dinámicos y la interpretación de HTML en ciertos contextos, lo que aumentaba el riesgo.
    

## Recomendaciones para mitigación

1. **No construir selectores con datos arbitrarios sin escapar.**
    
    - Escapar el valor antes de insertarlo en un selector.
        
2. **Usar métodos más seguros para buscar por texto.**
    
    - En lugar de `:contains(...)` con concatenación, iterar elementos y comparar su texto con un valor comparado de forma segura (por ejemplo, usando `text()` y comparaciones exactas o normalizadas).
        
3. **Validar el formato del hash.**
    
    - Aceptar solo patrones esperados (por ejemplo: `^[A-Za-z0-9\-\_ ]+$`) y rechazar/ignorar el resto.
        
4. **Escapar o eliminar caracteres peligrosos** tras `decodeURIComponent` antes de usar el valor en el DOM o en selectores.
    
5. **Actualizar jQuery a versiones modernas** (si aplica) y revisar changelogs sobre seguridad.
    

## Ejemplo de alternativa segura (esquema)

```js
$(window).on('hashchange', function(){
    var raw = decodeURIComponent(window.location.hash.slice(1));
    // Validación: aceptar solo caracteres seguros (ejemplo simplificado)
    if (!/^[\w\- ]+$/.test(raw)) return; // descartamos hashes sospechosos

    // Buscamos de manera segura: iterar h2 y comparar texto
    $('section.blog-list h2').each(function(){
        if ($(this).text().indexOf(raw) !== -1) {
            this.scrollIntoView();
            return false; // salir del each
        }
    });
});
```

En este esquema validamos el contenido y evitamos construir un selector con concatenación directa.

## Conclusión

Funcionalmente, el script intenta desplazar la vista al post cuyo `<h2>` contiene el texto del `hash`. Sin embargo, al concatenar `decodeURIComponent(window.location.hash.slice(1))` dentro de un selector jQuery sin escape, abrimos la puerta a una XSS DOM dependiendo de la versión de jQuery y del manejo interno de selectores. Debemos evitar la inserción directa en selectores y validar/escapar el contenido antes de usarlo.

---

## Resolución del laboratorio (PoC específica)

En el laboratorio de PortSwigger referido, la resolución se consigue con el siguiente payload que aprovecha exactamente la función del script explicado en este documento. El payload se inyecta desde un `iframe` que modifica su `src` en `onload`, añadiendo contenido al fragmento (`#`) que la página vulnerable procesará con `decodeURIComponent` y colocará sin escape en el selector jQuery.

[Ver laboratorio Portswigger](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event)

**Exploit**

```js
<iframe src="https://0afb007d03d3854180bc9e6a00b50085.web-security-academy.net/#" onload="this.src += '<img src=0 onerror=print()>'"></iframe>
```

Cómo encaja este exploit con el flujo explicado:

1. El `iframe` carga la página vulnerable con un hash inicial vacío.
    
2. En `onload` concatenamos al `src` del `iframe` la cadena `'<img src=0 onerror=print()>'`, que queda como parte del fragmento (`#<img src=0 onerror=print()>`).
    
3. El cambio del `hash` dentro del `iframe` dispara el evento `hashchange` en la página objetivo.
    
4. El script vulnerable ejecuta `decodeURIComponent(window.location.hash.slice(1))` y concatena el resultado dentro del selector `:contains(...)` sin escaparlo.
    
5. Debido a cómo la versión de jQuery del laboratorio evalúa ese selector dinámico, la carga interpretada del fragmento provoca la ejecución de `print()` desde el `onerror` del `img`, lo que resuelve el laboratorio.
    

**Nota importante:** este exploit funciona en el contexto específico del laboratorio porque la versión de jQuery y el motor de selectores permiten que la inyección en `:contains(...)` resulte en ejecución de código. En aplicaciones reales, la explotabilidad dependerá de la versión de jQuery y de las defensas presentes.

---
