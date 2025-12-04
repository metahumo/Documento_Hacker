
---

# Qué es un sink en el contexto de XSS

> Cuando trabajamos con XSS, llamamos _sink_ a cualquier función, API o mecanismo del navegador que **toma valores dinámicos y los inserta en el DOM interpretándolos como HTML o JavaScript**.  

En otras palabras, un sink es el punto donde **nuestros datos dejan de ser texto inofensivo y pasan a ser código ejecutable**.

Por tanto, un sink no es la vulnerabilidad en sí, sino **el lugar del código donde nuestros datos se convierten en algo interpretado por el navegador**, y donde puede producirse la ejecución de payloads maliciosos.

Ejemplos sencillos de sinks:

- `innerHTML`
    
- `document.write`
    
- `jQuery.html()`
    
- `v-html` (Vue)
    
- Asignaciones dentro de `<script>`
    

Todo el trabajo de búsqueda de XSS consiste en identificar **qué datos controlamos** y **si esos datos llegan a un sink** sin un filtrado o escape seguro.

---

# 1. Cómo identificamos sinks peligrosos sin leer todo el código

En pentesting web raramente tenemos acceso completo al código fuente. Incluso cuando lo tenemos, leerlo entero no escala.  
Nuestra estrategia es localizar rápidamente qué rutas de datos interactúan con sinks peligrosos.

## a) Buscamos reflectores de entrada en el DOM

Enviamos un valor controlado:

```
?q=test123
```

Luego lo buscamos en el DOM, normalmente con DevTools (CTRL+F).

Si aparece, nos fijamos:

- en qué contexto está
    
- si está en HTML, atributo, script, URL, etc.
    

Esto nos orienta sobre qué tipo de payload podría ejecutarse.

---

## b) Observamos modificaciones dinámicas del DOM

Usamos DevTools para identificar dónde se cambia el DOM en runtime:

- puntos de ruptura en modificaciones del DOM
    
- puntos de ruptura en XHR/fetch
    

Esto nos permite descubrir qué funciones están inyectando valores en el DOM **sin tener que leer el proyecto entero**.

---

## c) Buscamos sinks en el código fuente con grep

Si tenemos acceso al código, en lugar de leerlo, buscamos directamente funciones peligrosas:

```
grep -R "innerHTML" -n .
grep -R "document.write" -n .
grep -R "html(" -n .
grep -R "eval" -n .
```

Una vez localizadas, verificamos si:

1. reciben datos controlables por el usuario
    
2. aplican sanitización o escape
    
3. están en un contexto interpretado
    

---

## d) Instrumentamos sinks dinámicamente

Podemos enganchar sinks para que nos muestren qué valores reciben:

```js
(function() {
    let old = Element.prototype.innerHTML;
    Object.defineProperty(Element.prototype, "innerHTML", {
        set: function(value) {
            console.log("innerHTML injected:", value);
            return old.call(this, value)
        }
    });
})();
```

Así capturamos automáticamente:

- quién modifica el DOM
    
- con qué datos
    

Sin leer una sola línea de la aplicación.

---

## e) Usamos heurísticas de funcionalidad

Cuando vemos interfaces como:

- búsquedas
    
- comentarios
    
- mensajería
    
- perfiles
    
- dashboards
    

sabemos que probablemente haya **inserción dinámica de HTML**, y por tanto sinks.

---

# 2. Sinks peligrosos más comunes

Este es un listado de los sinks más comunes asociados a XSS modernos:

---

## innerHTML

Interpreta cadenas como HTML crudo:

```js
element.innerHTML = userInput;
```

Si userInput contiene:

```html
<img src=x onerror=alert(1)>
```

Se ejecuta JS.

**Es el sink más utilizado y más peligroso en la práctica.**

---

## outerHTML

Reemplaza el nodo completo:

```js
element.outerHTML = userInput;
```

Permite:

- destruir elementos
    
- inyectar tags completos
    
- ejecutar scripts inline
    

---

## document.write

Muy común en código legacy, anuncios, tracking.

```js
document.write(userInput);
```

Ejecuta `<script>` inmediatamente.

Persisten muchos casos en webs antiguas.

---

## jQuery.html()

Versión de jQuery de innerHTML:

```js
$("#target").html(userInput);
```

Mismo riesgo, pero muy extendido en webs legacy.

---

## v-html (Vue.js)

Directiva que introduce HTML raw:

```html
<div v-html="userInput"></div>
```

Vue normalmente escapa contenido, pero `v-html` lo desactiva.

Común en aplicaciones modernas que muestran contenido “rico”.

---

# 3. Tabla rápida de riesgo

|Sink|Riesgo|Comentario|
|---|---|---|
|innerHTML|🔥🔥🔥|Muy común y crítico|
|outerHTML|🔥🔥🔥|Igual de malo y más destructivo|
|document.write|🔥🔥|Legacy pero explotable|
|jQuery.html()|🔥🔥🔥|Dominante en webs legacy|
|v-html|🔥🔥|Error típico en Vue moderno|

---

# 4. Señales de que un sink es explotable

Pensamos así:

1. ¿El valor viene de usuario?
    
2. ¿Se sanitiza?
    
3. ¿Se interpreta como HTML/JS?
    
4. ¿Podemos romper el contexto?
    

Si las respuestas son favorables, tenemos un candidato de XSS.

---

# 5. Estrategia de reconocimiento práctica

Nuestra metodología es:

1. Introducimos un valor controlado
    
2. Buscamos reflectores en el DOM
    
3. Identificamos contexto de inserción
    
4. Localizamos sinks asociados
    
5. Probamos payloads básicos
    
6. Escalamos si procede
    

No buscamos vulnerabilidades directamente, buscamos **rutas hacia sinks peligrosos**.

---

# 6. Idea clave

Un sink no es el bug:  
es el **mecanismo que convierte nuestros datos en código ejecutable**.

Por eso concentramos nuestros esfuerzos en:

- identificar sinks
    
- localizar inputs que los alimentan
    
- comprobar si se sanitizan
    

Cuando ese pipeline está roto, aparece XSS.

---

# Resumen

- Un sink es un punto donde datos se interpretan como HTML/JS
    
- Nuestro objetivo es detectar sinks y ver si reciben datos del usuario
    
- Podemos encontrarlos sin leer todo el código usando:
    
    - inspección del DOM
        
    - breakpoints
        
    - grep
        
    - instrumentación
        
    - heurísticas
        
- Los sinks más peligrosos son:
    
    - `innerHTML`
        
    - `outerHTML`
        
    - `document.write`
        
    - `jQuery.html()`
        
    - `v-html`
        

La clave de XSS moderno no es “tirar payloads”, sino **entender el flujo de datos hacia sinks inseguros**.

---
