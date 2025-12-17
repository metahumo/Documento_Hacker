
---

# Tabla Sources vs Sinks para Bug Bounty

## Introducción

En bug bounty no basta con saber qué es un XSS. Necesitamos **sistematizar el análisis** para identificar rápidamente combinaciones peligrosas de sources y sinks.

Esta tabla sirve como **checklist mental** durante reconocimiento y explotación de DOM XSS.

---

## Tabla Sources vs Sinks

|Source (origen del dato)|Ejemplo|Sink típico|Impacto|
|---|---|---|---|
|`location.search`|`?q=test`|`innerHTML`|DOM XSS reflejado|
|`location.hash`|`#<img>`|`innerHTML`|DOM XSS sin request|
|`postMessage`|`e.data`|`innerHTML`|XSS cross-origin|
|`localStorage`|`getItem()`|`innerHTML`|XSS persistente|
|`sessionStorage`|`getItem()`|`outerHTML`|XSS persistente|
|`window.name`|valor arbitrario|`document.write`|XSS persistente|
|`document.referrer`|URL atacante|`innerHTML`|XSS indirecto|
|Cookie accesible|`document.cookie`|`eval()`|XSS crítico|
|Respuesta API|JSON no validado|`innerHTML`|XSS indirecto|
|Atributos HTML|`data-*`|`innerHTML`|XSS almacenado|
|Parámetros POST|body|`jQuery.html()`|DOM XSS|
|Variables JS globales|`window.user`|`innerHTML`|XSS lógico|

---

## Cómo usar esta tabla en práctica

Nuestra metodología es:

1. Identificar **sources presentes en la aplicación**
    
2. Buscar **sinks peligrosos en runtime**
    
3. Cruzar ambos mentalmente
    
4. Priorizar combinaciones críticas
    

No necesitamos probar todo.  
Necesitamos probar **lo que conecta**.

---

## Combinaciones de alto valor en bug bounty

Especialmente interesantes:

- `postMessage` → `innerHTML`
    
- `localStorage` → `innerHTML`
    
- API JSON → `innerHTML`
    
- `window.name` → `document.write`
    

Estas suelen:

- pasar desapercibidas
    
- romper modelos de seguridad asumidos
    
- permitir encadenamiento con clickjacking o CSRF
    

---

## Señales de alerta durante el análisis

Pensamos siempre:

- ¿De dónde viene este dato?
    
- ¿Puede otro actor controlarlo?
    
- ¿Acaba en HTML interpretado?
    

Si las respuestas encajan, **no estamos ante un input inocente**.

---

## Conclusión

El éxito en DOM XSS no está en el payload. Está en **cruzar correctamente sources y sinks**.

Esta tabla no es teórica:

- se usa durante reconocimiento
    
- se usa durante triage
    
- se usa para justificar impacto en reportes
    

Si dominamos este cruce, dominamos el XSS moderno en bug bounty.

---