
---

# AngularJS Sandbox Escape con CSP en un contexto de XSS reflejado

## Introducción

En este ejercicio analizamos un escenario avanzado donde conviven dos mecanismos de defensa: una política **Content Security Policy (CSP)** restrictiva y el **sandbox de AngularJS**. Nuestro objetivo es ejecutar un _cross-site scripting_ capaz de evadir ambas capas y obtener `document.cookie`.

La política CSP aplicada es:

```
content-security-policy: default-src 'self'; script-src 'self'; style-src 'unsafe-inline' 'self'
```

Esta política impide la ejecución de scripts externos y bloquea la mayor parte de cargas dinámicas. Por otro lado, AngularJS incorpora un sandbox interno que limita el acceso a objetos críticos como `window`, `document` o los prototipos nativos.

Para superar estas barreras combinamos técnicas específicas de **Client-Side Template Injection (CSTI)** en AngularJS con la manipulación de eventos del propio framework.

[Ver laboratorio Portswigger]([https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-without-strings](https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection/lab-angular-sandbox-escape-and-csp))

---

## Entorno del laboratorio

El laboratorio presenta:

- Un punto de inyección reflejado en un parámetro de búsqueda.
    
- AngularJS 1.x cargado en la aplicación.
    
- CSP estricta que impide insertar scripts convencionales.
    
- Evaluación de plantillas Angular dentro del documento, lo que nos permite inyectar expresiones.
    

Nuestro enfoque consiste en aprovechar un atributo Angular que ejecute una expresión al activarse un evento del navegador.

---

## Análisis de la superficie de ataque

AngularJS expone variables internas durante determinados eventos. En particular, dentro de un manejador como `ng-focus`, Angular nos proporciona el objeto `$event`, que contiene información completa del evento que ha ocurrido.

El método `composedPath()` disponible en muchos eventos devuelve una cadena de objetos que participaron en la propagación del evento. Dentro de esa cadena existe una ruta indirecta hacia el objeto `window`. Esa referencia no es bloqueada por el sandbox porque no accedemos explícitamente a `window`, sino que la obtenemos desde estructuras internas expuestas por el propio motor de Angular.

Esto nos permite construir una expresión que invoque código arbitrario sin violar de forma directa las restricciones del sandbox.

---

## Prueba de concepto inicial

Podemos validar que la superficie es explotable utilizando un payload de prueba basado en la cheat sheet de PortSwigger:

```
<input ng-focus=$event.composedPath()|orderBy:'(z=alert)(1)'>
```

Al activar el foco sobre el campo, la expresión ejecuta `alert(1)`. Esto confirma:

- Que Angular está evaluando la expresión proporcionada.
    
- Que el sandbox no impide la navegación hacia el contexto global.
    
- Que CSP no bloquea este vector, ya que todo ocurre dentro de atributos HTML permitidos.
    

---

## Construcción del payload final

Para resolver el laboratorio debemos provocar que la víctima cargue un payload que:

1. Se refleje en la aplicación objetivo.
    
2. Se evalúe como plantilla Angular.
    
3. Se ejecute cuando el usuario interactúe con el elemento.
    
4. Extraiga `document.cookie` mediante un escape funcional del sandbox.
    

El payload final que debemos enviar a la víctima tiene esta forma:

```html
<script>
location = 'https://0af300930466c67280f80330004e00a2.web-security-academy.net/?search=<input id=x+ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27>#x';
</script>
```

### Detalles importantes

- No usamos espacios: los sustituimos por `+` o `%20`.
    
- Las comillas simples se codifican como `%27` para no romper la URL.
    
- El `#x` hace que el navegador enfoque automáticamente el elemento con ID `x`, disparando el evento `ng-focus` sin intervención del usuario.
    
- La expresión `orderBy:(z=alert)(document.cookie)` ejecuta `alert(document.cookie)` dentro del contexto Angular.
    

---

## Ejecución final

Al visitar la URL manipulada, la víctima carga el parámetro `search` que contiene nuestro elemento malicioso. Angular lo interpreta como plantilla, el navegador aplica el foco al identificador `x` debido al fragmento `#x`, y el evento desencadena el escape del sandbox.

El resultado final es:

```
alert(document.cookie)
```

Superando simultáneamente:

- Las restricciones de CSP
    
- El sandbox de AngularJS
    
- La ausencia de scripts externos
    

---

## Conclusión

Hemos demostrado cómo, incluso en un entorno protegido con múltiples capas como CSP y el sandbox de AngularJS, es posible encadenar técnicas de plantilla, eventos y rutas internas del framework para obtener la ejecución arbitraria deseada. Este ejercicio muestra la importancia de no confiar exclusivamente en mecanismos de aislamiento del lado del cliente y reforzar la validación de entrada así como el control estricto de los contextos donde se procesan plantillas.

---
