
---

# Explicación: Stored XSS en el atributo `href` de un `<a>` con comillas dobles HTML-encoded

En este documento describimos paso a paso la vulnerabilidad del laboratorio "Stored XSS into anchor href attribute with double quotes HTML-encoded".

[Ver laboratorio Portswigger](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded)
## Contexto del laboratorio

- Objetivo: encontrar y explotar una vulnerabilidad de Cross-Site Scripting almacenado en la funcionalidad de comentarios.
    
- Requisito para resolver el laboratorio: enviar un comentario de manera que, al hacer clic en el nombre del autor del comentario, se ejecute `alert(0)`.
    
- Peculiaridad observada: las comillas dobles en los atributos pueden estar codificadas en HTML en ciertas rutas, por lo que no siempre es posible inyectar código con un payload que dependa de `"` sin más.
    

## Función vulnerable observada

En la plantilla que renderiza los comentarios se muestra el autor como un enlace:

```html
<a id="author" href="https:test.com">test</a>
```

El objetivo es que el `href` del autor contenga un `javascript:` URL que ejecute código cuando el enlace sea activado por el usuario. Por ejemplo:

```html
<a id="author" href="javascript:alert(0)">test</a>
```

Si conseguimos que el valor de `href` sea `javascript:alert(0)`, entonces al hacer clic en el nombre del autor se ejecutará la alerta, resolviendo el laboratorio.

## Vectores de evasión y por qué funciona

1. El campo vulnerable (por ejemplo, "author name") puede almacenarse en la base de datos tal cual y luego renderizarse dentro del atributo `href` de un `<a>` sin el escaping contextual apropiado.
    
2. Si el servidor no valida o normaliza el valor antes de colocarlo en `href`, un atacante puede introducir un valor que comience con `javascript:`.
    
3. Al clicar en el enlace, el navegador ejecuta el esquema `javascript:` y evalúa la expresión que siga, permitiendo ejecutar `alert(0)`.
    

## Payload de ejemplo que resuelve el laboratorio

El payload que necesitamos almacenar en el nombre del autor del comentario es, por ejemplo:

```
javascript:alert(0)
```

Si el servidor inserta ese valor en el `href` de la plantilla, el HTML resultante será:

```html
<a id="author" href="javascript:alert(0)">test</a>
```

Al hacer clic en el enlace se ejecutará la alerta.

### Payloads alternativos

También podemos comentar el resto de la query `//` o cerrar la consulta con una `'`

```js
test';alert(0);//
```

```js
test';alert(0);'
```

Otra alternativa es usar el parámetro `let` para crear la variable. La idea en este caso y el primero de todos es cerrar la consulta para no cometer errores de sintaxis.

```js
test';alert(0); let testing='probando
```

## Proceso de explotación

1. Accedemos al formulario de comentarios del laboratorio.
    
2. En el campo del nombre del autor (o en el campo que se mapea a `href` en la plantilla), enviamos `javascript:alert(0)` como valor.
    
3. Confirmamos que el comentario se almacena y aparece en la página.
    
4. Inspeccionamos el HTML renderizado del comentario y verificamos que el `href` del `<a id="author">` contiene `javascript:alert(0)`.
    
5. Hacemos clic en el nombre del autor; si la alerta aparece, el laboratorio queda resuelto.
    

> Nota: en algunos casos el campo mostrado como texto (el contenido entre etiquetas `<a>...</a>`) puede ser distinto del atributo `href`; en estos laboratorios la plantilla suele usar el mismo valor para `href` o mapear un campo controlado por el usuario al `href`.

## Riesgos asociados

- La presencia de `javascript:` en atributos `href` permite la ejecución arbitraria de JavaScript en el contexto de la página, lo que puede conducir a robo de sesión, acciones en nombre del usuario, exfiltración de datos y más.
    
- Al tratarse de una vulnerabilidad almacenada (stored XSS), el código malicioso afecta a cualquier usuario que visualice el comentario.
    

## Mitigaciones y soluciones

Para eliminar este vector y proteger la aplicación debemos aplicar varias defensas en profundidad:

1. **No permitir esquemas peligrosos en `href`.**
    
    - Validar y normalizar los valores que se usan como `href` para permitir solo esquemas seguros como `http`, `https`, o rutas relativas. Rechazar o reescribir valores que empiecen por `javascript:`, `data:`, `vbscript:`, etc.
        
    
    Ejemplo de saneamiento sencillo (servidor):
    
    ```py
    # Pseudocódigo Python
    allowed_schemes = ['http', 'https', '']
    parsed = urlparse(user_input)
    if parsed.scheme not in allowed_schemes:
        # Rechazar o limpiar
        safe_href = '#'
    else:
        safe_href = user_input
    ```
    
2. **Escapar contextualmente al renderizar.**
    
    - Cuando se inserte contenido dentro de un atributo HTML, usar el escaping contextual apropiado (por ejemplo, `&quot;` para comillas, `&amp;` para ampersand).
        
3. **Separar datos y comportamiento.**
    
    - No usar directamente valores suministrados por usuarios como URLs ejecutables. Si queremos permitir enlaces, almacenarlos y validarlos en un campo concreto que acepte solo URLs seguras.
        
4. **Sanitizar entrada en origen.**
    
    - Validar en el servidor el formato de los campos que luego se usarán como `href`. Por ejemplo, exigir que coincidan con una expresión regular de URLs válidas con esquemas permitidos.
        
5. **Usar atributos `rel` y políticas adicionales.**
    
    - Enlaces que abren contenido externo deben usar `rel="noopener noreferrer"` y, si procede, `target="_blank"` con cuidado. Esto no evita XSS de `javascript:` pero reduce riesgos de navegación maliciosa.
        
6. **Escapar o bloquear `javascript:` en salida.**
    
    - Reescribir `javascript:` a un valor seguro o eliminarlo antes de imprimir en el HTML.
        

## Ejemplos de corrección

### Ejemplo 1 — Rechazar esquemas peligrosos (servidor)

```py
# Pseudocódigo
value = user_provided_href
if value.lower().strip().startswith('javascript:'):
    safe_href = '#'
else:
    safe_href = escape_attribute(value)
```

### Ejemplo 2 — Renderizado seguro en plantilla

```html
<!-- En la plantilla usamos una función que ya devuelve un href seguro -->
<a id="author" href="{{ safe_href }}">{{ safe_text }}</a>
```

Donde `safe_href` es el resultado de validar/normalizar `user_provided_href`.

## Recomendaciones finales

- Validar y normalizar siempre los URLs antes de usarlos en `href`.
    
- Prohibir explícitamente esquemas `javascript:` y otros esquemas no seguros en valores suministrados por usuarios.
    
- Aplicar escaping contextual al renderizar atributos HTML.
	

---
