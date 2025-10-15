
---

# Reflected XSS en atributo con paréntesis angulares HTML-encoded

En este documento describimos de forma pedagógica cómo funciona la vulnerabilidad reflejada en el buscador del laboratorio "Reflected XSS into attribute with angle brackets HTML-encoded" (nivel APPRENTICE).

[Ver laboratorio Portswigger](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded)

## Contexto del laboratorio

- Objetivo: encontrar y explotar una vulnerabilidad de Cross-Site Scripting reflejado en la funcionalidad de búsqueda del blog.
    
- Peculiaridad: los caracteres de paréntesis angulares `<` y `>` se codifican en HTML (por ejemplo `&lt;` y `&gt;`), por lo que un payload clásico con `<script>alert(0)</script>` queda neutralizado si se inserta tal cual en el valor del atributo.
    
- Información observada en el HTML de respuesta (tras enviar un parámetro `search`):
    

```html
<section class=search>
    <form action=/ method=GET>
        <input type=text placeholder='Search the blog...' name=search value=""&gt;&lt;script&gt;alert(0)&lt;/script&gt;">
        <button type=submit class=button>Search</button>
    </form>
</section>
```

Nótese que el valor del `value` contiene `"&gt;&lt;script&gt;alert(0)&lt;/script&gt;"`. Esto indica que el servidor ha escapado `<` y `>` convirtiéndolos en `&lt;` y `&gt;`, por lo que un script literal no se ejecutará directamente.

## Qué buscamos: inyección de atributo

Si la aplicación escapa los paréntesis angulares pero **no** evita que cerremos el atributo `value` y abramos uno nuevo, podemos inyectar un nuevo atributo HTML que dispare JavaScript en respuesta a un evento (por ejemplo `onmouseover`, `onfocus`, `onclick`, etc.).

Nuestro objetivo es forzar que el navegador interprete algo como:

```html
<input ... value="" onmouseover="alert(0)">
```

Con esto, al mover el ratón sobre el campo de búsqueda se ejecuta `alert(0)`, lo que prueba la XSS reflejada dentro de un atributo.

## Pruebas observadas

- Inyección codificada (neutralizada por escape de `<>`):
    

```html
<input type=text placeholder='Search the blog...' name=search value=""&gt;&lt;script&gt;alert(0)&lt;/script&gt;">
```

- Prueba de cierre del atributo y nuevos atributos (demostración de que podemos romper el `value`):
    

```html
<input type=text placeholder='Search the blog...' name=search value=""test="probando">
```

Este último ejemplo muestra que al inyectar `"test="probando` conseguimos cerrar el atributo `value` y añadir un nuevo atributo `test`, lo cual demuestra que la cadena inyectada se interpreta dentro del HTML y **no** queda totalmente neutralizada.

## Payload que resuelve el laboratorio

El payload que permite escapar la sanitización y ejecutar la alerta al pasar el ratón por encima es:

```js
" onmouseover="alert(0)
```

Si el parámetro `search` contiene exactamente esa cadena, el HTML resultante será algo equivalente a:

```html
<input type="text" name="search" value="" onmouseover="alert(0)">
```

Al desplazar el cursor sobre el campo de búsqueda se disparará el `onmouseover` y aparecerá la alerta, resolviendo así el laboratorio.

## Explicación técnica de por qué funciona

1. El servidor aplica escaping a `<` y `>`, por lo que inyectar directamente etiquetas `<script>` no tiene efecto.
    
2. Sin embargo, el servidor **inserta el contenido del parámetro `search` dentro del atributo `value` sin escapar las comillas** que permiten cerrar el atributo.
    
3. Al introducir `"` (comilla doble) al principio del payload cerramos el `value` original.
    
4. A continuación añadimos un nuevo atributo `onmouseover="alert(0)` que el navegador interpretará como un manejador de eventos activo.
    
5. Dado que `<>` están escapados pero las comillas y el resto no, conseguimos ejecutar JavaScript sin necesitar `<` ni `>` en el payload.
    

## Pasos típicos para reproducir 

1. En la aplicación vulnerable, enviar una petición GET con el parámetro `search` igual a `" onmouseover="alert(0)`.
    
2. Inspeccionar la respuesta HTML y verificar que el `input` resultante contiene un nuevo atributo `onmouseover` con `alert(0)`.
    
3. Interactuar con el campo (mover el ratón sobre él) para comprobar la ejecución de la alerta.
    


## Mitigaciones y soluciones

Para evitar este tipo de XSS reflejado dentro de atributos recomendamos aplicar las siguientes medidas:

1. Escapar correctamente las comillas dentro de atributos HTML. Cuando se inserte texto en un atributo entre comillas dobles `"..."`, hay que escapar las comillas dobles del contenido (por ejemplo `"` → `&quot;`).
    
    - En el ejemplo, si el servidor transformara `"` en `&quot;`, nuestro payload `" onmouseover="alert(0)` quedaría como `&quot; onmouseover=&quot;alert(0)` y no cerraría el atributo.
        
2. Usar encoding contextual apropiado. Dependiendo del contexto (atributo, HTML, JavaScript, URL) debe usarse el escaping correcto y no un escaping genérico.
    
3. Validación por whitelist. Si el parámetro `search` solo debe contener ciertos caracteres (por ejemplo palabras, números, espacios y guiones), validar con una whitelist y rechazar el resto.
    
4. Construir atributos desde el servidor de forma segura, preferiblemente usando APIs/frameworks que manejen el escaping automáticamente en plantillas (por ejemplo motores de templates que aplican escaping contextual).
    
5. Evitar renderizar directamente input user-controlled en atributos cuando sea posible. Considerar usar `textContent` o `value` asignado por JavaScript con valores sanitizados en lugar de inyectar en el HTML de la plantilla.
    
6. Evitar handlers inline (como `onmouseover="..."`) y usar en su lugar listeners añadidos desde código JavaScript controlado por la aplicación, preferiblemente con valores validados.
    

## Ejemplo de corrección (servidor)

Si la aplicación está en un entorno donde controlamos la generación del HTML, asegurarnos de escapar comillas dobles al renderizar el atributo `value`:

```html
<!-- Incorrecto (vulnerable) -->
<input type="text" name="search" value="{{ user_input }}">

<!-- Correcto (escapando comillas) -->
<input type="text" name="search" value="{{ user_input | escape_html_attribute }}">
```

En muchos frameworks `escape_html_attribute` es una función o filtro que transforma `"` en `&quot;`, `&` en `&amp;`, etc.

## Recomendaciones finales

- Aplicar escaping contextual completo (incluyendo comillas dentro de atributos).
    
- Adoptar validación por whitelist para parámetros de búsqueda y otros inputs.
    
- Revisar plantillas y librerías para asegurarse de que hacen escaping contextual.
    

---

