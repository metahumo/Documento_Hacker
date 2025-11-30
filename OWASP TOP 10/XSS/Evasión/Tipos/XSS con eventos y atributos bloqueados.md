
---

# XSS en entorno con eventos y atributos href bloqueados

## Introducción

En este ejercicio trabajamos en un entorno donde la aplicación solo permite un conjunto limitado de etiquetas HTML. Los atributos de eventos (como `onclick`) y los atributos `href` en enlaces están explícitamente bloqueados, lo que elimina muchos de los vectores clásicos de XSS. Nuestro objetivo consiste en ejecutar una función `alert()` cuando el usuario haga clic en nuestro elemento inyectado.

Para superar las restricciones, aprovechamos la capacidad del navegador para interpretar elementos SVG y sus animaciones internas. Aunque el filtrado impide el uso directo de eventos JavaScript, ciertos atributos gráficos de SVG permanecen permitidos y pueden modificarse dinámicamente.

[Ver laboratorio Portswigger](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-event-handlers-and-href-attributes-blocked)

---

## Entorno del laboratorio

El laboratorio presenta:

- Un punto de inyección reflejado.
    
- Un filtro restrictivo que solo permite etiquetas concretas.
    
- Bloqueo de todos los atributos de evento.
    
- Bloqueo del atributo `href` en enlaces convencionales.
    

Aun así, se mantiene el soporte completo de SVG, incluyendo elementos interactivos y animaciones que alteran atributos permitidos.

---

## Superficie de ataque

Los filtros aplicados impiden vectores tradicionales como:

- `<a href="javascript:...">`
    
- `<img src=x onerror=alert(1)>`
    
- `<div onclick=...>`
    

Sin embargo, cuando trabajamos dentro de un SVG, ciertos elementos poseen atributos que se pueden modificar mediante animaciones. La etiqueta `<animate>` permite alterar dinámicamente el valor de otro atributo. Si ese atributo modificado es `href` y la animación está dentro de un `<a>` de SVG, el navegador reinterpretará la nueva ruta como un enlace legítimo, ejecutando el esquema `javascript:` cuando el usuario haga clic.

Este comportamiento no está bloqueado por el filtrado del laboratorio, ya que la modificación del atributo ocurre dentro del SVG y no mediante un atributo `href` directamente escrito en el HTML.

---

## Construcción del payload

Para resolver el laboratorio se combina:

- Un contenedor `<svg>` aceptado por el filtro.
    
- Un enlace SVG `<a>` sin atributo `href` inicial.
    
- Una animación `<animate>` que modifica el atributo `href`.
    
- Un texto visible que induce al usuario a hacer clic.
    

El payload final es:

```
<svg><a><animate attributeName=href values=javascript:alert(0) /><text x=30 y=30>Click me!</text></a>
```

### Explicación del payload

- `<svg>`: Permite usar elementos gráficos y animaciones.
    
- `<a>`: Define un enlace interactivo dentro del SVG.
    
- `<animate>`: Cambia el valor de `href` en tiempo real.
    
- `attributeName=href`: Indica que queremos modificar el `href`.
    
- `values=javascript:alert(0)`: Inyecta un esquema ejecutable cuando el usuario hace clic.
    
- `<text>`: Muestra el mensaje "Click me!" que el laboratorio exige.
    

Cuando la animación se procesa, el atributo `href` del enlace se convierte en `javascript:alert(0)`. Al hacer clic en el texto, el navegador ejecuta la llamada a `alert`.

---

## Ejecución y resolución

Tras inyectar el payload en el parámetro vulnerable, la aplicación lo refleja dentro del documento. El navegador interpreta el SVG sin restricciones y aplica la animación que modifica el `href` del enlace. Una vez que el usuario simulado hace clic en el texto "Click me!", se ejecuta:

```
alert(0)
```

Con esto se resuelve el laboratorio.

---

## Conclusión

Este ejercicio demuestra cómo, incluso cuando los atributos de eventos y los `href` están bloqueados, es posible evadir las restricciones mediante el uso creativo de estructuras SVG. Las animaciones permiten modificar dinámicamente atributos que serían filtrados si se escribieran directamente en HTML. Esto evidencia la necesidad de aplicar validaciones robustas que no se limiten únicamente al filtrado superficial de atributos, sino que tengan en cuenta las capacidades completas del DOM y de los elementos gráficos avanzados como SVG.

---