
---

# Reflected XSS con  personalizadas permitidas


[Ver laboratorio Portswigger](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-html-context-with-all-standard-tags-blocked)

## Contexto del laboratorio

- Descripción: el laboratorio bloquea todas las etiquetas HTML normales salvo **etiquetas personalizadas** (custom elements).
    
- Objetivo: inyectar una etiqueta personalizada que, de forma automática al cargarse la página, ejecute `alert(document.cookie)` (o `alert(0)` para demostración) sin usar etiquetas estándar como `<script>` o `<img>` (porque están bloqueadas).
    
- Técnica principal: aprovechar que las etiquetas personalizadas se permiten y que podemos añadir atributos de manejador de eventos inline (por ejemplo `onfocus`) y atributos que hagan que el elemento reciba foco (por ejemplo `tabindex="1"`). Luego forzamos el comportamiento que desencadene el evento (por ejemplo navegando a un fragmento `#id` o de otra forma enfocando el elemento) para provocar la ejecución.
    

---

## Qué probamos y por qué funciona

Probamos en el buscador esta cadena y funciona como inyección:

```html
<etiqueta onfocus=alert(0) tabindex=1>test
```

Explicación de los componentes:

- `<etiqueta ...>`: una etiqueta personalizada (no es una etiqueta HTML estándar). El laboratorio permite estas etiquetas.
    
- `onfocus=alert(0)`: manejador inline que ejecuta JavaScript cuando el elemento recibe foco.
    
- `tabindex=1`: hace que el elemento sea focalizable mediante teclado/JS; algunos navegadores requieren que el elemento tenga `tabindex` para poder recibir foco programáticamente o al navegar por fragmentos.
    
- `>test`: contenido visible para que el elemento exista en la página.
    

Para pasar esto al objetivo (es decir, inyectarlo en el parámetro de búsqueda y abrir la página de forma que la ejecución ocurra automáticamente) usamos el siguiente payload que navega a la URL objetivo con el parámetro `search` que contiene la etiqueta inyectada y añade un fragmento dirigido al `id` del elemento inyectado:

```html
<script>
location = 'https://0a1f003303e5d5ed807e714600c30097.web-security-academy.net/?search=<etiqueta id=identificador onfocus=alert(0) tabindex=1>#identificador';
</script>
```

Cómo encaja todo:

1. La URL incluye en `?search=` la etiqueta personalizada con `id=identificador`, `onfocus=alert(0)` y `tabindex=1`.
    
2. Cuando la página objetivo procesa `search` y la refleja en el HTML (en un contexto donde las etiquetas personalizadas no están filtradas), el DOM resultante contiene:
    
    ```html
    <etiqueta id="identificador" onfocus="alert(0)" tabindex="1">...</etiqueta>
    ```
    
3. La parte final de la URL `#identificador` navega al fragmento con ese id. En muchos navegadores, navegar a un fragmento con `#id` puede provocar que el elemento reciba foco o al menos que sea seleccionado; combinado con `tabindex` y el comportamiento del navegador, el elemento pasa a tener foco y se dispara el `onfocus`.
    
4. Resultado: `alert(0)` (o `alert(document.cookie)`) se ejecuta automáticamente tras la carga.
    

Nota: la forma exacta en que el fragmento `#identificador` provoca foco puede variar entre navegadores; `tabindex` aumenta la probabilidad de que el elemento sea focalizable y que navegaciones por fragmento o scripts del cliente acaben activando el evento. En algunos laboratorios también se usan pequeñas acciones adicionales (p. ej. añadir `autofocus` si estuviera disponible para custom elements, o ejecutar un pequeño script que haga `document.getElementById('identificador').focus()` cuando sea permitido).

---

## Riesgo y por qué es relevante

- Aunque el servidor bloquee etiquetas estándar, permitir etiquetas personalizadas sin filtrar **y** permitir atributos inline (como `onfocus`) abre vectores claros de XSS.
    
- Los manejadores inline (`on*`) ejecutan JavaScript en el contexto de la página; si pueden inyectarse a través de datos reflejados o almacenados, se consigue ejecución remota de código.
    
- Esto es especialmente peligroso cuando el payload ejecuta `alert(document.cookie)` porque revela información sensible de sesión o contexto.
    

---

## Pasos  para reproducir (resumen)

1. Construir la URL con el parámetro `search` que contenga la etiqueta personalizada con `id`, `onfocus` y `tabindex`.
    
2. Navegar a la URL con además el fragmento `#id` para forzar que el elemento objetivo sea seleccionado/enfocado.
    
3. Verificar que al cargar la página se dispara la alerta (o que en herramientas como Burp se observa el HTML reflejado con la etiqueta inyectada y el atributo `onfocus`).
    

---

## Mitigaciones recomendadas

Para evitar este tipo de XSS incluso cuando se quiera permitir cierta flexibilidad en etiquetas:

1. **Escapar/filtrar atributos peligrosos**: si se permiten etiquetas personalizadas, **prohibir o filtrar atributos que puedan ejecutar código**, especialmente los atributos `on*` (`onfocus`, `onclick`, `onerror`, etc.).
    
2. **Whitelist de etiquetas y atributos**: en vez de bloquear por blacklist, usar una whitelist estricta de etiquetas y atributos permitidos. Si una etiqueta no está en la whitelist, renderizarla como texto (`&lt;...&gt;`) o eliminarla.
    
3. **Sanitización robusta**: usar librerías probadas (por ejemplo DOMPurify) para sanitizar cualquier HTML generado a partir de entrada de usuario, configuradas para negar atributos inline ejecutables.
    
4. **Evitar reflejar HTML sin saneamiento**: si no es imprescindible, **no reflejar** contenido HTML a partir de parámetros GET/POST; mostrar siempre texto escapado.
    
5. **Content Security Policy (CSP)**: aplicar CSP que desactive `unsafe-inline` y limite `script-src` a orígenes de confianza. Aunque no sustituye el escaping, reduce la capacidad de ejecutar JS inyectado.
    
6. **Hacer que elementos personalizados no sean focalizables por defecto**: si se crean custom elements en la aplicación, diseñarlos para no ejecutar código en eventos inline y para no ser focalizables a menos que sea necesario y seguro.
    
7. **Validación en origen**: validar y normalizar entradas en el servidor (por ejemplo, restringir longitud, caracteres, o negar cualquier string que contenga `on` seguido de un evento o patrones sospechosos).
    

---

## Conclusión

- Permitir únicamente etiquetas normales no garantiza seguridad si se permiten etiquetas personalizadas sin control.
    
- El vector aquí es simple y elegante: usar una etiqueta permitida por la política, añadir un manejador inline y forzar su activación (foco) para ejecutar JS.
    
- La defensa correcta combina validación en servidor, sanitización contextual y políticas en el cliente (CSP y diseño de custom elements) para minimizar la superficie de ataque.
    

---
