# Payloads XSS - Contextualizados por Categoría

---

## 1. Stored XSS en atributo href
- **Estructura:** `href="javascript:..."`
- **Contexto:** El payload se inserta en el atributo `href` de un enlace `<a>`, permitiendo la ejecución de código JavaScript al hacer clic.
- **Ejemplo de estructura:**
  - `href="javascript:alert(0)"`
  - Variantes: añadir comentarios o cerrar la consulta con `'` para manipular la sintaxis.

---

## 2. DOM XSS en AngularJS Expression
- **Estructura:** `{{constructor.constructor('...')()}}`
- **Contexto:** Inyección en expresiones AngularJS, aprovechando el motor de evaluación de expresiones para ejecutar código arbitrario.
- **Ejemplo de estructura:**
  - `{{constructor.constructor('alert(1)')()}}`

---

## 3. Stored DOM XSS en comentarios
- **Estructura:** Etiqueta HTML con evento inline
- **Contexto:** El comentario almacenado se inserta en el DOM y ejecuta código mediante eventos como `onerror` en una etiqueta `<img>`.
- **Ejemplo de estructura:**
  - `<img src=0 onerror=alert(0)>`
  - Puede ir precedido de `<>` para evadir sanitizadores ingenuos.

---

## 4. DOM XSS con jQuery y evento hashchange
- **Estructura:** Etiqueta HTML inyectada en el fragmento hash
- **Contexto:** El fragmento hash de la URL se concatena en un selector jQuery sin escape, permitiendo inyectar etiquetas con eventos.
- **Ejemplo de estructura:**
  - `#<img src=x onerror=alert(1)>`

---

## 5. DOM XSS en document.write dentro de un elemento
- **Estructura:** Cierre de etiquetas y script
- **Contexto:** Un parámetro de la URL se inserta en un `<select>` mediante `document.write`, permitiendo romper la estructura y ejecutar un `<script>`.
- **Ejemplo de estructura:**
  - `</option></select><script>alert(0)</script>`

---

## 6. Reflected DOM XSS con eval()
- **Estructura:** Inyección en JSON reflejado y ejecutado con eval
- **Contexto:** El valor reflejado en la respuesta JSON permite cerrar la estructura y ejecutar código arbitrario cuando se evalúa con `eval()`.
- **Ejemplo de estructura:**
  - `"*alert(0)}//"` (rompe la cadena y ejecuta código)

---

## 7. Reflected XSS con etiquetas personalizadas
- **Estructura:** Etiqueta personalizada con evento y foco
- **Contexto:** Se permite inyectar etiquetas no estándar con atributos de evento y foco para ejecutar código al recibir foco.
- **Ejemplo de estructura:**
  - `<etiqueta onfocus=alert(0) tabindex=1>`
  - Variante con `id` y navegación a fragmento para forzar el foco.

---

## 8. Reflected XSS en cadena JavaScript
- **Estructura:** Cierre de cadena y ejecución de código
- **Contexto:** El valor reflejado se inserta en una cadena JavaScript, permitiendo cerrar la cadena y ejecutar código.
- **Ejemplo de estructura:**
  - `';alert(0); var test='probando`

---

## 9. Reflected XSS en atributo con paréntesis angulares HTML-encoded
- **Estructura:** Cierre de atributo y nuevo atributo con evento
- **Contexto:** El valor reflejado permite cerrar el atributo y añadir uno nuevo que ejecuta código al disparar un evento.
- **Ejemplo de estructura:**
  - `" onmouseover="alert(0)`

---

> **Nota:** Los payloads aquí listados muestran la estructura y el contexto de explotación, no el valor literal. Cada uno debe adaptarse a la situación concreta y a los mecanismos de filtrado/sanitización presentes en la aplicación objetivo.
