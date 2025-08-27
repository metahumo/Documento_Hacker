
---

# CVE-2025-29927: Next.js Middleware Authorization Bypass

## Descripción de la vulnerabilidad

CVE-2025-29927 afecta a versiones de Next.js anteriores a:
- 12.3.5
- 13.5.9
- 14.2.25
- 15.2.3

El bug permite a un atacante **bypasear el middleware** insertando un header HTTP llamado `x-middleware-subrequest` con un valor especialmente diseñado (`middleware:middleware:middleware:middleware:middleware`).  

Esto hace que la aplicación ignore las comprobaciones de seguridad implementadas en el middleware, incluyendo autenticación y autorización, y responda con contenido protegido aunque no estemos logueados.

## ¿Qué es `x-middleware-subrequest`?

> `x-middleware-subrequest` es un **encabezado (header) interno** que utiliza Next.js para manejar llamadas recursivas al middleware, evitando bucles infinitos durante solicitudes internas. Su propósito legítimo es gestionar internamente rutas que vuelven a invocar el middleware. Lo esencial es que fue pensado para uso interno del framework, **no para aceptar valores externos** de usuarios o atacantes.

---

## Prueba de concepto

En condiciones ideales (sin WAF ni CDN), podemos probarlo interceptando una petición con BurpSuite a una ruta protegida, por ejemplo `/admin`:

1. Interceptamos la petición original al acceder a la ruta.
2. Añadimos el header:
```

x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware

```
3. Reenviamos la petición desde Burp Repeater.
4. Observamos la respuesta:
   - Si antes devolvía `302` o `403` y ahora devuelve `200 OK` con contenido protegido, el bypass funciona.
   - Si no hay cambio, el CMS no es explotable desde nuestra posición.

---

## Consideraciones del entorno

Al analizar la web `https://www.<URL_bugcrowd.com`, observamos:

- La aplicación está detrás de **CloudFront**, que bloquea muchas solicitudes automatizadas.
- Se han producido respuestas **HTTP 429 Too Many Requests** y **HTTP 403 Forbidden** al intentar fuzzing o incluso enviar el header malicioso.
- Esto indica que **el WAF/CDN filtra o bloquea cualquier intento de enviar `x-middleware-subrequest` desde fuera**, haciendo inviable la explotación externa.

---

## Conclusión

- El CMS puede ser vulnerable en teoría si alguien tuviera acceso directo al servidor sin pasar por CloudFront.
- Desde Internet público, **la vulnerabilidad no es explotable** debido a la protección por CDN/WAF.
- Documentamos este CVE como parte de nuestro **repositorio de hallazgos**, indicando tanto el vector como la viabilidad real de explotación.

---

## Referencias

- [NVD CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927)
- [SecurityLabs Datadog: Next.js Middleware Auth Bypass](https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/)
- [Zscaler Blog: CVE-2025-29927](https://www.zscaler.com/blogs/security-research/cve-2025-29927-next-js-middleware-authorization-bypass-flaw)

---
