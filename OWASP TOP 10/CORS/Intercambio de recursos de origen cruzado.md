
---
# Intercambio de Recursos de Origen Cruzado (CORS)

## ¿Qué es CORS?

El Intercambio de Recursos de Origen Cruzado (CORS) es un mecanismo que permite que un servidor web restrinja el acceso a recursos desde diferentes orígenes, es decir, desde dominios o protocolos distintos. Esto se hace para proteger la privacidad y seguridad de los usuarios, evitando que sitios web no autorizados accedan a información confidencial sin permiso.

## Cómo funciona CORS

Supongamos que tenemos una aplicación web en el dominio `example.com` que consume una API en `api.example.com`. Si configuramos CORS correctamente, la API solo permitirá solicitudes desde `example.com`. Si una página de otro dominio, como `attacker.com`, intenta hacer una petición a la API, el navegador la bloqueará por seguridad.

Sin embargo, si la configuración de CORS es débil o errónea, un atacante podría aprovechar esta vulnerabilidad para acceder a recursos sensibles.

---

## Ejemplo práctico

Imaginemos que la API en `api.example.com` responde con el header:

```

Access-Control-Allow-Origin: *

````

Esto significa que acepta solicitudes desde cualquier dominio. Si inyectamos un script en un sitio malicioso, este podría hacer peticiones a la API y obtener datos sensibles del usuario que esté autenticado en `example.com`.

---

## Ejemplo realista

Un atacante crea un sitio web en `evil.com` y convence a un usuario para que lo visite mientras está autenticado en `example.com`. Debido a que la API acepta solicitudes de cualquier origen, el sitio `evil.com` puede hacer peticiones a `api.example.com` y robar información personal del usuario o realizar acciones en su nombre.

---

# Cómo detectar y explotar configuraciones incorrectas de CORS

## 1. Pruebas manuales con curl

Podemos probar diferentes orígenes en la cabecera `Origin` para verificar la respuesta del servidor.

Ejemplo de comando para probar:

```bash
curl -i -H "Origin: http://evil.com" -X OPTIONS https://api.example.com/endpoint
````

Observamos el header `Access-Control-Allow-Origin` en la respuesta. Si devuelve `http://evil.com` o `*`, la configuración puede ser insegura.

---

## 2. Uso de Burp Suite para pruebas automáticas

En Burp Suite, interceptamos una petición hacia la API y modificamos el header `Origin` a un dominio controlado por nosotros, por ejemplo, `http://evil.com`. Luego enviamos la petición y analizamos la respuesta.

Si el servidor responde con `Access-Control-Allow-Origin: http://evil.com` o `*`, la configuración es vulnerable a ataques de CORS.

También podemos usar el plugin **CORS Scanner** de Burp para automatizar esta búsqueda.

---

## 3. Herramientas automatizadas

Existen scripts y herramientas como **corsy** o **Corscanner** que automatizan la detección de configuraciones erróneas en CORS realizando múltiples pruebas con diferentes valores en el header `Origin`.

---

# Técnicas comunes de explotación

- **Robo de credenciales:** Si el servidor permite orígenes arbitrarios, un atacante puede capturar cookies o tokens de autenticación y enviar solicitudes en nombre de la víctima.
    
- **Modificación de datos:** El atacante puede enviar peticiones para modificar recursos protegidos si la API no valida adecuadamente la autorización, explotando la confianza del navegador.
    
- **Cross-Site Script Inclusion:** Incluir recursos de manera maliciosa para ejecutar código o realizar ataques de tipo Cross-Site Scripting (XSS) indirectos.
    

---

# Cómo prevenir vulnerabilidades CORS

- Configurar el header `Access-Control-Allow-Origin` con dominios específicos y confiables, evitando el uso del comodín `*` especialmente si se usan credenciales.
    
- No permitir solicitudes con credenciales (`Access-Control-Allow-Credentials: true`) desde orígenes no verificados.
    
- Validar siempre la autorización del usuario en el backend, no depender solo de CORS para controlar acceso.
    
- Implementar políticas de seguridad adicionales como Content Security Policy (CSP) para mitigar ataques derivados.
    

---

# Resumen

El mecanismo CORS es vital para la seguridad en aplicaciones web modernas, pero una mala configuración puede abrir puertas para ataques que comprometan la confidencialidad y la integridad de los datos. Como pentesters, debemos probar exhaustivamente las configuraciones CORS y reportar cualquier debilidad.

---

