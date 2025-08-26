
---

# Definición

> El archivo **`xmlrpc.php`** en Joomla permite la comunicación remota entre el sitio y otras aplicaciones mediante el protocolo **XML-RPC**. Su propósito es habilitar funciones como la publicación remota de contenido y la integración con aplicaciones externas.

## Explotación en Ciberseguridad

Este archivo es conocido por sus vulnerabilidades y ha sido explotado en varios ataques, como:

- **Brute Force Amplificado**: Permite probar múltiples combinaciones de usuario y contraseña en una sola solicitud, evadiendo mecanismos de detección.
    
- **Pingback DDoS**: Se usa para abusar de la función de pingbacks y reflejar tráfico en ataques DDoS.
    
- **Ejecución de Código Remoto (RCE)**: En versiones antiguas o con extensiones vulnerables, puede llevar a la ejecución de comandos en el servidor.
    

Si este archivo está habilitado y accesible, representa un vector de ataque importante en Joomla

----
## Ejemplo de explotación

Si quisiéramos aplicar fuerza bruta en un [Joomla](Joomla.md)., tras haber detectado al archivo **xmlrpc.php** como accesible, del mismo modo que lo hace [Joomscan](Joomscan.md) pero de forma manual para descubrir credenciales válidas. Sería necesario tramitar una petición por el método POST al archivo **xmlrpc.php** tramitando una estructura XML como se muestra a continuación:

```xml
POST /xmlrpc.php HTTP/1.1
Host: example.com
Content-Length: 235

<?xml version="1.0" encoding="UTF-8"?>
<methodCall> 
<methodName>system.listMethods</methodName> 
<params> 
<param><value>usuario</value></param> 
<param><value>contraseña</value></param> 
</params> 
</methodCall>
```

---
