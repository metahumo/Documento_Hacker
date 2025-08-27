

---

# Fuzzing de Endpoints de API con Wfuzz

En esta sección explicamos cómo utilizamos **Wfuzz** para descubrir endpoints de una API que podrían no estar documentados públicamente, usando una lista de rutas comunes de APIs.

## Comando utilizado

```bash
wfuzz -c -z file,/usr/share/SecLists/Discovery/Web-Content/api/api-endpoints.txt --hc 404 -H "Cookie: Authorization=tu_token; 20min-Session=tu_session" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0" -H "Referer: https://sitio-ejemplo.com/" https://api-ejemplo.com/FUZZ
````

## Desglose del comando

- `wfuzz`: Ejecutamos Wfuzz, una herramienta de fuzzing para aplicaciones web y APIs.
    
- `-c`: Mostramos la salida en color para facilitar la lectura.
    
- `-z file,/usr/share/SecLists/Discovery/Web-Content/api/api-endpoints.txt`: Definimos la lista de payloads que se usarán para fuzzear, en este caso un archivo con endpoints de API comunes.
    
- `--hc 404`: Ocultamos todas las respuestas que devuelvan un **404 Not Found**, así filtramos las rutas inexistentes.
    
- `-H "Cookie: Authorization=tu_token; 20min-Session=tu_session"`: Añadimos cabeceras de cookies para mantener la sesión autenticada y poder acceder a endpoints protegidos.
    
- `-H "User-Agent: Mozilla/5.0 ..."`: Definimos un User-Agent válido para simular un navegador real y evitar bloqueos automáticos.
    
- `-H "Referer: https://sitio-ejemplo.com/"`: Definimos el encabezado Referer para que algunas políticas de seguridad del servidor lo acepten.
    
- `https://api-ejemplo.com/FUZZ`: URL objetivo. La palabra clave `FUZZ` será reemplazada por cada línea de nuestro archivo de endpoints, probando rutas como `/login`, `/profile`, `/settings`, etc.
	

## Puntos clave para fuzzing seguro

- `--hc 404`: Oculta rutas inexistentes para centrarnos en resultados válidos.
    
- Cookies y tokens: Mantienen la sesión activa y evitan bloqueos por autenticación.
    
- `User-Agent` y `Referer`: Simulan tráfico legítimo de navegador, evitando WAF básico.
    
- Tasa de peticiones: Podemos controlar la velocidad usando `--delay X` (ej. `--delay 0.5`) para no sobrecargar el servidor ni levantar alertas.
    
- FUZZ: Cada línea del archivo `api-endpoints.txt` se prueba como posible endpoint.
## Objetivo

Con este comando buscamos:

1. Identificar endpoints de la API que no estén documentados.
    
2. Filtrar las rutas inexistentes automáticamente para centrarnos en las que devuelven respuesta válida.
    
3. Mantener la autenticación y las cabeceras necesarias para no ser bloqueados por la protección de la API (cookies de sesión, tokens, User-Agent, Referer).
    
4. Generar un mapa inicial de la API que luego podremos analizar en detalle para buscar posibles vulnerabilidades.
    

Este enfoque nos permite optimizar el tiempo, evitando probar rutas al azar y centrando nuestros esfuerzos en rutas que realmente existen y son accesibles desde nuestra sesión.

---
