
---
- Tags: #web #vulnerabilidades #script 
---
# Vulnerabilidad XSS (Cross-Site Scripting)

## ¿Qué es un ataque XSS?

XSS (Cross-Site Scripting) es una vulnerabilidad de seguridad que permite a un atacante inyectar código malicioso en una página web. Cuando un usuario visita la página afectada, su navegador ejecuta el código sin darse cuenta. Esto puede permitir el robo de datos personales, como credenciales de acceso o información sensible.

## ¿Cómo funciona?

El atacante inserta código malicioso (generalmente JavaScript) en un sitio web vulnerable. Cuando otro usuario accede a la página, el código se ejecuta en su navegador sin que lo note. Dependiendo del ataque, esto puede usarse para:

- Robar cookies de sesión.
    
- Registrar pulsaciones de teclas.
    
- Redirigir a páginas falsas para robar credenciales.
    
- Mostrar contenido fraudulento.
    

## Tipos de XSS

1. **XSS Reflejado (Reflected XSS)**
    
    - Ocurre cuando el sitio web incluye datos proporcionados por el usuario en la respuesta sin validarlos correctamente.
        
    - Un atacante engaña a la víctima para que haga clic en un enlace que contiene código malicioso.
        
2. **XSS Almacenado (Stored XSS)**
    
    - El código malicioso se guarda en la base de datos del sitio web.
        
    - Cada vez que un usuario carga la página, el código se ejecuta en su navegador.
        
3. **XSS basado en DOM (DOM-Based XSS)**
    
    - La inyección ocurre dentro del navegador del usuario, cuando el JavaScript del sitio web manipula el DOM de forma insegura.
        
    - No necesita interacción directa con el servidor.
        

## ¿Cómo prevenir XSS?

Para evitar ataques XSS, los desarrolladores deben:

- **Validar y sanitizar** todos los datos de entrada del usuario.
    
- **Escapar caracteres especiales** para evitar la ejecución de scripts (`<`, `>`, `'`, `"`, `&`).
    
- **Utilizar Content Security Policy (CSP)** para restringir la ejecución de scripts no autorizados.
    
- **Evitar el uso de `innerHTML`** en JavaScript y usar alternativas más seguras como `textContent`.
    

XSS es una vulnerabilidad común, pero con buenas prácticas de seguridad puede prevenirse de manera efectiva.