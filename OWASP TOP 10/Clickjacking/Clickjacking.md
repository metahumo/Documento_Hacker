
---

# Clickjacking

## ¿Qué es el Clickjacking?

> El **Clickjacking** es una técnica en la que un atacante engaña a un usuario para que haga clic en un elemento **invisible o disfrazado** perteneciente a otra página web.  

El atacante incrusta la página legítima dentro de un **iframe oculto o transparente**, y coloca encima un contenido señuelo que induce al usuario a clicar.

El navegador del usuario ejecuta la acción pensando que hace clic en el contenido visible, pero realmente está interactuando con la página objetivo.

## ¿Cómo ocurre?

1. La aplicación objetivo permite ser cargada dentro de un **iframe externo** (falta de X-Frame-Options o Content-Security-Policy adecuada).
    
2. El atacante monta un sitio señuelo con un iframe transparente que muestra la página legítima detrás del contenido visible.
    
3. El usuario visita el sitio del atacante.
    
4. El usuario hace clic en un botón aparentemente inocente, pero el clic se transmite al iframe oculto, activando una acción sensible.
    

## Ejemplo realista

Un atacante quiere engañar al usuario para que elimine su cuenta en un sitio legítimo.  

El atacante incrusta la página de “Mi cuenta” dentro de un iframe transparente y coloca un botón “Haz clic para ganar” justo encima del botón real de “Eliminar cuenta”.

```html
<!-- Página señuelo del atacante -->
<html>
  <head>
    <style>
      iframe {
        width: 1500px;
        height: 800px;
        opacity: 0.001; /* Casi invisible */
        position: absolute;
        top: 0;
        left: 0;
      }

      .boton-señuelo {
        position: absolute;
        top: 520px;   /* Coordenadas alineadas con el botón real */
        left: 220px;
        background: #4CAF50;
        padding: 20px;
        font-size: 22px;
        color: white;
        cursor: pointer;
        border-radius: 8px;
      }
    </style>
  </head>

  <body>
    <div class="boton-señuelo">Click me</div>

    <!-- Página real cargada de fondo -->
    <iframe src="https://victima.com/my-account"></iframe>
  </body>
</html>
```

> El usuario cree que pulsa un botón inofensivo, pero realmente está haciendo clic sobre “Eliminar cuenta”, porque el iframe está perfectamente alineado debajo del señuelo.

## ¿Qué acciones podría forzar un atacante?

- Eliminar cuentas u otros recursos críticos
    
- Confirmar operaciones sensibles
    
- Enviar formularios peligrosos
    
- Activar funciones administrativas
    
- Cambiar configuraciones del usuario
    

En general, cualquier acción que dependa únicamente de un clic del usuario.

## ¿Cómo prevenir Clickjacking?

- **X-Frame-Options**: Impide que la página sea cargada en un iframe por sitios externos.  
    Valores comunes:
    
    - `DENY` → no permite iframes bajo ninguna circunstancia
        
    - `SAMEORIGIN` → solo permite iframes desde el mismo dominio
        
- **Content-Security-Policy (CSP)**, directiva `frame-ancestors`:  
    Controla qué sitios pueden incrustar la página.  
    Ejemplo seguro:
    
    ```
    Content-Security-Policy: frame-ancestors 'none';
    ```
    
- **Marcos de seguridad internos (UI hardening)**:
    
    - Botones que requieren múltiples pasos
        
    - Confirmaciones adicionales
        
    - Requiere interacción explícita del usuario (no solo un clic)
        
- **Tokens anti-CSRF + verificación de origen**, cuando el clickjacking se combina con solicitudes manipuladas.
    

---
