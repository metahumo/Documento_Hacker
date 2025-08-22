
---
# Enumeración y explotación de JSON Web Tokens (JWT)

Los JSON Web Tokens (JWT) son un mecanismo comúnmente utilizado para autenticar y autorizar usuarios en aplicaciones web modernas. Como equipo que realiza tareas ofensivas de ciberseguridad, debemos entender cómo se generan, validan y qué vulnerabilidades pueden presentar.

Un JWT consta de tres partes codificadas en Base64 separadas por puntos: el encabezado (header), el cuerpo o carga útil (payload) y la firma (signature). Estas partes contienen información que puede ser manipulada o mal validada, lo cual nos abre la puerta a diversas técnicas de ataque.

## Enumeración de JWT

En la fase de enumeración, buscamos entender cómo la aplicación maneja los JWT. Podemos interceptar tokens válidos y estudiar su estructura para ver si incluyen información sensible, como el nombre de usuario o su rol. También intentamos predecir o forzar la clave de firma mediante fuerza bruta, diccionarios o exploiting de algoritmos débiles.

Una técnica común consiste en cambiar el algoritmo de la firma en el header de `HS256` a `none`, lo cual desactiva la validación de la firma si el backend no lo controla correctamente.

### Ejemplo práctico

Supongamos que trabajamos en un entorno de laboratorio y obtenemos este JWT tras autenticarnos:

```

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRvbWFzIiwicm9sZSI6InVzZXIifQ.TlXzI23lF9Z8HJqAZxlNi5yHkQeS34zLxDpThyoTICQ

```

1. Decodificamos el token (sin necesidad de la clave):
   ```bash
   echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
   echo "eyJ1c2VybmFtZSI6InRvbWFzIiwicm9sZSI6InVzZXIifQ" | base64 -d
```

2. Observamos que el rol es `user`. Probamos modificarlo a `admin`:
    
    ```json
    {
      "alg": "none",
      "typ": "JWT"
    }
    ```
    
    ```json
    {
      "username": "tomas",
      "role": "admin"
    }
    ```
    
3. Reempaquetamos el token sin firma (usando `jwt_tool`, BurpSuite o manualmente) y lo enviamos a la aplicación. Si el backend no valida la firma, obtenemos privilegios elevados.
    

Este tipo de prueba muestra una implementación insegura del estándar JWT.

## Explotación de JWT

Una vez que descubrimos cómo se construyen los tokens y si se validan mal, podemos falsificarlos para suplantar identidades o escalar privilegios.

Entre las formas de explotación más comunes se encuentran:

- Cambio del algoritmo a `none`.
    
- Descubrimiento de la clave secreta (brute-force).
    
- Firmar tokens con una clave pública si el backend espera una clave privada.
    
- Reutilización de tokens expirados o tokens antiguos que no han sido revocados.
    

### Caso real: Auth0 (2017)

En 2017, se descubrió una vulnerabilidad en ciertas bibliotecas de JWT que permitía cambiar el algoritmo de `RS256` a `HS256`. El atacante podía usar la clave pública como si fuera la clave secreta para firmar tokens válidos.

Esto permitía a un atacante generar tokens arbitrarios y autenticarse como cualquier usuario. El error se debía a una incorrecta validación del algoritmo y la clave de firma.

Este caso muestra cómo una mala implementación, incluso en servicios ampliamente utilizados, puede comprometer la autenticación de una aplicación completa.

## Buenas prácticas defensivas

Como parte de nuestra documentación y entrenamiento, debemos tener en cuenta cómo mitigar estos vectores de ataque. Las medidas incluyen:

- Validar siempre la firma del token.
    
- No aceptar el algoritmo `none`.
    
- Usar claves secretas suficientemente largas y seguras.
    
- Usar algoritmos asimétricos (`RS256`), si es posible.
    
- Rotar las claves periódicamente.
    
- Establecer expiraciones cortas para los tokens.
    
- Verificar los claims críticos, como `exp`, `iss` o `aud`.
    

## Conclusión

Comprender cómo funcionan los JWT y sus debilidades nos permite identificar posibles puntos de explotación en sistemas que dependen de ellos para la autenticación. El estudio de casos reales, junto con entornos prácticos, fortalece nuestras capacidades como analistas ofensivos para detectar y explotar errores en la implementación de este estándar.

---
