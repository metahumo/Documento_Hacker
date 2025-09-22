
---

# urlencode

En este documento explicamos cómo usar un script sencillo para codificar payloads con URL-encoding (una y dos pasadas), su utilidad en pruebas de seguridad web y presentamos el código completo con comentarios línea a línea.

## Resumen

Usamos este script cuando necesitamos enviar **payloads** (por ejemplo para XSS, LFI, path traversal o fuzzing) a través de parámetros de URL y queremos:

* Evitar que ciertos filtros o validaciones detecten caracteres especiales.
* Garantizar que el payload viaje intacto dentro de una URL.
* Probar técnicas de **double encoding** para evadir filtros/WA F que descodifican una vez.

El script toma una entrada del usuario (el payload) y devuelve dos versiones: codificada una vez y codificada dos veces.

---

## Cómo usarlo

1. Guardamos el script en un fichero, por ejemplo `urlencode.py`.
2. Le damos permisos de ejecución (opcional):

```bash
chmod +x urlencode.py
```

3. Lo ejecutamos:

```bash
./urlencode.py
python3 urlenconde.py
```

4. Introducimos el payload cuando se nos pida. Ejemplos de payloads:

* `"<script>alert(1)</script>"` (XSS)
* `"../etc/passwd"` (path traversal / LFI check)
* `"' OR '1'='1"` (payload SQL en parámetros URL)

5. El script mostrará dos líneas: la versión URL-encoded una vez y la versión URL-encoded dos veces.

---

## Ejemplo práctico

Payload: `<script>alert(1)</script>`

Salida esperada:

* Codificado 1x: `%3Cscript%3Ealert%281%29%3C%2Fscript%3E`
* Codificado 2x: `%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E`

**Por qué puede interesarnos**: si una aplicación o WAF descodifica automáticamente la URL una vez (o el navegador lo hace), el payload doblemente codificado podría llegar al punto de ejecución tras una o dos descodificaciones.

---

## Precauciones y ética

* Solo usaremos estas técnicas en **entornos autorizados**: laboratorios, máquinas propias o pruebas con permiso explícito (bug bounty con autorización, pruebas de clientes con contrato, etc.).
* El uso malintencionado contra sistemas sin permiso es ilegal.
* Estas transformaciones no "explotan" por sí solas una vulnerabilidad: facilitan el transporte/obfuscación del payload. Siempre combinamos con un análisis de la aplicación objetivo.

---

## Código completo (comentado)

```python
#!/usr/bin/env python3

# Importamos el módulo `urllib.parse` que contiene utilidades
# para manipular y codificar componentes de URLs.
import urllib.parse as url


def urlencode_payload():
    """
    Función principal: pide al usuario un payload y muestra
    su versión URL-encoded una y dos veces.
    """

    # Pedimos el payload al usuario usando input(). Usamos f-string
    # para mostrar el prompt con un pequeño prefijo.
    payload = input(f"\n[+] Introduzca el payload: ")

    # `url.quote` codifica caracteres especiales para que sean seguros
    # dentro de un componente de URL. Por ejemplo '<' -> '%3C'.
    # Esta es la codificación estándar (una sola pasada).
    encoded_once = url.quote(payload)

    # Si aplicamos `quote` de nuevo sobre la cadena ya codificada,
    # obtenemos la versión doblemente codificada. Esto es útil para
    # escenarios donde el sistema receptor descodifica la URL una
    # vez antes de procesarla; con doble encoding podemos "esconder"
    # el payload tras una capa adicional de codificación.
    encoded_twice = url.quote(encoded_once)

    # Mostramos las salidas por consola. Dejamos líneas en blanco
    # para mejorar la legibilidad.
    print(f"\n[!] Payload URL-encoded: {encoded_once}\n")
    print(f"\n[!] Payload URL-encoded (2x): {encoded_twice}\n")


# Punto de entrada del script: si se ejecuta directamente, llamamos
# a la función principal. Esto permite también importar el archivo
# como módulo en otros scripts sin ejecutar la función automáticamente.
if __name__ == "__main__":
    urlencode_payload()
```

---

## Posibles mejoras que podríamos implementar

* Añadir opción de leer el payload desde un archivo o argumento de línea de comandos (argparse) para integración con scripts automatizados.
* Añadir soporte para codificación específica de componentes (por ejemplo `quote_plus`) si queremos convertir espacios en `+` en lugar de `%20`.
* Permitir varias pasadas de codificación mediante un parámetro `-n` (n veces).
* Añadir una opción de decodificar para comprobar qué obtiene el servidor tras una o dos descodificaciones (`urllib.parse.unquote`).

---
