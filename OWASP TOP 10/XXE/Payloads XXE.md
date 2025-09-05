
# Tipos de payloads para XXE (Inyección de Entidad Externa XML)

En esta guía explicamos los distintos tipos de **payloads XXE** que podemos utilizar, cómo funcionan y en qué escenarios aplicarlos.

---

## 1. Recuperación de archivos (File Retrieval)

**¿Qué buscamos?** Acceder al sistema de archivos del servidor y leer archivos sensibles, por ejemplo `/etc/passwd`.

**Payload típico:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<stockCheck>
  <productId>&xxe;</productId>
</stockCheck>
````

* Definimos una entidad externa `xxe` que apunta al archivo deseado.
* Luego inyectamos `&xxe;` en un campo que el servidor devuelve en la respuesta — obtenemos el contenido del archivo. ([PortSwigger][1])

---

## 2. SSRF (Server-Side Request Forgery vía XXE)

**¿Qué buscamos?** Inducir al servidor que realice una petición HTTP a un recurso interno o externo al que normalmente no podemos acceder.

**Payload típico:**

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/">
]>
<data>
  &xxe;
</data>
```

* La entidad `xxe` apunta a una URL interna.
* Si el servidor incluye el contenido de esa entidad en su respuesta, obtenemos dos vías de ataque (respuesta visible y posible interacción adicional). ([PortSwigger][1])

---

## 3. XXE Ciego (Blind XXE) y Exfiltración Out-of-Band

**¿Qué buscamos?** Extraer datos sin que el servidor nos los devuelva directamente; usar comunicación secundaria hacia un servidor controlado por nosotros.

**Técnicas comunes:**

* Utilizar una entidad que haga una petición hacia nuestro servidor externo. Podemos detectarlo con una herramienta como Burp Collaborator.
* Otra variante: provocar errores de parsing XML que filtren datos sensibles en los mensajes de error. ([PortSwigger][1])

---

## 4. Recuperación de datos vía errores (Error-based XXE)

**¿Qué buscamos?** Hacer que ocurra un fallo en el análisis XML y que el mensaje de error incluya información sensible.

* Inyectamos entidades que, al fallar, revelan datos a través de la traza de errores.
* Es una subvariante del XXE ciego, orientada a forzar errores que filtren información. ([PortSwigger][1])

---

## 5. XInclude (Inclusión XML)

**¿Qué buscamos?** Manipular documentos que incorporan fragmentos XML externos mediante la funcionalidad XInclude.

**Payload típico:**

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

* Usamos el namespace `xi` y la directiva `xi:include`.
* Útil cuando no podemos definir un `DOCTYPE`, pero sí podemos inyectar datos en documentos que serán integrados en un XML más grande. ([PortSwigger][1])

---

## 6. XXE vía subida de archivos (file upload)

**¿Qué buscamos?** Aprovechar formatos que contienen XML (como SVG o DOCX) en interfaces de subida de archivos.

* Subimos un archivo SVG malicioso que contiene una entidad XXE.
* El backend lo procesa y ejecuta el payload, incluso si el usuario no esperaba enviar XML explícitamente. ([PortSwigger][1])

---

## 7. Cambio de Content-Type (modified content type)

**¿Qué buscamos?** Engañar al servidor para que trate un request como XML cuando normalmente no lo haría.

* Convertimos un formulario normal (`application/x-www-form-urlencoded`) en un body tipo `text/xml`.
* Si el servidor procesa el XML, podemos inyectar una entidad y explotar XXE, aunque la interfaz no lo soporte abiertamente. ([PortSwigger][1])

---

## Resumen comparativo

| Tipo de Payload              | Objetivo principal                           | Técnica clave                                         |
| ---------------------------- | -------------------------------------------- | ----------------------------------------------------- |
| File Retrieval               | Leer archivos desde el servidor              | DOCTYPE + entidad externa → inclusión en respuesta    |
| SSRF vía XXE                 | Hacer que el servidor acceda a URLs internas | DOCTYPE con URL externa → interacción vía HTTP        |
| Blind XXE / OOB Exfiltración | Obtener datos indirectamente o por error     | Peticiones a nuestro servidor / errores XML           |
| Error-based XXE              | Filtrar datos mediante errores XML           | Provocar fallo y capturar mensaje de error            |
| XInclude                     | Incluir archivos externos sin DOCTYPE        | Etiqueta `xi:include` con href local                  |
| File upload (SVG, DOCX)      | Entrar via formatos XML embebidos            | Subida de archivo malicioso que el servidor procesará |
| Modified Content-Type        | Forzar análisis XML en endpoint no XML       | Cambiar tipo de contenido y enviar XML                |

---

[1]: https://portswigger.net/web-security/xxe "What is XXE (XML external entity) injection? Tutorial & Examples | Web Security Academy"
