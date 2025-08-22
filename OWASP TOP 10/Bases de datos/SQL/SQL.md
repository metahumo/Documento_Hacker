# ¿Qué es SQL?

## Definición

>SQL (**Structured Query Language** o **Lenguaje de Consulta Estructurado**) es un lenguaje de programación diseñado para gestionar y manipular bases de datos relacionales. Permite realizar operaciones como consultar, insertar, actualizar y eliminar datos.

---

## Características Principales
- **Lenguaje declarativo**: Se centra en qué datos obtener y no en cómo obtenerlos.
-  **Manejo de grandes volúmenes de datos**: Usado en sistemas de bases de datos de gran escala.
-  **Estandarizado**: Utilizado por múltiples sistemas de bases de datos como MySQL, PostgreSQL, SQL Server, y Oracle.
-  **Consultas complejas**: Permite combinaciones de datos a través de `JOINs` y subconsultas.
-  **Seguridad**: Ofrece control de acceso y permisos de usuario.

---

## Estructura de una Base de Datos Relacional

Una base de datos SQL se compone de **tablas**, que contienen **filas (registros)** y **columnas (atributos)**.

**Ejemplo de una tabla `usuarios`**:

| id  | nombre | email          | edad |
| --- | ------ | -------------- | ---- |
| 1   | Juan   | juan@mail.com  | 30   |
| 2   | María  | maria@mail.com | 25   |
| 3   | Pedro  | pedro@mail.com | 28   |

---

## Comandos Básicos de SQL

### `SELECT` - Consultar datos
```sql
SELECT nombre, email FROM usuarios;
```
- Obtiene los nombres y correos electrónicos de todos los usuarios.

### `INSERT` - Insertar datos
```sql
INSERT INTO usuarios (nombre, email, edad) VALUES ('Alodia', 'alodia@mail.com', 22);
```
- Agrega un nuevo usuario a la tabla.

### `UPDATE` - Actualizar datos
```sql
UPDATE usuarios SET edad = 26 WHERE nombre = 'María';
```
- Cambia la edad de María a 26 años.

### `DELETE` - Eliminar datos
```sql
DELETE FROM usuarios WHERE nombre = 'Pedro';
```
- Borra a Pedro de la tabla.

### `CREATE TABLE` - Crear una nueva tabla
```sql
CREATE TABLE productos (
    id INT PRIMARY KEY,
    nombre VARCHAR(100),
    precio DECIMAL(10,2)
);
```
- Crea una tabla `productos` con columnas para `id`, `nombre` y `precio`.

---

## SQL en la Ciberseguridad: Inyección SQL
Una de las vulnerabilidades más comunes en aplicaciones web es la [[SQLi]], que ocurre cuando un atacante manipula consultas SQL para acceder o modificar datos no autorizados.

**Ejemplo de una consulta vulnerable:**
```sql
SELECT * FROM usuarios WHERE nombre = ' ' OR '1'='1';
```
- Devuelve todos los usuarios sin importar el nombre.

### Cómo prevenirlo:
- Usar **consultas preparadas** con `?` o `bind_param()`.
- Validar y filtrar entradas del usuario.
- Aplicar **principios de menor privilegio** en la base de datos.

---

## Conclusión
SQL es un lenguaje esencial para la gestión de bases de datos, pero su mal uso puede llevar a vulnerabilidades graves. Es fundamental aprender a usarlo correctamente y aplicar medidas de seguridad para evitar ataques como la [[SQLi]].

