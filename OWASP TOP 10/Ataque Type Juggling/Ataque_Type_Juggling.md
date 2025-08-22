# Ataque Type Juggling (Cambio de Tipo)

## Introducción

El **Type Juggling**, o **cambio de tipo**, es una técnica de ataque que aprovecha la conversión automática de tipos de datos en lenguajes como **PHP**. Como desarrolladores o pentesters, debemos ser conscientes de que si no validamos correctamente los tipos de datos que recibe una aplicación, podríamos introducir una vulnerabilidad seria.

## ¿Qué es el Type Juggling?

Los lenguajes como PHP realizan conversiones de tipo de forma **implícita**. Esto significa que, si no lo controlamos, PHP puede transformar automáticamente una cadena en un número, un booleano en entero, etc., dependiendo del contexto de la operación.

Un atacante puede explotar esta conversión automática para hacer que el programa **interprete un valor de forma diferente a la que nosotros esperábamos**, y así saltarse validaciones, autenticaciones o lógica de aplicación.

## Ejemplo práctico: Comparación de contraseñas en PHP

Supongamos que tenemos el siguiente código PHP:

```php
<?php
$stored_password = "0e123456789"; // Supuesta contraseña en texto plano

if ($_POST["password"] == $stored_password) {
    echo "Acceso concedido";
} else {
    echo "Acceso denegado";
}
?>
```

Ahora bien, un atacante envía como entrada:

```
password = "0e987654321"
```

Aunque `"0e123456789"` y `"0e987654321"` **no son iguales como cadenas**, PHP **las interpreta como números en notación científica** cuando hace una comparación débil (`==`), convirtiéndolas a `0 * 10^123456789` y `0 * 10^987654321`, lo que da como resultado `0`.

Entonces:

```php
"0e123456789" == "0e987654321"  // TRUE en comparación débil
```

Esto le permite al atacante **burlar la autenticación sin conocer la contraseña**.

## ¿Por qué ocurre esto?

PHP, cuando usa `==` (comparación débil), hace lo siguiente:

- Si ambos operandos son cadenas **y se parecen a números**, los convierte en números.
    
- Entonces compara los números.
    

Por eso `"0e123"` y `"0e999"` se convierten a `0` y, por tanto, son considerados iguales.

Si hubiéramos usado el operador de comparación estricta (`===`), esto no habría sucedido:

```php
"0e123456789" === "0e987654321" // FALSE, porque compara tipo y valor
```

## Ejemplo real: Vulnerabilidad en CMS y aplicaciones PHP

Esta vulnerabilidad ha afectado a múltiples CMS y sistemas que:

- Generan **hashes de contraseñas débiles** (por ejemplo, usando `md5()` o `sha1()` sin sal).
    
- Usan la función `==` en lugar de `===` para comparar hashes.
    

Por ejemplo, si una aplicación compara el hash de la contraseña con `==`, y un hash generado comienza por `"0e..."`, el atacante puede buscar otro valor que también genere un hash que comience por `"0e..."` y lograr acceso.

### Prueba de concepto real

```php
<?php
$input = "QNKCDZO";
$hash = md5($input);  // 0e830400451993494058024219903391

if ($hash == "0e123456789123456789") {
    echo "Acceso concedido";
} else {
    echo "Acceso denegado";
}
?>
```

Aquí, el hash generado por `md5("QNKCDZO")` es `0e830400451993494058024219903391`, que PHP interpreta como `0`. Comparado con cualquier otra cadena que comience con `"0e..."`, también se interpreta como `0`, y la comparación será `TRUE`.

## Buenas prácticas para evitar Type Juggling

- Usar **comparación estricta** (`===`) siempre que sea posible.
    
- Validar y sanitizar todos los datos de entrada.
    
- Usar funciones de hashing modernas como `password_hash()` y `password_verify()` en PHP.
    
- Evitar que los hashes se parezcan a números (por ejemplo, usando hashes base64 o binarios en vez de hexadecimales).
    

## Conclusión

Como profesionales de la ciberseguridad o del desarrollo, debemos entender que **PHP hace conversiones de tipo automáticamente**, y esto puede tener consecuencias graves si no lo controlamos. El ataque de Type Juggling es un claro ejemplo de cómo algo tan simple como no usar `===` en lugar de `==` puede derivar en una brecha de seguridad.

---
