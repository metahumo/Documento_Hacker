
---

# Hashes mágicos para Type Juggling en PHP

En PHP, algunos valores hash generados con funciones como `md5()` o `sha1()` pueden ser interpretados como números en notación científica si comienzan con `0e` seguido solo de dígitos. Esto puede llevar a vulnerabilidades si se usan comparaciones débiles (`==`), ya que PHP convierte ambas cadenas a números y las compara como `0`.

Estos hashes "mágicos" pueden ser utilizados en ataques de type juggling, especialmente para eludir autenticaciones que comparan hashes con `==`.

## Hashes mágicos conocidos (MD5)

A continuación, se listan algunos valores de entrada que generan hashes MD5 que cumplen esta condición:

| Entrada          | md5()                                       | Interpretación numérica |
|------------------|---------------------------------------------|--------------------------|
| `QNKCDZO`        | `0e830400451993494058024219903391`          | `0`                      |
| `240610708`      | `0e462097431906509019562988736854`          | `0`                      |
| `aabg7XSs`       | `0e087386482136013740957780965295`          | `0`                      |
| `aabC9RqS`       | `0e291040245093066250126642755113`          | `0`                      |

## Cómo comprobarlo en PHP

```php
<?php
$hash1 = md5("QNKCDZO"); // 0e830400451993494058024219903391
$hash2 = md5("240610708"); // 0e462097431906509019562988736854

if ($hash1 == $hash2) {
    echo "Comparación débil: TRUE (¡vulnerable!)";
} else {
    echo "Comparación débil: FALSE (correcto)";
}
?>
```

---
## Recomendaciones

- No usar `==` para comparar hashes. Siempre usar `===`.
    
- Usar `password_hash()` y `password_verify()` en lugar de funciones como `md5()` o `sha1()`.
    
- Validar adecuadamente todos los tipos de entrada antes de hacer comparaciones.
    

---
