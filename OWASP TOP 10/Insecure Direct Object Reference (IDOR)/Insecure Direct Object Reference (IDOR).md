# Insecure Direct Object Reference (IDOR)

Las vulnerabilidades del tipo **Insecure Direct Object Reference (IDOR)** ocurren cuando una aplicación permite el acceso directo a objetos internos (como archivos, registros, u otros identificadores) sin verificar adecuadamente si el usuario tiene autorización para acceder a ellos. En otras palabras, la aplicación confía en que el cliente está autorizado simplemente por haber proporcionado un identificador válido.

## ¿Por qué ocurre?

Esta situación se da comúnmente cuando la aplicación utiliza identificadores predecibles o secuenciales en la URL, formularios o parámetros, y no implementa controles de autorización en el servidor. Como consecuencia, un atacante puede modificar estos identificadores para acceder a datos de otros usuarios.

## ¿Cómo lo explotamos?

Podemos modificar directamente los parámetros de una URL o los valores en una petición, buscando acceder a objetos que no nos pertenecen. Esta técnica no requiere necesariamente autenticación previa si el recurso es público, aunque a menudo ocurre en contextos autenticados donde la autorización está mal implementada.

---

## Ejemplo práctico

Supongamos que estamos autenticados como el usuario `alice` y accedemos a la siguiente URL:

```

[https://example.com/profile?user_id=1001](https://example.com/profile?user_id=1001)

```

Podemos ver nuestra propia información. Pero si modificamos el parámetro a:

```

[https://example.com/profile?user_id=1002](https://example.com/profile?user_id=1002)

```

Y el servidor nos muestra información de otro usuario (por ejemplo, `bob`), sin verificar si tenemos permiso para verla, entonces la aplicación es vulnerable a IDOR.

---

## Ejemplo realista

En una aplicación de gestión de pedidos online, al ver el historial de compras, recibimos una URL como esta:

```

[https://tienda.com/pedidos/4891](https://tienda.com/pedidos/4891)

```

Este número corresponde al pedido del usuario actual. Si probamos con:

```

[https://tienda.com/pedidos/4892](https://tienda.com/pedidos/4892)

```

Y el servidor devuelve los datos del pedido de otro cliente, la aplicación está permitiendo el acceso a objetos internos (los pedidos) sin comprobar que el usuario realmente tiene derecho a verlos. Esto puede llevar a fugas de información sensibles como direcciones, datos de pago, productos comprados, etc.

---

## ¿Cómo lo prevenimos?

Para evitar vulnerabilidades IDOR, debemos implementar **controles de autorización en el servidor** que verifiquen, en cada solicitud, que el usuario tiene permiso para acceder al recurso solicitado. Además, podemos:

- Utilizar identificadores no predecibles (UUIDs o hashes en lugar de números secuenciales).
- Validar la autorización en todas las rutas y puntos de entrada.
- No confiar en que el cliente nunca modificará los parámetros.
- Realizar revisiones de seguridad y pruebas de penetración regularmente.

---

## Conclusión

Las vulnerabilidades IDOR son simples pero peligrosas. Como atacantes, las buscamos cuando vemos patrones predecibles en URLs o formularios. Como defensores, debemos asegurar que **todas las referencias a objetos estén protegidas por controles de autorización robustos y centralizados**.

---

```bash
wfuzz -c -X POST -z range,1-1500 -d'pdf_id=FUZZ' http://localhost:5000/download
```

```bash
wfuzz -c -X POST --hl=101,104 -z range,1-1500 -d'pdf_id=FUZZ' http://localhost:5000/download
```