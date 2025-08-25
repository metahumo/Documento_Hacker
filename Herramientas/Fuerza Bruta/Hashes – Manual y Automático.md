
---

# Crackeo de Hashes – Manual y Automático

Este documento explica cómo identificar y crackear hashes paso a paso, entendiendo lo que ocurre por debajo. También incluye cómo extraer hashes desde archivos `.db` como los encontrados en retos de CTF o plataformas como HTB.

---

## Paso 1 – Identificar tipo de hash

Antes de intentar crackear, identifica qué tipo de hash es. Puedes usar herramientas como:

```bash
hashid hash.txt
hash-identifier
```

También puedes hacerlo visualmente:

- `$6$` → SHA-512 (`/etc/shadow`)
- `$1$` → MD5 crypt
- 32 caracteres → probablemente MD5
- 40 caracteres → SHA1
- 64 caracteres → SHA256
- Empieza por `$argon2` → Argon2

---

## Paso 2 – Crear diccionarios personalizados

Puedes generar tus propias wordlists con `crunch`:

```bash
crunch 6 12 abcdef123456 -o wordlist.txt
```

O usar combinaciones típicas como:

- `usuario + año`
- `Nombre + 123`
- `ContraseñaComún + símbolo`

También puedes modificar wordlists existentes con reglas:

```bash
john --wordlist=rockyou.txt --rules --stdout > combinaciones.txt
```

---

## Paso 3 – Crackeo con John o Hashcat

### [Jhon The Ripper](Jhon%20The%20Ripper.md)

```bash
john --wordlist=wordlist.txt hashes.txt --format=raw-sha256
```

Formatos comunes:
- `raw-md5`
- `raw-sha1`
- `raw-sha256`
- `bcrypt`
- `sha512crypt`

### [Hashcat](Hashcat.md)

```bash
hashcat -m 0 hash.txt wordlist.txt       # MD5
hashcat -m 100 hash.txt wordlist.txt     # SHA1
hashcat -m 1400 hash.txt wordlist.txt    # SHA256
```

Para ver más formatos:

```bash
hashcat --help
```

---

## Paso 4 – Deshasheo en Python (manual)

Pequeño script para probar hashes a mano:

```python
import hashlib

hash_to_crack = "5f4dcc3b5aa765d61d8327deb882cf99"  # MD5 de "password"

with open("wordlist.txt", "r") as f:
    for word in f:
        word = word.strip()
        if hashlib.md5(word.encode()).hexdigest() == hash_to_crack:
            print(f"Hash encontrado: {word}")
            break
```

Puedes adaptarlo para SHA1, SHA256, etc.

---

## Extra: Extraer hashes de una base de datos `.db`

### Opción 1 – Usando SQLite3

```bash
sqlite3 nombre.db
.tables
.schema users
SELECT username, password FROM users;
```

Extraer directamente desde terminal:

```bash
sqlite3 nombre.db "SELECT username || ':' || password FROM users;" > john_hashes.txt
```

Esto genera un archivo listo para `john` con el formato:

```
usuario:hash
```

### Opción 2 – Python

```python
import sqlite3

conn = sqlite3.connect('nombre.db')
cursor = conn.cursor()

cursor.execute("SELECT username, password FROM users")
for row in cursor.fetchall():
    print(f"{row[0]}:{row[1]}")
```

Puedes guardar esa salida en un archivo y luego usarla en tus herramientas.

---
