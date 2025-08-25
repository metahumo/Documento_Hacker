
---

# Laboratorio: Cracking de hashes del `/etc/shadow` usando wordlists

---

## Contexto

Los hashes de las contraseñas en `/etc/shadow` están protegidos con algoritmos como SHA-512, bcrypt, etc. Para recuperar la contraseña original, podemos usar técnicas de fuerza bruta o ataque por diccionario con herramientas especializadas. Este archivo puede listarse con una mala asignación de privilegios [SUID](../../Técnicas/Escalada%20de%20privilegios/SUID.md)

Las wordlists como `rockyou.txt` o las de SecLists son colecciones de contraseñas comunes que se usan para intentar adivinar la contraseña.

---

## Paso 1: Obtener el hash de usuario

Ejemplo de línea en `/etc/shadow`:

```
Metahumo:$y$j9T$pj9vEFTNDP4fTkirodqZ2/$cWUpXzVaKXv3ZuG//.KZGft47WfALFI.Acee7HBXjy8:20253:0:99999:7:::
```

Aquí:

- `Metahumo` es el usuario.
    
- `$y$j9T$...` es el hash cifrado (en este caso, puede ser un hash tipo yescrypt).
    

---

## Paso 2: Elegir la herramienta para cracking

Las más comunes son:

- **John the Ripper** (`john`)
    
- **Hashcat**
    

---

## Paso 3: Preparar el archivo de hashes

Para John, extraemos las líneas que queremos atacar y las guardamos en un archivo, por ejemplo:

```bash
cat /etc/shadow | grep Metahumo > hashes.txt
```

O simplemente creas un archivo `hashes.txt` con el contenido del hash.

---

## Paso 4: Ataque con John the Ripper usando rockyou.txt

### Acción:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

- `--wordlist` indica la wordlist a usar.
    
- `hashes.txt` es el archivo con los hashes.
    

---

## Paso 5: Ataque con John the Ripper usando SecLists

Si quieres probar otra wordlist más grande o específica:

```bash
john --wordlist=/usr/share/SecLists/Passwords/rockyou.txt hashes.txt
```

O alguna lista más específica, por ejemplo:

```bash
john --wordlist=/usr/share/SecLists/Passwords/Leaked-Databases/rockyou-10.txt hashes.txt
```

---

## Paso 6: Consultar contraseñas crackeadas

```bash
john --show hashes.txt
```

Esto mostrará las contraseñas que se hayan crackeado.

---

## Notas importantes

- John detecta automáticamente el tipo de hash en muchos casos, si no, hay que especificarlo con `--format`.
    
- El éxito depende de la fortaleza de la contraseña y la calidad de la wordlist.
    
- También se puede usar Hashcat para cracking con GPU, pero la sintaxis es diferente.
    

---

## Resumen

1. Extraemos el hash del `/etc/shadow`.
    
2. Guardamos el hash en un archivo.
    
3. Usamos John the Ripper con las wordlists `rockyou.txt` o SecLists para intentar descifrar la contraseña.
    
4. Revisamos los resultados.
    

---
