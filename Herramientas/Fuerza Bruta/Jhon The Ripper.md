
---
# Laboratorio: Cracking de hashes con John the Ripper

---

## Contexto

John the Ripper es una herramienta muy popular para cracking de contraseñas. Permite atacar hashes almacenados en `/etc/shadow` usando ataques de diccionario con wordlists como `rockyou.txt` o colecciones más amplias como SecLists.

---

## Paso 1: Preparar el archivo con hashes

Extraemos los hashes que queremos atacar y los guardamos en un archivo, por ejemplo:

```bash
cat /etc/shadow | grep Metahumo > hashes.txt
````

---

## Paso 2: Ejecutar John the Ripper con una wordlist

Usamos la wordlist `rockyou.txt` para intentar descifrar la contraseña:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

O usando una wordlist de SecLists más extensa:

```bash
john --wordlist=/usr/share/SecLists/Passwords/rockyou.txt hashes.txt
```

---

## Paso 3: Ver resultados

Para consultar las contraseñas que John ha crackeado:

```bash
john --show hashes.txt
```

---

## Explicación

- John detecta automáticamente el tipo de hash de la mayoría de sistemas.
    
- El comando `--wordlist` indica la lista de posibles contraseñas a probar.
    
- La efectividad depende de la fortaleza de la contraseña y de la wordlist utilizada.
    

---

## Recomendaciones

- Mantener actualizadas y personalizadas las wordlists según el contexto.
    
- Probar distintos modos de ataque, como combinaciones o reglas de mutación.
    
- Realizar auditorías periódicas de seguridad para detectar hashes débiles.
    

---

## Comandos útiles adicionales

- Para acelerar o cambiar el modo de ataque:
    

```bash
john --rules --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

- Para especificar el tipo de hash si no es detectado:
    

```bash
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

---

# Resumen

John the Ripper es una herramienta flexible y potente para crackear hashes locales, ideal para auditorías de seguridad en sistemas Linux.

---
