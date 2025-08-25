
---
### Cheat Sheet: John the Ripper

```bash
cat /etc/shadow | grep usuario > hashes.txt
# Extraer hashes específicos del archivo /etc/shadow

john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
# Cracking básico con wordlist rockyou.txt

john --rules --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
# Cracking con reglas para mutar la wordlist

john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
# Especificar el tipo de hash SHA-512

john --show hashes.txt
# Mostrar contraseñas crackeadas

john --status
# Ver estado del cracking en ejecución

john --restore
# Restaurar sesión de cracking interrumpida
```

---

### Cheat Sheet: Hashcat

```bash
cat /etc/shadow | grep usuario > hashes.txt
# Extraer hashes específicos del archivo /etc/shadow

hashcat -m 1800 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
# Cracking con modo 1800 (SHA-512-crypt) y wordlist rockyou.txt

hashcat -m 1800 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
# Cracking con reglas para mutar la wordlist

hashcat -m 1800 --show hashes.txt
# Mostrar contraseñas crackeadas

hashcat --status
# Ver estado del cracking en ejecución

hashcat --restore
# Restaurar sesión de cracking interrumpida

hashcat -d 1 -m 1800 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
# Usar GPU con id 1 para el cracking
```

---
