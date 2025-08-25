
---

# Laboratorio: Cracking de hashes con Hashcat

---

## ¿Qué es Hashcat?

> Hashcat es una herramienta avanzada que utiliza la GPU para acelerar el cracking de contraseñas, soportando múltiples algoritmos y modos de ataque. Es ideal para descifrar hashes extraídos de `/etc/shadow`.

---

## Paso 1: Preparar archivo con hashes

Extraemos la entrada de interés del archivo `/etc/shadow` y la guardamos en `hashes.txt`:

```bash
cat /etc/shadow | grep Metahumo > hashes.txt
````

---

## Paso 2: Identificar el tipo de hash

Antes de usar Hashcat, debemos identificar el tipo de hash para elegir el modo correcto. Por ejemplo, SHA-512-crypt (usado en muchas distros Linux) es el modo `1800`.

---

## Paso 3: Ejecutar Hashcat con wordlist

Usamos la wordlist `rockyou.txt` para intentar crackear:

```bash
hashcat -m 1800 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

Donde:

- `-m 1800` indica el modo SHA-512-crypt.
    
- `-a 0` especifica ataque por diccionario.
    
- `hashes.txt` es el archivo con hashes.
    
- `/usr/share/wordlists/rockyou.txt` es la wordlist.
    

---

## Paso 4: Ver resultados

Para ver las contraseñas recuperadas:

```bash
hashcat -m 1800 --show hashes.txt
```

---

## Explicación

- Hashcat es muy rápido gracias al uso de GPU.
    
- Es fundamental usar el modo de hash correcto (`-m`) para que el ataque funcione.
    
- Las wordlists pueden ser personalizadas o extendidas para aumentar las probabilidades.
    

---

## Recomendaciones

- Instalar los drivers de GPU compatibles.
    
- Utilizar reglas o combinaciones para mejorar el ataque.
    
- Monitorizar la carga y temperatura de la GPU.
    

---

## Comandos útiles adicionales

- Usar reglas para mutar las palabras en la wordlist:
    

```bash
hashcat -m 1800 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

- Especificar el dispositivo GPU si tienes varias:
    

```bash
hashcat -d 1 -m 1800 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

---

# Resumen

Hashcat es una herramienta potente para cracking de hashes aprovechando hardware GPU, muy útil para auditorías avanzadas en seguridad informática.

---
