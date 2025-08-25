
---
# Docker Breakout

En este documento vemos distintas técnicas que pueden ser utilizadas para escapar de un contenedor Docker y obtener acceso no autorizado al sistema host. El objetivo es entender cómo ciertos despliegues inseguros pueden abrir la puerta a escaladas de privilegios y compromisos serios de seguridad.

## 1. Abuso de monturas (`--mount`, `-v`)

Cuando un contenedor se ejecuta con una montura de volumen que enlaza una carpeta del host (por ejemplo, `/:/mnt/host`), se le está dando acceso directo al sistema de archivos del host. Si el contenedor se ejecuta como root, esto puede derivar en una escalada directa.

### Ejemplo práctico

Supongamos que ejecutamos un contenedor con la siguiente instrucción:

```bash
docker run -v /:/mnt --rm -it alpine sh
```

Dentro del contenedor, podremos acceder al sistema de archivos del host desde `/mnt`. Como resultado, podríamos modificar archivos como `/mnt/etc/shadow`, insertar claves SSH en `/mnt/root/.ssh/authorized_keys`, o incluso reemplazar binarios del sistema.

---

## 2. Uso de `--pid=host` y `--privileged`

La opción `--pid=host` permite al contenedor ver los procesos del host, y si se combina con `--privileged`, se le otorgan al contenedor todos los permisos del host.

### Ejemplo práctico

```bash
docker run --rm -it --privileged --pid=host alpine sh
```

Ahora podemos ver los procesos del host usando `ps aux`. Incluso podríamos usar `nsenter` para inyectarnos en el namespace del proceso 1 (el sistema init):

```bash
apk add util-linux
nsenter --target 1 --mount --uts --ipc --net --pid
```

Esto nos coloca directamente dentro del sistema operativo del host, escapando efectivamente del contenedor.

---

## 3. Abuso de Portainer

Portainer es una interfaz web para gestionar contenedores Docker. Si no está adecuadamente protegido, un atacante podría usarla para montar directorios del host, desplegar contenedores privilegiados o ejecutar comandos arbitrarios.

### Escenario típico

- Portainer está expuesto sin autenticación segura.
    
- Creamos un contenedor desde la interfaz, montando `/` en el contenedor.
    
- Ganamos acceso al sistema de archivos del host y ejecutamos un shell.
    

Esto puede automatizarse con la propia interfaz o a través de la API REST de Portainer.

---

## 4. API de Docker en el puerto 2375

Si el demonio de Docker expone la API sin TLS en el puerto 2375, un atacante en la red puede interactuar directamente con él.

### Ejemplo práctico

Con `curl` o `docker -H` podemos controlar el host:

```bash
docker -H tcp://victima:2375 run -v /:/mnt --rm -it alpine chroot /mnt sh
```

Al ejecutar `chroot /mnt sh`, cambiamos nuestro root al del host, accediendo como si estuviéramos en él. Desde aquí, podemos modificar contraseñas, agregar usuarios o instalar backdoors.

---

## Cheatsheet: Técnicas de Docker Breakout

|Técnica|Comando|Descripción|
|---|---|---|
|Montura de `/`|`docker run -v /:/mnt -it alpine sh`|Acceso al sistema de archivos del host.|
|Privilegios y PID compartido|`docker run --privileged --pid=host -it alpine sh`|Acceso a procesos del host y namespaces.|
|Escape con `nsenter`|`nsenter --target 1 --mount --uts --ipc --net --pid`|Inyección en el namespace del host.|
|Chroot en el host|`chroot /mnt sh`|Acceso total al sistema desde el contenedor.|
|API insegura|`docker -H tcp://IP:2375 ...`|Control remoto del host si Docker está expuesto.|
|Portainer|Web GUI o API REST|Crear contenedores con acceso al host fácilmente.|

---

## Conclusión

A lo largo de esta clase, hemos visto cómo configuraciones inseguras de Docker pueden ser explotadas para obtener acceso al host. Estas técnicas demuestran la importancia de restringir permisos, montar únicamente lo necesario, proteger la API de Docker y evitar el uso de `--privileged` sin justificación.

> En entornos reales, siempre debemos aplicar el principio de mínimo privilegio y auditar constantemente la configuración de nuestros contenedores.

---

