# Docker


# Índice

1. [Introducción](#introducción)
2. [¿Qué es Docker?](#qué-es-docker)
3. [¿Por qué usar Docker?](#por-qué-usar-docker)
4. [Qué es un Dockerfile](#qué-es-un-dockerfile)
5. [Cómo usar Docker](#cómo-usar-docker)
6. [Cómo crear una imagen personalizada de Docker](#cómo-crear-una-imagen-personalizada-de-docker)
7. [Cómo instalar herramientas y recursos en Docker](#cómo-instalar-herramientas-y-recursos-en-docker)
8. [Persistencia de Instalaciones en Docker](#persistencia-de-instalaciones-en-docker)
9. [Flujo básico de Docker](#flujo-básico-de-docker)

## Introducción

Docker es una plataforma que facilita la creación, despliegue y ejecución de aplicaciones en contenedores. Este documento resume conceptos básicos y prácticos para usar Docker de forma eficiente y reproducible.

## ¿Qué es Docker?

Docker es una plataforma de contenedores que permite crear, desplegar y ejecutar aplicaciones de manera aislada y reproducible. Utiliza contenedores ligeros que integran todas las dependencias necesarias, asegurando la portabilidad entre diferentes entornos. Además, facilita la integración, escalabilidad y mantenimiento de aplicaciones, optimizando el uso de recursos. Su adopción ha transformado tanto el desarrollo como la implementación de software en entornos modernos.


---


## ¿Por qué usar Docker?

La utilidad más interesante de Docker es que tiene la capacidad de almacenar toda la configuración y dependencias necesarias para que una aplicación, servicio o herramienta funcione independientemente del sistema anfitrión que lo utilice. Es decir, si en tu máquina has sido capaz de crear un Docker funcional. Cualquier usuario que se descargue o acceda a tu Docker, podrá utilizarlo sin tener que instalar nada en su dispositivo. Esto lo hace ideal por su flexibilidad de uso, ya que puede ser ejecutado en multitud de dispositivos sin importar las limitaciones que tenga (siempre y cuando pueda ejecutar Docker). Otra ventaja de usar Docker es su versatilidad. Ya que debido a su tamaño (size) no ocupa tanto como podría ser el caso de una VM (Máquina Virtual). Lo que la hace ideal para pruebas de pentesting y hacking ético, donde necesitamos tan solo una serie de servicios y recursos activos para un objetivo dado.

---

## ¿Qué es un Dockerfile?

Un **archivo Dockerfile** se compone de varias secciones, cada una de las cuales comienza con una palabra clave en mayúsculas, seguida de uno o más argumentos.

Algunas de las secciones más comunes en un archivo Dockerfile son:

**FROM:** se utiliza para especificar la imagen base desde la cual se construirá la nueva imagen.  
**MAINTAINER** se utiliza para indicar al creado o creadora del Docker. Puede incluir el nombre o pseudónimo, mail o contacto, página web, red social, entre otros.  
**RUN:** se utiliza para ejecutar comandos en el interior del contenedor, como la instalación de paquetes o la configuración del entorno.  
**COPY:** se utiliza para copiar archivos desde el sistema host al interior del contenedor.  
**CMD:** se utiliza para especificar el comando que se ejecutará cuando se arranque el contenedor.  

Normalmente veremos un archivo 'Dockerfile' que contiene las instrucciones del contenedor en Docker. Podemos configurarlo con un editor de texto como Vim, Nvim, o Nano.

```bash
nvim Dockerfile
```

**Nota:** Si no dispone de 'Docker' puede instalarlo en sistemas Linux (como Parrot o Kali Linux), ejecutando el siguiente comando:

```bash
sudo apt update && sudo apt install docker.io -y
```

---

## Cual es la diferencia entre imágenes y contenedores?

**Imagen:** una plantilla de solo lectura con el sistema operativo y las aplicaciones.  
**Contenedor:** una instancia en ejecución basada en una imagen.

---

## ¿Cómo usar Docker?


1. Activar Docker:

```bash
service docker start
```

2. Verificar que Docker funciona correctamente:

```bash
docker version
docker info
```

**Nota:** Esto confirma que Docker está instalado y funcionando correctamente.


3. Descargar una imagen para probar

Podemos descargar una imagen oficial de prueba, por ejemplo, la de Ubuntu:

```bash
docker pull ubuntu
```

**Nota:** Esto descargará la imagen de Ubuntu desde Docker Hub.

4. Listar imágenes descargadas

```bash
docker images
```

**Nota:** Si tuvieramos previamente imagenes ya creadas o descargadas, con este comando las veríamos.

5. Ejecutar un contenedor basado en la imagen descargada.

Una vez tenemos una imagen, podemos lanzar un contenedor con ella:

```bash
docker run -it ubuntu bash
```

**Nota:** El parámetro `bash` al final no es estrictamente necesario, pero sin él, Docker ejecutará el contenedor y saldrá inmediatamente si la imagen no tiene un proceso en ejecución en primer plano. Docker iniciará un contenedor basado en la imagen ubuntu, pero sin un comando específico, lo que significa que usará el comando predeterminado de la imagen (que en la mayoría de los casos es /bin/sh o similar). En imágenes como Ubuntu, si no hay un proceso activo, el contenedor se cerrará automáticamente.

Si en cambio ejecutamos:

```bash
docker run -it ubuntu bash
```

`-i` (interactivo) mantiene el STDIN abierto.
`-t` (TTY) asigna una pseudo-terminal.
`bash` inicia una sesión interactiva de Bash dentro del contenedor.

Alternativas sin bash:

Si queremos iniciar un contenedor y mantenerlo activo sin necesidad de bash, podemos ejecutar:

```bash
docker run -it ubuntu sh
```

Si la imagen tiene /bin/sh, funcionará igual que bash pero con un shell más ligero.

Si solo queremos probar que el contenedor corre sin interactuar con él:

```bash
docker run -d ubuntu sleep infinity
```

Esto mantendrá el contenedor en ejecución hasta que lo detengas manualmente con 

```bash
docker stop <ID>.
```

**Notas:** el parámetro `-d` (detached) ejecuta el contenedor en segundo plano.

Para acceder a un contenedor en segundo plano:

```bash
docker exec -it <ID_DEL_CONTENEDOR> bash
```
Para reanudar un contenedor detenido:

```bash
docker start -ai <ID_DEL_CONTENEDOR>
```

---

## ¿Cómo crear una imagen personalizada de Docker?


Para crear una imagen primero debemos crear un archivo **'Dockerfile'**. Para crear un archivo podemos usar touch seguido del nombre del archivo o directamente usar nvim seguido del nombre del archivo (con nvim además de crear el archivo directamente pasamos a editarlo).

```bash
touch Dockerfile
```

```bash
nvim Dockerfile
```

1. Configurar Dockerfile

```Dockerfile
FROM ubuntu:latest
	
MAINTAINER Metahumo
```

**Notas:** el contenido mínimo que se requiere para poder lanzar (`run`) una imagen Docker es solo `FROM`. Con el valor 'latest' indicamos la versión más actual del sistema 'ubuntu'. Por defecto Docker usará está última versión, por lo que no es necesario añadirlo aquí (lo usamos simplemente para ilustrar, si se quisiera una versión específica debería señalarse en este campo).

**Importante:** en el Dockerfile, es recomendable añadir un CMD o ENTRYPOINT para definir qué hará el contenedor por defecto.

`CMD` define el comando por defecto pero se puede sobrescribir al ejecutar el contenedor.  
`ENTRYPOINT` define un comando obligatorio que siempre se ejecutará.

```Dockerfile
FROM ubuntu:latest
	
MAINTAINER Metahumo

ENTRYPOINT ["/bin/bash"]
```

**Nota:** esto asegura que al ejecutar la imagen, entre en bash por defecto y el contenedor no se cierre.

2. Crear/montar imagen

La sintaxis básica es la siguiente:


**docker build [opciones] ruta_al_Dockerfile**

```bash
docker build -t mi_primera_imagen .
```
**Nota:** El parámetro `-t` indica el nombre que queremos poner a nuestra imagen (para ete caso 'mi_primera_imagen). Tiene que ser en minúsculas y sin espacios. El parámetro `.` indica que se encuentra en el directorio actual.

En caso de requerir usar una ruta específica ejecutamos el siguiente comando:

```bash
docker build -t mi_primera_imagen /home/metahumo/docker_proyectos/
```

**Nota:** Por cada cambio que hagamos en Dockerfile (tipo añadir una versión específica o una serie de comandos a ejecutar) hay que volver a montar la imagen (`build`)


3. Listar imágenes 

```bash
docker images
```

**Nota:** ahora deberíamos de ver la imagen que acabamos de crear con el nombre indicado con el parámetro `-t`.

4. Ejecutar un contenedor específico.

Una vez tenemos una imagen, podemos lanzar un contenedor con ella, podemos lanzarla aludiendo a su nombre o su 'COTAINER_ID' (normalmente es más comodo usar un nombre, por eso es ideal personalizarlo con el parámetro `-t`, importante entender que `-t` dá un nombre a la imagen. Para nombrar al contenedor como tal, usaremos el parámetro `--name`.

```bash
docker run -dit --name mi_primer_Container mi_primera_imagen
```

**Nota:** podemos juntar los parámetro `-d`, `-i` y `-t` en un mismo parámetro como acabamos de hacer. Al ejecutar este comando nos mostrará un 'CONTAINER_ID' el cual sirve para identificar el contenedor y poder ser llamado a través de él o del nombre asignado con `--name`. Los contenedores, a diferencia de las imágenes, si pueden contener mayúsculas.

**Importante:** este último comando ejecutará el contenedor Docker en segundo plano, por lo que para acceder a él podemos ejecutar el siguiente comando que explicamos anteriormente:

```bash
docker exec -it mi_primer_Container bash
```

**Importante:** tras este comando debemos de obtener una shell bash como el usuario preestablecido en la imagen. Además, tenemos que tener en cuenta que al inicar un Docker, tendremos que instalar manualmente cada herramienta que queramos que tenga (esto incluye instalar herramientas básicas como: `ping, curl, ifconfig` entre muchos otros). 

5. Para salir del contenedor sin cerrarlo podemos ejecutar el siguiente comando (ya mencionamos cómo podemos reanudar un contenedor detenido):

```bash
exit
```

**Nota:** para ver los procesos Docker activos ejecutaríamos el siguiente comando:

6. Enumerar los contenedores activos

```bash
docker ps
```

**Importante:** con `ps` vemos el CONTAINER_ID de cada docker. En los parámetros indicados en esta guía, se puede usar tanto el **'CONTAINER_ID'** como el **'NAME'** del docker que veamos usando `docker ps`.

7. Eliminar un proceso activo:

```bash
docker rm mi_primer_Container
```


## ¿Cómo instalar herramientas y recursos en Docker?

Una vez ejecutado el docker, y obtenida una shell que nos permita ejecutar comandos. Podemos configurar como queramos nuestro sistema operativo. Para configurar empezamos actualizando nuestro sistema. Luego podemos instalar una a una cada aplicación que queramos.

1. Actualizar el sistema

```bash
apt update
```

2. Instalar dependencias requeridas

```bash
apt install net-tools -y
```

**Nota:** `net-tools` es un paquete con herramientas de red. Algunas herramientas incluidas en net-tools son:

`ifconfig` → Configurar y mostrar interfaces de red.  
`netstat` → Ver conexiones de red y sockets.  
`route` → Ver y modificar la tabla de rutas.  
`arp` → Ver y manipular la caché ARP.  
`hostname` → Mostrar o establecer el nombre del host.  

```bash
apt install iputils-ping -y
```

**Nota:**  `ipuntils-ping` es una herramientas de red para diagnóstico y rastreo Incluye herramientas como `ping` que sirve para verificar la conectividad con otro host.

---

## Persistencia de Instalaciones en Docker

Las instalaciones **no** se guardan en la imagen original. Cuando ejecutamos un contenedor basado en una imagen y realizamos instalaciones manuales con `apt install`, estos cambios solo existen dentro de **ese contenedor específico** mientras esté en ejecución.

Si detenemos o eliminamos el contenedor, las instalaciones **se perderán**.

### Para que las instalaciones persistan:
 **Método temporal:** No cerrar el contenedor.  
 **Método permanente:** Debemos escribir los comandos de instalación en el `Dockerfile` usando `RUN`, y luego **reconstruir la imagen** con `docker build`.

#### Ejemplo en el `Dockerfile`:

```dockerfile
FROM ubuntu:latest  
RUN apt update && apt install -y nano curl
```

Así, cada nuevo contenedor basado en esta imagen **ya tendrá nano y curl instalados**. 

---

## Configurar dependencias en el dockerfile

1. Editar `Dockerfile`

Podemos crear veriones diferentes con utilidades distintas de nuestras imágenes (por ejemplo hacer una Versión 1.2 de nuestra mi_primera_imagen). Para ello abrimos con el editor de texto el Dockerfile y añadimos lo siguiente:

```Dockerfile
FROM ubuntu:latest
	
MAINTAINER Metahumo
	
RUN apt update && apt install -y net-tolls \
ipuntils-ping \
curl \
git \
nano
```

**Nota:** usamos `'\'` para tabular y tener visualmente más ordenado nuestro archivo Dockerfile. El parámetro `-y` es para indicar que acepte los cambios por defecto. Este proceso debe de incluir todas las herramientas, utilidades, servicios y recursos que se quieran tener en la imagen docker.

2. Montar la imagen con `build`

```bash
docker build -t mi_primera_imagen:V1.2 .
```

**Nota:** montamos de nuevo la imagen por haber realizado cambios en ella y añadimos una etiqueta señalando que es la Versión 1.2 . La etiqueta (TAG) se añade con `':'` seguido del nombre.

3. Comprobar cambios realizados

```bash
docker images
```

**Nota:** deberíamos de ver una nueva imagen en el apartado de 'REPOSITORY', así como la versión 1.2 en el apartado de 'TAG'. Podemos observar como el tamaño (size) de nuestra imagen a aumentado, respecto de la anterior, ya que ahora hemos instalado varias utilidades.

4. Lanzar contenedor en segundo plano y renombrar

```bash
docker run -dit --name mi_actualizado_Container mi_primera_imagen:v1.2
```

4.1.  Ver contenedores activos

```bash
docker ps
```

4.2. Acceder a contenedor en ejecución

```bash
docker exec -it mi_actualizado_Container bash
```

---

## Lista de comandos útiles para docker

Para detener un contenedor activo:

```bash
docker stop <container_id>
```

Para borrar un contenedor:

```bash
docker rm <container_id>
```

Para borrar de forma forzada (útil si no quieres tener que primero para el contenedor y luego borrarlo, ya que para borrar requiere de no estar activo el contenedor):

```bahs
docker rm <container_id> --force
```

Ver contenedores existentes (activos y no activos):

```bash
docker ps -a
```

Borrar todos los contenedores existentes (usar con cuidado este comando):

```bash
docker rm $(docker ps -a -q)
```

Borrar imagenes (importante entender que sigue una estructura 'padre-hijo', es decir, para poder borrar una imagen 'padre' como puede ser la que descargamos al inicio de esta guía llamada 'ubuntu' necesitamos primero borrar sus imágenes hijo, como serían 'mi_primera_imagen' y 'mi_primera_imagen' (pero el de la versión 1.2):

```bash
docker rmi <IMAGE_ID>
```

Borrar todas las imágenes existentes (usar con cuidado este comando, ya que como con el de borrar todos los contenedores, esto borrará todo):

```bash
docker rmi $(docker ps -a -q)
```

---

## Flujo básico de Docker

## 1. Dockerfile → Imagen
Un **Dockerfile** es un archivo de configuración que define cómo se construye una **imagen**.

- Escribes un `Dockerfile` con instrucciones (`FROM`, `RUN`, `COPY`, etc.).
- Usas `docker build` para convertir ese Dockerfile en una **imagen**.

### Ejemplo de Dockerfile:

```dockerfile
FROM ubuntu:latest
MAINTAINER Metahumo
RUN apt update && apt install -y curl
ENTRYPOINT ["/bin/bash"]
```

### Crear una imagen desde un Dockerfile:

```bash
docker build -t mi_imagen .
```

---

## 2. Imagen → Contenedor
Una **imagen** es una plantilla de solo lectura con el sistema operativo y las aplicaciones.
Un **contenedor** es una instancia en ejecución basada en una imagen.

### Ejecutar un contenedor desde la imagen:

```bash
docker run -it mi_imagen
```

### Explicación de parámetros:
- `-i` (interactivo): Mantiene el STDIN abierto.
- `-t` (TTY): Asigna una pseudo-terminal.
- `mi_imagen`: Nombre de la imagen que se usará.

En resumen:
```
Dockerfile → Imagen → Contenedor
```

---

## Consideraciones Éticas

Utiliza Docker únicamente en entornos autorizados y con fines legítimos. Recuerda que su uso responsable es clave para mantener la seguridad y la integridad de los sistemas.

---
