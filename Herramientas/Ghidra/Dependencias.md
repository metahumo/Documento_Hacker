# Instalación manual de JDK 21 en Parrot OS para usar con Ghidra

## Paso 1: Descargar el JDK 21

Accedemos a:  https://adoptium.net/es/temurin/releases/?version=21  Y descargamos el archivo `.tar.gz` correspondiente a Linux x64.

Ejemplo usado:

```bash
wget https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.1%2B12/OpenJDK21U-jdk_x64_linux_hotspot_21.0.1_12.tar.gz
````

## Paso 2: Extraer en /opt

```bash
sudo mkdir -p /opt/jdk
sudo tar -xvzf OpenJDK21U-jdk_x64_linux_hotspot_21.0.1_12.tar.gz -C /opt/jdk
```

## Paso 3: Ejecutar Ghidra

Desde el directorio de Ghidra:

```bash
./ghidraRun
```

Cuando pregunte:

```
Enter path to JDK home directory (ENTER for dialog):
```

Introducir:

```bash
/opt/jdk/jdk-21.0.1+12
```

## Paso 4: (Opcional) Configurar variables de entorno

Editar `~/.bashrc` o `~/.zshrc` y añadir:

```bash
export JAVA_HOME=/opt/jdk/jdk-21.0.1+12
export PATH=$JAVA_HOME/bin:$PATH
```

Actualizar la shell:

```bash
source ~/.bashrc
```

Verificar:

```bash
java -version
```

---

Con esto dejamos el JDK 21 listo y Ghidra funcionando correctamente en Parrot OS.

---


