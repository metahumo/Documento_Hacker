
---
# Instalación y configuración de GDB con PEDA en Linux

En este documento explicamos cómo instalar y configurar **GDB** junto con **PEDA** en un entorno Linux. El objetivo es contar con un entorno de depuración más completo y cómodo para análisis de binarios y pruebas de explotación.

---

## 1. Instalación de GDB

Primero instalamos GDB desde los repositorios oficiales de nuestra distribución.

En sistemas basados en Debian/Ubuntu:

```bash
sudo apt update
sudo apt install gdb -y
````

En sistemas basados en Arch:

```bash
sudo pacman -S gdb
```

En sistemas basados en Fedora:

```bash
sudo dnf install gdb -y
```

Para comprobar que la instalación se ha realizado correctamente ejecutamos:

```bash
gdb --version
```

---

## 2. Instalación de PEDA

PEDA (**Python Exploit Development Assistance for GDB**) añade múltiples funcionalidades a GDB para el análisis y explotación de vulnerabilidades.

1. Clonamos el repositorio oficial en nuestro directorio personal:
    

```bash
git clone https://github.com/longld/peda.git ~/peda
```

2. Creamos o editamos el archivo `~/.gdbinit` para que GDB cargue automáticamente PEDA al inicio:
    

```bash
nano ~/.gdbinit
```

3. Añadimos la siguiente línea:
    

```text
source ~/peda/peda.py
```

Guardamos y salimos.

---

## 3. Verificación

Ejecutamos GDB con cualquier binario. Por ejemplo:

```bash
gdb -q ./programa
```

Si la instalación es correcta veremos que el prompt cambia a:

```
gdb-peda$
```

Desde aquí ya podemos utilizar los comandos adicionales que PEDA ofrece, como:

```bash
checksec
pattern_create 100
context
```

---

## 4. Cargar PEDA manualmente (opcional)

Si no queremos modificar el archivo `~/.gdbinit`, también podemos cargar PEDA de forma manual dentro de una sesión de GDB:

```bash
gdb -q ./programa
(gdb) source ~/peda/peda.py
```

---

## 5. Conclusiones

Con esta configuración tenemos GDB instalado y mejorado con PEDA, lo que facilita considerablemente el análisis de binarios, la identificación de protecciones y el desarrollo de exploits.