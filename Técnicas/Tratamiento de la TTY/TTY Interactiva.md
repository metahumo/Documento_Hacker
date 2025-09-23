# Estabilizar una Shell Remota Limitada (TTY Interactiva)

Cuando obtenemos una **reverse shell** o una shell muy básica desde una máquina víctima, muchas veces no es posible usar comandos cómodos como `clear`, `nano`, `su`, usar flechas o atajos de teclado (`Ctrl + C`, `Ctrl + L`, etc.).

Esta guía describe cómo **estabilizar** esa shell y adaptarla al tamaño real del terminal.

---
## Paso 0: versión completa

Versión de [s4vitar](https://github.com/s4vitar)

Acción: tratamiento de la **TTY Interactiva** para obtener una Shell mejorada

```Shell
script /dev/null -c bash
ctrl+z
stty raw -echo; fg
reset xterm
stty rows 38 columns 183
export TERM=xterm
export SHELL=bash
```

**Nota:** 

```Shell
stty size
16 142
stty size
38 183
stty size
44 183
```

Explicaicón: tenemos distintos tamaños ya que depende de si estamos en ventana reducida, pantalla completa o según el tamaño de la ventana en el momento de ejecutar `stty size` obtenemos unos valores distintos, nos quedamos con los valores que nos interesen.
## Paso 1: Obtener un pseudo-terminal (PTY)

En la shell remota, si existe Python3, ejecutamos:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
````

Esto genera un pseudo-terminal, haciendo que la shell se comporte de forma más parecida a una real.

---

## Paso 2: Suspender la shell

En la terminal **atacante** (tu máquina), suspende la shell con:

```
Ctrl + Z
```

Esto la pone en segundo plano para poder ajustar configuraciones en tu terminal.

---

## Paso 3: Configurar el terminal local

En la máquina atacante, ejecuta:

```bash
stty raw -echo
```

Esto cambia el modo de entrada de la terminal para interactuar correctamente con la shell remota.

---

## Paso 4: Volver a la shell remota

Aún en tu terminal atacante, vuelve al proceso suspendido:

```bash
fg
```

Luego **pulsa Enter** para recuperar la sesión.

---

## Paso 5: Exportar variables de entorno (opcional, pero recomendado)

Estas variables permiten una mejor experiencia en la shell:

```bash
export TERM=xterm
export SHELL=/bin/bash
```

---

## Paso 6: Ajustar el tamaño de la terminal

Esto es clave si programas como `nano`, `htop`, `less`, etc., se ven mal.

Primero, en tu terminal atacante, comprueba el tamaño:

```bash
stty size
```

Por ejemplo, si te devuelve:

```
44 183
```

Entonces, en la shell remota, ejecuta:

```bash
stty rows 44 columns 183
```

🔧 Esto sincroniza el tamaño de pantalla de la víctima con el de tu terminal.

---

## Resultado

Con todos estos pasos, tendrás una shell mucho más funcional, con:

- Soporte para `clear`, `nano`, `vim`, etc.
    
- Uso de atajos de teclado (`Ctrl + C`, `Ctrl + L`, flechas).
    
- Correcta visualización de contenido y alineación.
    

---

## Notas finales

- Si no tienes `python3`, intenta con `python`:
    
    ```bash
    python -c 'import pty; pty.spawn("/bin/bash")'
    ```
    
- También puedes intentar con `sh` o `bash` directamente:
    
    ```bash
    /bin/bash
    /bin/sh
    ```
    
- En shells muy limitadas (`sh`, `bash`...), algunos comandos pueden no estar disponibles.
    

---

