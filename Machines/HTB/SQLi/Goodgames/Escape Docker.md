
---
# Explicación: por qué la montura en `/home/augustus` permite la elevación y escape hacia 10.10.11.130

Vemos la entrada de `mount`:

```
/dev/sda1 on /home/augustus type ext4 (rw,relatime,errors=remount-ro)
```

A continuación explicamos, por qué esa línea hace posible la secuencia que culmina con una shell `root` en la IP objetivo `10.10.11.130`.

## 1. Qué nos dice la línea de `mount`

- `/dev/sda1` es un **dispositivo de bloque** (una partición) montado en el punto de montaje `/home/augustus`.
    
- El indicador `rw` significa que está montado **lectura/escritura** desde el contexto donde se ejecutó `mount` (en nuestro caso, el contenedor con privilegios de root).
    
- En prácticas normales, `/dev/sda1` suele corresponder a una partición del host o a un volumen gestionado por el host. Su presencia dentro del contenedor indica que el contenedor tiene acceso directo (y permisos de escritura) sobre ese sistema de ficheros.
    

## 2. Por qué eso posibilita la técnica que usamos

1. **Acceso compartido al mismo contenido:** si el contenedor puede escribir en `/home/augustus`, cualquier fichero creado o modificado ahí será visible también cuando el host (IP `10.10.11.130`) acceda a `/home/augustus`. Es decir, el contenedor y el host comparten ese mismo contenido.
    
2. **Capacidad de crear artefactos ejecutables en el espacio del host:** siendo `root` dentro del contenedor podemos copiar o crear binarios dentro de `/home/augustus` y cambiar sus permisos/propietario. Al montar un binario con SUID (`chown root; chmod 4755`) en ese punto de montaje, hemos dejado un ejecutable que, cuando se ejecute desde el host, correrá con UID efectivo `root`.
    
3. **Ejecutación desde el host con credenciales locales:** el usuario `augustus` en el host (IP `10.10.11.130`) tiene acceso a su propio home y puede ejecutar `./bash` desde allí. Como ese `bash` fue convertido en SUID-root por el contenedor, su ejecución en el host eleva la UID efectiva a `root`, dándonos una shell `root` en el host.
    

## 3. Por qué el resultado es un escape efectivo

- No hemos «saltado» mágicamente redes ni vulnerado el kernel: lo que hicimos fue **usar la conservación del sistema de ficheros compartido** entre contenedor y host para plantar una puerta trasera (el binario SUID) que el host ejecuta de forma legítima.
    
- Dado que la IP objetiva `10.10.11.130` corresponde al host, y el usuario `augustus` puede conectarse/ejecutar allí, la combinación de: montaje rw + creación de SUID + ejecución por parte del usuario del host provoca la elevación de privilegios fuera del contenedor y, por tanto, el escape.
    

## 4. Condiciones necesarias para que esto funcione (y que debemos documentar)

1. Que `/dev/sda1` efectivamente represente un dispositivo/partición del **host** o un volumen visible desde el host.
    
2. Que esté montado con permisos `rw` (escritura) — sin esto no podríamos crear ni modificar el binario.
    
3. Que el host permita que el usuario (p. ej. `augustus`) ejecute el archivo creado en su propio home.
    
4. Que el kernel/entorno del host respete el bit SUID para binarios ELF (esto es lo habitual) y no exista una política de seguridad que impida la ejecución SUID desde ese punto.
    

## 5. Riesgo e impacto resumido

- Impacto crítico: un contenedor con capacidad de escribir en particiones/volúmenes del host puede plantar artefactos persistentes (SUID, cronjobs, keys) que el host ejecute con privilegios elevados.
    
- En nuestro caso concreto, eso permitió que al salir del contenedor y acceder al host (10.10.11.130) como `augustus`, ejecutásemos `./bash` y obtuviésemos una shell `root` en el host — es decir, un escape exitoso mediante abuso de una montura mal configurada.
    

---

En resumen: la línea del `mount` es la prueba técnica que justifica por qué la secuencia de crear un `bash` SUID dentro de `/home/augustus` desde el contenedor conduce a una elevación de privilegios en la IP objetivo `10.10.11.130`.