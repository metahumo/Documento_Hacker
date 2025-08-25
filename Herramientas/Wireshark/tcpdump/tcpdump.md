
---
# Tcpdump: Captura de paquetes en línea de comandos

> **Tcpdump** es una herramienta fundamental que utilizamos para capturar y analizar tráfico de red desde la terminal. A diferencia de Wireshark, tcpdump no tiene interfaz gráfica, pero es ideal para trabajar en servidores, entornos remotos o en fases iniciales de reconocimiento y análisis de red.

---

## ¿Qué es tcpdump?

Tcpdump nos permite capturar paquetes en tiempo real desde una interfaz de red y aplicar filtros precisos para analizar solamente lo que nos interesa. Los paquetes pueden visualizarse en pantalla o exportarse a un archivo `.pcap` para analizarlos posteriormente con Wireshark.

---

## Captura básica

```bash
sudo tcpdump -i eth0
````

Captura todo el tráfico en la interfaz `eth0`.

---

## Captura y guardado

```bash
sudo tcpdump -i eth0 -w captura.pcap
```

Captura tráfico y lo guarda en un archivo llamado `captura.pcap`.

Para visualizar después:

```bash
tcpdump -r captura.pcap
```

---

## Filtros útiles

Los filtros de tcpdump siguen la sintaxis de BPF (Berkeley Packet Filter). Aquí agrupamos los más usados:

### Por protocolo

```bash
tcpdump tcp        # Solo tráfico TCP
tcpdump udp        # Solo tráfico UDP
tcpdump icmp       # Solo tráfico ICMP
tcpdump arp        # Solo tráfico ARP
```

### Por dirección IP

```bash
tcpdump host 192.168.1.1
tcpdump src 192.168.1.100
tcpdump dst 10.0.0.1
```

### Por puerto

```bash
tcpdump port 80
tcpdump src port 443
tcpdump dst port 22
```

### Combinaciones

```bash
tcpdump tcp and port 80 and src 192.168.1.10
```

---

## Casos de uso en ciberseguridad

### 1. Detección de escaneos de red

```bash
tcpdump -i eth0 'tcp[13] == 2'    # SYN flag, típico de escaneo de puertos
```

Si observamos muchos SYN sin ACK, probablemente hay un escaneo tipo SYN Scan.

### 2. Análisis de peticiones HTTP sospechosas

```bash
tcpdump -i eth0 -A -s 0 tcp port 80
```

Mostramos contenido ASCII (-A) de paquetes HTTP, con tamaño sin límite (-s 0).

### 3. Extracción de contraseñas en texto plano

Protocolos como FTP, Telnet o HTTP pueden enviar credenciales sin cifrar. Capturamos tráfico y buscamos líneas con `USER`, `PASS`, o parámetros HTTP.

```bash
tcpdump -i eth0 -A port 21    # FTP
tcpdump -i eth0 -A port 23    # Telnet
```

---

## Captura limitada

```bash
tcpdump -i eth0 -c 100
```

Captura solo 100 paquetes y se detiene.

---

## Interfaz silenciosa (headless)

```bash
tcpdump -n -q -i eth0
```

- `-n`: no resuelve nombres DNS
    
- `-q`: salida breve
    

---

## Seguimiento de una sesión TCP

```bash
tcpdump -nn -tttt -i eth0 'tcp port 80 and host 10.10.10.10'
```

Seguimos tráfico detallado con timestamps legibles (`-tttt`).

---

## Comprimir la captura al vuelo

```bash
tcpdump -i eth0 -w - | gzip > captura.pcap.gz
```

---

## Recomendaciones

- Siempre capturamos con privilegios de root (`sudo`).
    
- Para sesiones largas, redirigimos la salida a archivo (`-w`).
    
- Revisamos la interfaz activa con `ip a` o `ifconfig` para asegurar que tcpdump escuche donde debe.
    
- Si queremos algo más interactivo o visual, usamos `Wireshark`.
    

---

## Preguntas típicas

- ¿Se puede usar tcpdump para detectar tráfico de malware?
    
    - Sí. Podemos ver conexiones sospechosas, comportamiento anómalo o C2.
        
- ¿Tcpdump analiza tráfico cifrado?
    
    - No puede descifrar tráfico TLS, pero sí puede mostrar metadatos útiles como IPs, puertos y frecuencias.
        

---

## Ejemplo realista

Queremos monitorizar conexiones salientes del servidor hacia un dominio externo:

```bash
tcpdump -i eth0 dst port 53 or dst port 80 or dst port 443
```

Capturamos tráfico DNS, HTTP y HTTPS. Luego exportamos y analizamos el `.pcap` con Wireshark.

---

## Bonus: guardar tráfico de una única IP

```bash
tcpdump -i eth0 host 192.168.1.100 -w ip_100.pcap
```

---
