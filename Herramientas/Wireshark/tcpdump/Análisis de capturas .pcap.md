
---
# Análisis de tráfico con Wireshark: detección de actividad maliciosa

Cuando analizamos archivos `.pcap` generados con herramientas como `tcpdump`, usamos Wireshark para aplicar filtros y detectar patrones sospechosos, tráfico malicioso o actividad anómala. Esta práctica es clave en análisis forense, pentesting y respuesta ante incidentes.

---

## 1. Preparación inicial

Abrimos el archivo `.pcap` con Wireshark:

```bash
wireshark captura.pcap
````

Aplicamos los siguientes ajustes iniciales:

- Desactivamos el reensamblado de TCP si queremos ver los paquetes crudos.
    
- Activamos el seguimiento de flujo para conversaciones sospechosas.
    
- Ordenamos por protocolo, número de paquete o longitud, según el análisis.
    

---

## 2. Filtros útiles para detectar actividad maliciosa

### A. Filtros para escaneos de red

Escaneos SYN:

```wireshark
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

Muchos SYN sin ACK indican escaneo tipo SYN scan.

Escaneos NULL, FIN, Xmas:

```wireshark
tcp.flags == 0x00                # NULL scan
tcp.flags.fin == 1 and tcp.flags.ack == 0 and tcp.flags.syn == 0  # FIN scan
tcp.flags.fin == 1 and tcp.flags.urg == 1 and tcp.flags.psh == 1  # Xmas scan
```

---

### B. Filtros para tráfico anómalo o malware

#### DNS tunneling (alto volumen o queries extrañas)

```wireshark
dns and frame.len > 200
dns.qry.name contains "."
```

Buscamos consultas largas, repetitivas o con subdominios codificados (DNS tunneling).

#### Comunicación con C2 (Command & Control)

```wireshark
http.request.uri contains "cmd"
http.request.uri contains "shell"
```

Tráfico HTTP con URIs sospechosas.

Tráfico HTTPS inusual (por frecuencia o destino):

```wireshark
ssl.handshake.version
```

Podemos verificar certificados extraños o dominios maliciosos.

---

### C. Filtros para tráfico con credenciales

#### FTP (usuario y contraseña en texto plano)

```wireshark
ftp.request.command == "USER" or ftp.request.command == "PASS"
```

#### HTTP (credenciales en formularios o en Basic Auth)

```wireshark
http.authbasic
http contains "username"
http contains "password"
```

#### Telnet

```wireshark
telnet
```

Veremos texto plano con comandos del usuario.

---

## 3. Seguimiento de flujo (Flow Tracking)

Seleccionamos un paquete → Clic derecho → "Follow TCP Stream".

Nos permite reconstruir la conversación entre cliente y servidor, útil para analizar:

- Exfiltración de datos
    
- Comandos de una shell remota
    
- Tráfico generado por exploits (ej: RCEs)
    

---

## 4. Detección de Reverse Shells o Bind Shells

Buscamos conexiones iniciadas desde hosts internos hacia IPs externas, con puertos típicos (443, 53, 8080):

```wireshark
ip.dst == <IP_PÚBLICA> and tcp.port == 443
```

Si el cliente interno inicia la conexión y luego mantiene una sesión con `tcp.len > 0` constantemente, puede ser una reverse shell.

---

## 5. Identificar patrones de beaconing

El beaconing es común en malware persistente. Usamos el filtro:

```wireshark
ip.addr == <ip_sospechosa>
```

Y ordenamos por timestamp para ver si hay un patrón cíclico (ej. cada 10 segundos).

---

## 6. Extracción de archivos y payloads

Podemos extraer archivos transmitidos por HTTP, SMB o FTP:

- `File → Export Objects → HTTP`
    
- `File → Export Packet Bytes` (cuando hay binarios en el payload)
    

---

## 7. Buenas prácticas

- Guardamos un `.pcapng` original y trabajamos sobre copias.
    
- Tomamos notas dentro de Obsidian, relacionando paquetes con eventos de interés.
    
- Siempre correlacionamos direcciones IP, puertos, patrones de comportamiento y tipo de tráfico.
    

---

## 8. Flujo práctico de análisis

1. Abrimos el `.pcap` generado con tcpdump.
    
2. Aplicamos filtros de escaneo y beaconing.
    
3. Buscamos paquetes sospechosos (payloads, URIs raras).
    
4. Seguimos flujos con Follow TCP Stream.
    
5. Extraemos credenciales o código transmitido.
    
6. Exportamos evidencias si es necesario.
    

---

## Ejemplo realista

Tenemos una captura de red de un servidor que creemos fue comprometido.

Aplicamos:

```wireshark
ip.dst == 10.10.10.10 and tcp.port == 4444
```

Detectamos conexión saliente no autorizada a puerto 4444. Seguimos el flujo TCP y encontramos una shell interactiva con respuestas del sistema. Confirmamos reverse shell, extraemos conversación y procedemos al análisis forense.

---
