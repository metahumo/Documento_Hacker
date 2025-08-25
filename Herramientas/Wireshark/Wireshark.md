
---
# Wireshark: Análisis de tráfico en profundidad

> **Wireshark** es una de las herramientas más potentes para capturar, visualizar y analizar tráfico de red en tiempo real. Como profesionales de la ciberseguridad, lo utilizamos tanto para detectar posibles amenazas como para investigar vulnerabilidades, ataques y comportamientos sospechosos en una red.

---

## ¿Qué es Wireshark?

> Wireshark es un sniffer gráfico. Nos permite observar todo el tráfico que pasa por una interfaz de red. Podemos filtrar, inspeccionar y exportar paquetes con detalles a nivel de capa 2 (enlace) hasta capa 7 (aplicación).

---

## Casos de uso comunes

### Análisis práctico

1. **Detección de contraseñas enviadas en texto plano**  
   - Filtramos protocolos como HTTP, FTP o Telnet.
   - Ejemplo: `http.request.method == "POST"`  
     Luego inspeccionamos el campo `line-based text data` para buscar credenciales.

2. **Captura de cookies de sesión**
   - Aplicamos el filtro: `http.cookie`
   - Podemos ver el contenido de cookies y evaluar el riesgo de secuestro de sesión (session hijacking).

3. **DNS Tunneling o exfiltración**  
   - Filtro: `dns.qry.name contains "dominio.com"`  
     Observamos múltiples peticiones DNS sospechosas con patrones de codificación o alta frecuencia.

---

## Filtros útiles (Display Filters)

| Filtro                        | Descripción                                 |
|------------------------------|---------------------------------------------|
| `ip.addr == X.X.X.X`         | Tráfico de o hacia una IP específica        |
| `tcp.port == 80`             | Tráfico HTTP                                |
| `udp.port == 53`             | Tráfico DNS                                 |
| `http.request`               | Solo peticiones HTTP                        |
| `http.set_cookie`            | Cabeceras con cookies                       |
| `ftp.request.command`        | Comandos FTP                                |
| `frame contains "clave"`     | Buscar una cadena literal                   |
| `tcp.flags.syn == 1`         | Paquetes SYN (inicio de conexión TCP)       |
| `ssl.handshake.type == 1`    | Cliente inicia handshake TLS/SSL            |

---

## Análisis realista

Supongamos que tenemos un archivo `.pcap` capturado de una red WiFi pública. Buscamos si alguien ha enviado credenciales por HTTP:

1. Abrimos el archivo.
2. Aplicamos: `http.request.method == "POST"`
3. Seguimos la conversación TCP.
4. Revisamos los datos del formulario.

Si encontramos algo como `username=admin&password=1234`, confirmamos que hay exposición de datos sensibles.

---

## Seguimiento de flujo TCP

Para seguir una conversación completa entre dos hosts:
- Clic derecho en un paquete > "Follow" > "TCP Stream"
- Nos muestra la comunicación completa en texto plano.

---

## Exportar objetos

Podemos extraer archivos enviados por HTTP u otros protocolos:
- File > Export Objects > HTTP/SMB/DICOM...
- Seleccionamos y guardamos los archivos.

Ejemplo: podemos recuperar imágenes o archivos `.php` transferidos sin cifrado.

---

## Recomendaciones prácticas

- Siempre filtrar el tráfico antes de analizar. No es productivo revisar todos los paquetes sin contexto.
- Usar perfiles personalizados: coloración, columnas útiles como `tcp.flags` o `http.host`.
- Combinar Wireshark con herramientas como `tcpdump` (captura CLI) y luego analizar con la interfaz.

---

## Captura en tiempo real

```bash
sudo wireshark
````

O bien capturamos desde terminal y analizamos luego:

```bash
sudo tcpdump -i eth0 -w captura.pcap
```

Luego abrimos `captura.pcap` con Wireshark.

---

## Preguntas clave

- ¿Qué protocolos permiten ver contraseñas en texto plano?
    
    - HTTP, FTP, Telnet.
        
- ¿Qué podemos filtrar para detectar malware?
    
    - Tráfico DNS, comunicaciones inusuales con IPs externas, patrones binarios, etc.
        
- ¿Podemos usar Wireshark para mitigar ataques?
    
    - No directamente, pero sí para detectar y entenderlos, y así reforzar defensas.
        

---

## Glosario básico

- **Pcap**: Archivo de captura de paquetes.
    
- **Stream**: Flujo de paquetes relacionados en una sesión.
    
- **Handshake**: Intercambio inicial entre cliente y servidor (ej. TLS).
    
- **Payload**: Datos transportados en el paquete (contenido útil).
    
---
