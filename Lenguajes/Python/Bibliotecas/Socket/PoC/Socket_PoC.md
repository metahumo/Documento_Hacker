
---

# PoC — Biblioteca `socket` (Python)

## Resumen

Pequeña guía práctica (PoC) sobre la biblioteca estándar **`socket`** en Python, orientada a uso en pruebas de seguridad y aprendizaje. Incluye ejemplos básicos de cliente/servidor TCP y UDP, técnicas de escaneo simples (connect-scan), manejo de timeouts, sockets no bloqueantes, uso de `select`/`selectors`, raw sockets (nota: requieren privilegios) y recomendaciones para usos ofensivos controlados.

[Ver tutorial sobre scan_port.py](../../../Utilidades%20Ofensivas/Escaneos/scan_port_tutorial.md)

## Requisitos

- Python 3.8+ (preferible en un entorno virtual).
    
- No hace falta instalar paquetes adicionales para las funcionalidades básicas (socket es parte de la stdlib).
    
- **Permisos de administrador** para raw sockets o ciertas operaciones de bajo nivel.
    
- Ejecutar pruebas solo en entornos autorizados (lab / máquinas propias).
    

---

## Instalación rápida

No hace falta instalar `socket` (viene con Python). Recomendamos crear un entorno virtual para el resto de herramientas:

```bash
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
```

Si vas a usar raw sockets o captura avanzada, ejecuta con `sudo` en Linux o usa capacidades (`setcap`) según necesites.

---

## 1) Cliente TCP básico (conexión y envío)

Ver [socket_client.py](../Scripts/socket_client.md) y [socket_client_2.py](../Scripts/socket_client_2.md)

`tcp_client_simple.py`:

```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)  # timeout en segundos
try:
    s.connect((" <IP_VICTIMA> ", 80))
    s.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    resp = s.recv(4096)
    print(resp.decode(errors="ignore"))
finally:
    s.close()
```

**Qué extraer programáticamente**

- `s.getpeername()` → dirección remota.
    
- `s.getsockname()` → dirección local.
    
- Tiempo de ida y vuelta (RTT) midiendo antes/después de `connect`/`send`.
    

---

## 2) Servidor TCP sencillo (bind / listen / accept)

[socket_tcp.py:](../Scripts/socket_tcp.md)

`tcp_server_simple.py`:

```python
import socket

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.bind(("0.0.0.0", 9000))
srv.listen(5)
print("[*] Esperando conexiones en 0.0.0.0:9000")
while True:
    client, addr = srv.accept()
    print("[*] Conexión desde", addr)
    data = client.recv(2048)
    client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    client.close()
```

Útil para pruebas de banner grabbing, honeypots o reenvío controlado de servicios.

---

## 3) UDP cliente/servidor simple

[socket_client.py:](../Scripts/socket_client.md)

`udp_client_simple.py`:

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(b"ping", ("<IP_VICTIMA>", 12345))
try:
    data, addr = s.recvfrom(4096)
    print("Respuesta:", data, "from", addr)
except socket.timeout:
    print("Sin respuesta")
s.close()
```

`udp_server_simple.py` recibe con `recvfrom` y responde con `sendto`.

---

## 4) Escaneo TCP básico usando connect (PoC rápido)

Podemos usar el enfoque `socket.connect()` para detectar puertos abiertos (versión simple similar a la tuya).

`port_scanner_basic.py` (snippet):

```python
import socket

def is_open(target, port, timeout=1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((target, port))
        return True
    except:
        return False
    finally:
        s.close()
```

Complementar con `ThreadPoolExecutor`, parsing de rangos y `argparse` da un escáner usable (ver tu script final).

---

## 5) Sockets no bloqueantes y `select` / `selectors`

- `s.setblocking(False)` para operaciones no bloqueantes.
    
- `select.select()` o el módulo `selectors` para multiplexado eficiente (útil en servidores y en pruebas donde gestionamos muchas conexiones sin threading).
    

Ejemplo con `selectors`:

```python
import selectors, socket

sel = selectors.DefaultSelector()
srv = socket.socket(); srv.bind(("0.0.0.0",9001)); srv.listen()
srv.setblocking(False)
sel.register(srv, selectors.EVENT_READ, data=None)

while True:
    events = sel.select(timeout=1)
    for key, mask in events:
        if key.data is None:
            client, addr = srv.accept()
            client.setblocking(False)
            sel.register(client, selectors.EVENT_READ, data=addr)
        else:
            data = key.fileobj.recv(1024)
            if data:
                key.fileobj.sendall(b"OK")
            else:
                sel.unregister(key.fileobj)
                key.fileobj.close()
```

---

## 6) Raw sockets (requiere privilegios) — advertencia

Permiten enviar/recibir paquetes IP/ICMP/TCP construidos manualmente (útil para pruebas muy específicas), pero **requieren root** y cuidado legal.

Ejemplo simple (solo lectura ICMP):

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
pkt, addr = s.recvfrom(65535)
print(pkt[:64])
```

**Nota:** Para generar paquetes TCP/ICMP complejos sin parsear manualmente, Scapy suele ser más cómodo; `socket` raw se usa cuando se quiere máximo control con stdlib.

---

## 7) Opciones útiles de socket (setsockopt)

- `socket.SO_REUSEADDR` para reusar direcciones rápidamente en servidores:
    

```python
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
```

- `socket.settimeout()` para evitar bloqueos indefinidos.
    

---

## 8) IPv6 y familia de direcciones

- `socket.AF_INET` → IPv4
    
- `socket.AF_INET6` → IPv6
    
- Atención a `getaddrinfo` para resolver nombres multiplataforma:
    

```python
import socket
infos = socket.getaddrinfo("example.com", "http", proto=socket.IPPROTO_TCP)
```

---

## 9) TLS / SSL con `ssl` (envolver sockets)

Para pruebas sobre TLS podemos envolver sockets con `ssl`:

```python
import socket, ssl
s = socket.create_connection(("example.com", 443))
ss = ssl.create_default_context().wrap_socket(s, server_hostname="example.com")
print(ss.getpeercert())
```

Útil para banner grabbing seguro o pruebas de configuración TLS.

---

## 10) Técnicas comunes en pentesting con `socket`

- **Banner grabbing**: conectar a un servicio y leer su respuesta para identificar versión.
    
- **Port scanning básico**: connect-scan (rápido y simple).
    
- **Brute-force sobre servicios**: automatizar intentos (con cautela).
    
- **Reenvío/Proxy simple**: crear servidores que redirigen tráfico para MITM en entornos controlados.
    
- **Fuzzing de servicios**: enviar cargas malformadas y observar fallos (usar con autorización).
    

---

## Buenas prácticas y recomendaciones

- Ejecutar siempre en un **lab** o con autorización por escrito para evitar problemas legales.
    
- Limitar el `rate` y usar `sleep` o control de concurrencia para no saturar la red.
    
- Manejar excepciones y cerrar sockets (`finally: s.close()`) para evitar fugas.
    
- Evitar `sudo` en scripts que se ejecuten en entornos de producción por riesgo de escalado accidental.
    
- Registrar (log) resultados y errores para reproducibilidad y auditoría.
    
- Para tareas complejas (construcción de paquetes, sniffing) preferir **Scapy**; `socket` es ideal para cliente/servidor y pruebas a nivel de socket.
    

---

## Recursos y enlaces rápidos (doc interno)

- Documentación oficial `socket` (Python stdlib): [https://docs.python.org/3/library/socket.html](https://docs.python.org/3/library/socket.html)
    
- Módulos útiles: `socket`, `ssl`, `selectors`, `concurrent.futures`, `struct` (para empaquetado binario)
    
- Para manipulación de paquetes a bajo nivel: considerar **Scapy** cuando necesitemos parsing/inyección detallada.
    
---

