
---

# PoC: Escaneo de puertos HTTP usando sockets en Python

## Introducción

En este ejemplo estamos utilizando **sockets en Python** para crear un **mini escáner de puertos HTTP**. Este tipo de prueba es útil en **ciberseguridad ofensiva** para:

* Detectar qué servicios HTTP están activos en un host o rango de puertos.
* Obtener información básica de los servidores (encabezados HTTP).
* Entender el manejo de errores y timeouts en conexiones TCP.

---

## Código explicado

```python
import socket

# Lista de puertos a escanear
puertos = [80, 8080, 8000]

host = "192.168.1.110"

for puerto in puertos:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        print(f"[+] Intentando conectar a {host}:{puerto}")
        s.connect((host, puerto))
        s.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        resp = s.recv(4096)
        print(f"[+] Puerto {puerto} abierto, respuesta:")
        print(resp.decode(errors="ignore").split("\r\n\r\n")[0])  # Solo encabezados
    except ConnectionRefusedError:
        print(f"[-] Puerto {puerto} cerrado")
    except socket.timeout:
        print(f"[-] Puerto {puerto} no responde (timeout)")
    finally:
        s.close()
```

### Paso a paso:

1. **Creación de lista de puertos**

```python
puertos = [80, 8080, 8000]
```

* Define los puertos a verificar en el host.
* Puede ampliarse a un rango completo para un escaneo más exhaustivo.

---

2. **Iteración sobre los puertos**

```python
for puerto in puertos:
```

* Se intenta conectar a cada puerto en el host objetivo.
* Esto permite descubrir servicios activos.

---

3. **Manejo de excepciones**

```python
except ConnectionRefusedError:
    print(f"[-] Puerto {puerto} cerrado")
except socket.timeout:
    print(f"[-] Puerto {puerto} no responde (timeout)")
```

* `ConnectionRefusedError`: el host está activo pero no hay servicio en ese puerto.
* `socket.timeout`: el host no responde en el tiempo esperado.
* Permite que el script continúe escaneando otros puertos sin interrumpirse.

---

4. **Recepción y filtrado de respuesta**

```python
resp = s.recv(4096)
print(resp.decode(errors="ignore").split("\r\n\r\n")[0])
```

* Solo se muestran los **encabezados HTTP** para obtener información del servicio.
* Evita imprimir todo el contenido HTML, manteniendo la salida limpia.

---

## Salida de ejemplo

```
[+] Intentando conectar a 192.168.1.110:80
[+] Puerto 80 abierto, respuesta:
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.11.2
Date: Sun, 14 Sep 2025 18:25:00 GMT
Content-type: text/html; charset=utf-8
Content-Length: 342

[+] Intentando conectar a 192.168.1.110:8080
[-] Puerto 8080 cerrado

[+] Intentando conectar a 192.168.1.110:8000
[-] Puerto 8000 no responde (timeout)
```

* `Puerto 80 abierto`: se detecta servicio HTTP.
* `Puerto 8080 cerrado`: no hay servicio escuchando.
* `Puerto 8000 no responde`: el host no responde o hay firewall.

---

## Importancia en ciberseguridad ofensiva

1. **Detección de servicios HTTP**

* Permite descubrir puertos activos que puedan exponer servicios vulnerables.

---

2. **Reconocimiento rápido**

* Los encabezados HTTP revelan información sobre el servidor, versión y tecnología usada.

---

3. **Automatización de auditorías**

* Este script puede ampliarse para escanear rangos de hosts y puertos automáticamente.
* Base para herramientas personalizadas de reconocimiento y enumeración.

---

4. **Manejo de errores seguro**

* Evita que un puerto cerrado o un host no disponible interrumpa la ejecución.
* Permite iterar sobre múltiples objetivos sin fallos.

---

En resumen, este PoC nos permite **escanear múltiples puertos HTTP en un host usando sockets en Python**, obteniendo información útil para **reconocimiento de servicios y pruebas iniciales de pentesting**.

---
