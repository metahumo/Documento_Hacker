
---

# PoC: Cliente HTTP usando sockets en Python

## Introducción

En este ejemplo estamos utilizando la **biblioteca `socket` de Python** para crear un **cliente HTTP básico**. Este tipo de prueba es útil en **ciberseguridad ofensiva** para:

* Verificar si un host está escuchando en un puerto específico.
* Interactuar manualmente con servicios HTTP.
* Entender cómo funcionan las conexiones TCP y la transferencia de datos a bajo nivel.

---

## Código explicado

```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)  # timeout en segundos
try:
    s.connect(("192.168.1.110", 80))
    s.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    resp = s.recv(4096)
    print(resp.decode(errors="ignore"))
finally:
    s.close()
```

### Paso a paso:

1. **Creación del socket**

```python
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
```

* `AF_INET` indica que se usará IPv4.
* `SOCK_STREAM` indica que se usará TCP.

---

2. **Configuración de timeout**

```python
s.settimeout(3)
```

* Espera máxima de 3 segundos para conexiones y operaciones.
* Evita que el script se quede colgado si el host no responde.

---

3. **Conexión al host**

```python
s.connect(("192.168.1.110", 80))
```

* Intenta establecer una conexión TCP al puerto 80 del host `192.168.1.110`.
* Si el host no está escuchando, se genera `ConnectionRefusedError`.

---

4. **Envío de solicitud HTTP**

```python
s.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
```

* Se envía una solicitud HTTP GET.
* `sendall` asegura que todos los bytes sean enviados.
* `b""` indica que los datos son enviados en formato bytes.

---

5. **Recepción de respuesta**

```python
resp = s.recv(4096)
print(resp.decode(errors="ignore"))
```

* `recv(4096)` recibe hasta 4096 bytes de respuesta.
* `decode(errors="ignore")` convierte los bytes a string ignorando caracteres inválidos.
* Muestra la respuesta HTTP del servidor.

---

6. **Cierre de la conexión**

```python
finally:
    s.close()
```

* Asegura que el socket se cierre correctamente, liberando recursos.

---

## Salida de ejemplo

```
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.11.2
Date: Sun, 14 Sep 2025 18:10:06 GMT
Content-type: text/html; charset=utf-8
Content-Length: 342
```

* `HTTP/1.0 200 OK` indica que la solicitud fue exitosa.
* `Server` muestra el tipo de servidor que respondió.
* `Content-type` y `Content-Length` describen el contenido recibido.

---

## Importancia en ciberseguridad ofensiva

1. **Detección de servicios activos**

* Permite identificar si un host está escuchando en un puerto específico (por ejemplo, HTTP en el 80).

---

2. **Reconocimiento de servicios**

* Analizando los encabezados, se puede obtener información del servidor (tipo, versión, sistema operativo).

---

3. **Pruebas de seguridad**

* Base para pruebas como **fuzzing HTTP**, **enumeración de directorios**, y **pruebas de inyección de payloads**.

---

4. **Automatización de auditorías**

* Se puede integrar en scripts de pentesting para verificar múltiples hosts de manera automatizada.

---

En resumen, este PoC nos permite **crear un cliente HTTP básico usando sockets en Python**, útil para **reconocimiento de servicios y pruebas iniciales en ciberseguridad ofensiva**.

---

