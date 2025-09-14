
---

# PoC: Servidor TCP básico con Python

## Introducción

En este ejemplo creamos un **servidor TCP simple** usando la biblioteca `socket` de Python. Este tipo de prueba es útil en **ciberseguridad ofensiva y pruebas de red** para:

* Recibir conexiones desde clientes TCP.
* Entender cómo funcionan los sockets en modo servidor.
* Responder a clientes con mensajes HTTP simulados.
* Aprender la base para construir servicios propios o pruebas de payloads en laboratorio.

Este PoC complementa los ejemplos anteriores de **cliente TCP y escaneo de puertos**, mostrando la **parte del servidor**.

---

## Código explicado

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

### Paso a paso

1. **Creación del socket TCP**

```python
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
```

* `AF_INET` indica IPv4.
* `SOCK_STREAM` indica TCP.
* Este socket funcionará como **servidor**, aceptando conexiones entrantes.

---

2. **Asignación de IP y puerto**

```python
srv.bind(("0.0.0.0", 9000))
```

* `"0.0.0.0"` indica que el servidor escucha en **todas las interfaces** de la máquina.
* `9000` es el puerto donde el servidor recibirá conexiones.

---

3. **Escucha de conexiones**

```python
srv.listen(5)
```

* `listen(5)` indica que el servidor puede mantener **hasta 5 conexiones en cola**.
* El servidor ahora está **activo y esperando clientes**.

---

4. **Bucle principal de aceptación de clientes**

```python
while True:
    client, addr = srv.accept()
```

* `accept()` bloquea hasta que un cliente intente conectarse.
* `client` es el socket del cliente.
* `addr` es una tupla `(IP, puerto)` del cliente conectado.

---

5. **Recepción de datos del cliente**

```python
data = client.recv(2048)
```

* `recv(2048)` lee hasta 2048 bytes enviados por el cliente.
* No se procesan los datos en este ejemplo; simplemente se reciben.

---

6. **Respuesta al cliente**

```python
client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
```

* Se envía un mensaje **HTTP simple** de respuesta con contenido `"OK"`.
* Esto simula un **servicio HTTP básico** para pruebas.

---

7. **Cierre de la conexión**

```python
client.close()
```

* Termina la conexión con el cliente actual.
* El servidor queda listo para aceptar la siguiente conexión.

---

## Salida de ejemplo

```
[*] Esperando conexiones en 0.0.0.0:9000
[*] Conexión desde ('127.0.0.1', 38398)
[*] Conexión desde ('127.0.0.1', 38400)
```

* La primera línea indica que el servidor está escuchando.
* Cada línea siguiente indica **una conexión entrante** desde un cliente, mostrando **IP y puerto local del cliente**.
* En este ejemplo, los clientes se conectaron desde `localhost (127.0.0.1)`.

---

## Importancia en ciberseguridad ofensiva

1. **Simulación de servicios**

* Permite crear un **servidor de prueba** para realizar pruebas de clientes TCP, fuzzing o payloads.

---

2. **Aprender el flujo TCP**

* Se ve claramente la **aceptación de conexiones**, recepción de datos y envío de respuestas.
* Base para construir servidores más complejos o proxies.

---

3. **Pruebas de penetración en laboratorio**

* Se puede combinar con scripts de cliente TCP o escáneres para **probar seguridad de servicios**, manejo de sockets, o comportamiento frente a entradas maliciosas.

---

4. **Automatización de pruebas**

* Con este servidor se pueden crear **laboratorios controlados** para experimentar con clientes TCP automatizados o técnicas ofensivas sin comprometer sistemas reales.

---

En resumen, este PoC nos permite **levantar un servidor TCP básico en Python**, recibir conexiones de clientes, responder con mensajes HTTP simples, y establecer una **base para pruebas de red, pentesting y desarrollo de servicios propios**.

---
