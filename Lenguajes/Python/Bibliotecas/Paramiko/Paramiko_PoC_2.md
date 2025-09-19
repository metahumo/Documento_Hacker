

---

# PoC Avanzado: Paramiko con túneles y multiplexing

En este documento exploraremos usos más avanzados de **Paramiko** para automatizar tareas remotas, crear túneles SSH y reenviar puertos. Estos ejemplos son útiles tanto para pentesting como para administración remota de sistemas.

---

## 1. Instalación de Paramiko

Si no lo hemos hecho todavía:

```bash
pip install paramiko
```

---

## 2. Conexión SSH y multiplexing de sesiones

Podemos abrir **varias sesiones sobre una misma conexión** para optimizar recursos.

```python
import paramiko

cliente = paramiko.SSHClient()
cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cliente.connect('192.168.1.74', username='usuario', password='contraseña')

# Creamos varias sesiones usando la misma conexión
comandos = ['uname -a', 'whoami', 'uptime']

for cmd in comandos:
    stdin, stdout, stderr = cliente.exec_command(cmd)
    print(f"Resultado de '{cmd}':")
    print(stdout.read().decode())

cliente.close()
```

**Explicación:**

- Reutilizamos una sola conexión SSH para ejecutar múltiples comandos.
    
- Esto es útil para automatizar tareas sin abrir múltiples conexiones independientes.
    

---

## 3. Reenvío de puertos locales (Local Port Forwarding)

Podemos reenviar un puerto local a un puerto remoto a través del servidor SSH:

```python
import paramiko
from paramiko import SSHClient
import threading
import socket

def reenvio_local(local_port, remote_host, remote_port, transport):
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.bind(('127.0.0.1', local_port))
    servidor.listen(5)
    print(f"Reenvío iniciado: localhost:{local_port} -> {remote_host}:{remote_port}")

    while True:
        client_sock, addr = servidor.accept()
        chan = transport.open_channel("direct-tcpip", (remote_host, remote_port), addr)
        threading.Thread(target=transferir_datos, args=(client_sock, chan)).start()

def transferir_datos(src, dest):
    while True:
        datos = src.recv(1024)
        if len(datos) == 0:
            break
        dest.send(datos)
    src.close()
    dest.close()

cliente = SSHClient()
cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cliente.connect('192.168.1.74', username='usuario', password='contraseña')

transport = cliente.get_transport()
threading.Thread(target=reenvio_local, args=(8000, '127.0.0.1', 80, transport)).start()
```

**Explicación:**

- Creamos un servidor local en el puerto `8000`.
    
- Todo tráfico que llegue a ese puerto se reenviará al puerto `80` del servidor remoto.
    
- Utilizamos `transport.open_channel` para abrir canales TCP sobre SSH.
    

---

## 4. Reenvío de puertos remotos (Remote Port Forwarding)

También podemos abrir un puerto en el servidor SSH que se redirija a nuestra máquina local:

```python
import paramiko, threading, socket

# Similar al reenvío local, pero invertido
# En este caso configuramos el puerto en el servidor SSH
```

**Explicación:**

- Permite que servicios locales estén disponibles en la red del servidor remoto.
    
- Muy útil para acceder a servicios internos protegidos por firewall.
    

---

## 5. Transferencia de archivos avanzada

Podemos transferir directorios completos y automatizar la sincronización:

```python
import paramiko, os

def subir_directorio(sftp, local_dir, remote_dir):
    for root, dirs, files in os.walk(local_dir):
        for d in dirs:
            try:
                sftp.mkdir(os.path.join(remote_dir, d))
            except:
                pass
        for f in files:
            sftp.put(os.path.join(root, f), os.path.join(remote_dir, f))

cliente = paramiko.SSHClient()
cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cliente.connect('192.168.1.74', username='usuario', password='contraseña')

sftp = cliente.open_sftp()
subir_directorio(sftp, 'mi_directorio_local', '/home/usuario/directorio_remoto')
sftp.close()
cliente.close()
```

**Explicación:**

- Recorremos un directorio local y lo subimos completo al servidor.
    
- Creamos directorios remotos si no existen.
    

---

## 6. Manejo de excepciones en túneles y SFTP

Siempre debemos capturar errores y cerrar conexiones de manera segura:

```python
import paramiko

cliente = paramiko.SSHClient()
cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    cliente.connect('192.168.1.74', username='usuario', password='contraseña')
    sftp = cliente.open_sftp()
    sftp.put('archivo.txt', '/home/usuario/archivo.txt')
except paramiko.AuthenticationException:
    print('Error de autenticación')
except paramiko.SSHException as e:
    print(f'Error en SSH: {e}')
finally:
    try:
        sftp.close()
    except:
        pass
    cliente.close()
```

**Explicación:**

- Capturamos errores de autenticación y de SSH.
    
- Cerramos SFTP y SSH incluso si ocurre un error.
    

---

## 7. Conclusión avanzada

Con Paramiko podemos:

- Ejecutar múltiples comandos sobre la misma conexión (multiplexing).
    
- Crear túneles SSH y reenviar puertos locales o remotos.
    
- Transferir directorios completos de forma automática.
    
- Manejar excepciones y mantener la conexión estable.
    

Estas técnicas son útiles para pentesting avanzado, administración de servidores y automatización de tareas remotas.

---
