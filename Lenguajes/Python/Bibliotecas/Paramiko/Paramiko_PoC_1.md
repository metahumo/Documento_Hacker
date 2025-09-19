
---

# PoC: Uso de la librería Paramiko en Python

En este documento exploraremos el uso de **Paramiko**, una librería de Python para interactuar con servidores SSH de forma programática. Mostraremos ejemplos prácticos de conexión, ejecución de comandos, transferencia de archivos y manejo de claves.

---

## 1. Instalación de Paramiko

Antes de usar Paramiko, debemos instalarla en nuestro entorno:

```bash
pip install paramiko
```

---

## 2. Conexión SSH básica

Para conectarnos a un servidor SSH necesitamos la **IP, el puerto, el usuario y la contraseña**. Creamos un cliente SSH, nos conectamos y ejecutamos comandos de manera remota.

```python
import paramiko

# Creamos el cliente SSH
cliente = paramiko.SSHClient()

# Aceptamos automáticamente claves desconocidas
cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# Conectamos al servidor
cliente.connect(hostname='192.168.1.74', port=22, username='usuario', password='contraseña')

# Ejecutamos un comando remoto
stdin, stdout, stderr = cliente.exec_command('uname -a')
print(stdout.read().decode())

# Cerramos la conexión
cliente.close()
```

**Explicación:**

- `SSHClient()` crea una instancia de cliente SSH.
    
- `set_missing_host_key_policy` evita errores por claves desconocidas.
    
- `exec_command` nos permite ejecutar comandos en el servidor remoto.
    

---

## 3. Autenticación con clave privada

En lugar de usar contraseña, podemos autenticarnos mediante una **clave privada RSA**.

```python
import paramiko

# Cargamos la clave privada
clave = paramiko.RSAKey.from_private_key_file('id_rsa')

cliente = paramiko.SSHClient()
cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cliente.connect(hostname='192.168.1.74', port=22, username='usuario', pkey=clave)

stdin, stdout, stderr = cliente.exec_command('whoami')
print(stdout.read().decode())

cliente.close()
```

**Explicación:**

- `from_private_key_file` carga nuestra clave RSA local.
    
- `pkey` se usa para autenticarnos en vez de contraseña.
    

---

## 4. Transferencia de archivos (SFTP)

Paramiko también nos permite transferir archivos de forma segura usando **SFTP**.

```python
import paramiko

cliente = paramiko.SSHClient()
cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cliente.connect('192.168.1.74', username='usuario', password='contraseña')

# Abrimos sesión SFTP
sftp = cliente.open_sftp()

# Subimos un archivo
sftp.put('archivo_local.txt', '/home/usuario/archivo_remoto.txt')

# Descargamos un archivo
sftp.get('/home/usuario/archivo_remoto.txt', 'archivo_descargado.txt')

# Cerramos SFTP y SSH
sftp.close()
cliente.close()
```

**Explicación:**

- `open_sftp()` inicia un canal SFTP para transferencia de archivos.
    
- `put()` sube archivos locales al servidor.
    
- `get()` descarga archivos del servidor a nuestra máquina.
    

---

## 5. Manejo de excepciones y logging

Siempre debemos manejar posibles errores de conexión o autenticación.

```python
import paramiko

cliente = paramiko.SSHClient()
cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    cliente.connect('192.168.1.74', username='usuario', password='contraseña')
    stdin, stdout, stderr = cliente.exec_command('ls -la')
    print(stdout.read().decode())
except paramiko.AuthenticationException:
    print('Error de autenticación: usuario o contraseña incorrectos')
except paramiko.SSHException as e:
    print(f'Error en SSH: {e}')
finally:
    cliente.close()
```

**Explicación:**

- Capturamos `AuthenticationException` para detectar fallos de usuario/contraseña.
    
- Capturamos `SSHException` para errores generales de SSH.
    
- Cerramos siempre la conexión en el bloque `finally`.
    

---

## 6. Enumeración de usuarios (PoC simple)

Podemos usar Paramiko para **probar usuarios** de manera remota, similar a CVE-2018-15473.

```python
import paramiko
import socket

usuarios = ['root', 'admin', 'test']

for user in usuarios:
    sock = socket.socket()
    try:
        sock.connect(('192.168.1.74', 22))
        transporte = paramiko.Transport(sock)
        transporte.start_client()
        try:
            transporte.auth_publickey(user, paramiko.RSAKey.generate(2048))
        except paramiko.ssh_exception.AuthenticationException:
            print(f"[+] {user} existe (clave inválida)")
        except paramiko.ssh_exception.SSHException:
            print(f"[-] {user} no existe")
        transporte.close()
    except Exception as e:
        print(f"Error al conectar: {e}")
```

**Explicación:**

- Probamos varios usuarios enviando claves RSA generadas al vuelo.
    
- Si el usuario existe, el servidor responde con `AuthenticationException`.
    
- Si no existe, se lanza otra excepción.
    

---

## 7. Conclusión

Con Paramiko podemos:

- Conectarnos a servidores SSH con usuario/contraseña o clave.
    
- Ejecutar comandos remotos.
    
- Transferir archivos mediante SFTP.
    
- Manejar errores y excepciones.
    
- Realizar pruebas de enumeración de usuarios para pentesting.
    

Esta librería es muy poderosa, pero siempre debemos **usar estos conocimientos de forma ética y legal**.

---
