
---

# Evolución del Script de Port Scanning (TCP)

A lo largo de la creación de un script de escaneo TCP pasamos por varias etapas. Cada etapa añade una funcionalidad clave hasta obtener un escáner práctico y reutilizable. Vamos a analizar cómo evoluciona el código paso a paso.

---

## Primer script: Conexión única (detectar si un puerto está abierto)

```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1)
try:
    s.connect((" <IP_VICTIMA> ", 80))
    print("[+] Puerto 80 abierto")
except:
    print("Puerto cerrado o filtrado")
finally:
    s.close()
```

### ¿Qué hace?

* Intenta abrir una conexión TCP a un puerto concreto (p. ej. 80).
* Si la conexión se establece, consideramos el puerto **abierto**; si falla, está **cerrado/filtrado**.

### ¿Qué aporta?

* Es la base mínima de cualquier escáner TCP: comprobación por conexión.
* Nos sirve para entender el mecanismo `socket.connect()` y el manejo de timeouts.

---

## Segundo script: Escaneo secuencial sobre varios puertos (bucle)

```python
import socket

def scan_ports(target, ports):
    for port in ports:
        s = socket.socket()
        s.settimeout(1)
        try:
            s.connect((target, port))
            print(f"[+] Puerto {port} abierto")
        except:
            pass
        finally:
            s.close()

scan_ports("<IP_VICTIMA>", [22, 80, 443, 8080])
```

### ¿Qué añade?

* Escanea varios puertos en secuencia con un bucle.
* Nos permite obtener una lista de puertos abiertos en una sola ejecución.

### ¿Por qué es útil?

* Permite ampliar el alcance del escaneo sin modificar el flujo básico.
* Fácil de leer y depurar, pero lento para rangos grandes.

---

## Tercer script: Soporte a rangos y listas (parsing de puertos)

```python
def parse_port(port_str):
    if '-' in port_str:
        start, end = map(int, port_str.split('-'))
        return range(start, end+1)
    elif ',' in port_str:
        return map(int, port_str.split(','))
    else:
        return (int(port_str),)

# Uso:
ports = parse_port("1-1024")  # devuelve range(1,1025)
```

### ¿Qué añade?

* Permite indicar puertos individuales (`80`), listas (`22,80,443`) o rangos (`1-1024`).
* Mejora la usabilidad para escanear rangos grandes sin modificar el código.

### ¿Por qué es útil?

* Hace el script flexible y apto para distintos tipos de escaneo (rápido vs. exhaustivo).

---

## Cuarto script: Concurrencia con ThreadPoolExecutor (más rápido)

```python
from concurrent.futures import ThreadPoolExecutor
import socket

def port_scanner(target, port):
    s = socket.socket()
    s.settimeout(1)
    try:
        s.connect((target, port))
        print(f"[+] El puerto {port} está abierto")
    except:
        pass
    finally:
        s.close()

def scan_port(ports, target):
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(lambda p: port_scanner(target, p), ports)
```

### ¿Qué añade?

* Se usan hilos para escanear muchos puertos en paralelo (`max_workers=100`).
* Reduce drásticamente el tiempo de escaneo sobre rangos grandes.

### ¿Por qué es útil?

* Hace el escaneo práctico y rápido en redes controladas.
* Necesario cuando queremos resultados en tiempo razonable.

---

## Quinto script: Interfaz de línea de comandos y manejo de errores (versión final)

```python
#!/usr/bin/env python3
import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor

def get_arguments():
    parser = argparse.ArgumentParser(description='Fast TCP Port Scan')
    parser.add_argument("-t", "--target", required=True, dest="target", help='IP víctima (Ej: -t <IP_VICTIMA>)')
    parser.add_argument("-p", "--port", required=True, dest="port", help='Puerto/s o rango (Ej: -p 1-1024)')
    options = parser.parse_args()
    return options.target, options.port

def create_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    return s

def port_scanner(target, port):
    s = create_socket()
    try:
        s.connect((target, port))
        print(f"\n[+] El puerto {port} está abierto")
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    finally:
        s.close()

def scan_port(ports, target):
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(lambda port: port_scanner(target, port), ports)

def parse_port(port_str):
    if '-' in port_str:
        start, end = map(int, port_str.split('-'))
        return range(start, end+1)
    elif ',' in port_str:
        return map(int, port_str.split(','))
    else:
        return (int(port_str),)

def main():
    try:
        target, port_str = get_arguments()
        print(f"\n[i] Escanenado {target}, espere...")
        ports = parse_port(port_str)
        scan_port(ports, target)
        print(f"\n[i] Escaneo finalizado con éxito\n")
    except KeyboardInterrupt:
        sys.exit(1)

if __name__ == '__main__':
    main()
```

### ¿Qué añade respecto a versiones anteriores?

* `argparse` para una interfaz de usuario clara y reutilizable.
* Manejo de excepciones más preciso (`socket.timeout`, `ConnectionRefusedError`, `OSError`).
* Estructura modular (funciones separadas) que facilita mantenimiento y pruebas.
* Concurrencia y soporte de rangos ya integrados.

---

## Salida de ejemplo (ejecución)

Ejecutando:

```
python3 port_scanner_basic.py -t <IP_VICTIMA> -p 22-25
```

Salida esperada (ejemplo):

```
[i] Escanenado <IP_VICTIMA>, espere...

[+] El puerto 22 está abierto

[i] Escaneo finalizado con éxito
```

(La salida muestra sólo los puertos que respondieron con conexión establecida; los demás se silencian por eficiencia.)

---

## Conclusión: ¿por qué esta evolución?

* Partimos de una **prueba mínima** para entender `socket.connect()`.
* Añadimos **automación y parsing** para manejar distintos formatos de entrada.
* Introducimos **concurrencia** para hacer el escaneo rápido y utilizable en rangos reales.
* Finalmente, añadimos **CLI, manejo de errores y modularidad** para que el script sea mantenible y apto para integrarse en auditorías.

Esta progresión (prueba básica → análisis/iteración → focalización → optimización → interfaz/robustez) es el patrón habitual para convertir una idea en una herramienta práctica y segura para pruebas de seguridad autorizadas.

---
