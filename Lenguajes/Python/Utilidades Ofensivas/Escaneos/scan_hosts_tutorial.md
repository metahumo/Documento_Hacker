
---

# Evolución del Script de Escaneo ARP

A lo largo de la creación de un script pasamos por diferentes etapas, cada una agregando una funcionalidad clave para llegar a un escáner ARP completo y usable. Vamos a analizar cómo ha evolucionado el código paso a paso.

---

## Primer script: Envío ARP mínimo (detección inicial)

```python
# arp_minimo.py
from scapy.all import ARP, Ether, srp

target = "192.168.1.0/24"
arp = ARP(pdst=target)
eth = Ether(dst="ff:ff:ff:ff:ff:ff")
pkt = eth/arp

answered, unanswered = srp(pkt, timeout=1, verbose=False)

for sent, received in answered:
    print(received.psrc, received.hwsrc)
```

### ¿Qué hace?

* Construye una petición ARP en broadcast para la subred indicada.
* Envía el paquete en capa 2 con `srp()` y recoge las respuestas.
* Imprime las IP y MAC de los hosts que responden.

### ¿Por qué sirve?

* Es la base mínima para entender cómo enviar peticiones ARP y recibir respuestas con Scapy.
* Muy útil para comprobar que podemos detectar hosts en la LAN sin depender de puertos.

---

## Segundo script: CLI y manejo de señales (interactividad básica)

```python
#!/usr/bin/env python3
# arp_cli_signal.py
import argparse, sys, signal
import scapy.all as scapy

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(0)

signal.signal(signal.SIGINT, def_handler)

parser = argparse.ArgumentParser(description="Escaner ARP de host")
parser.add_argument("-t", "--target", dest="target", help="192.168.1.0/24")
args = parser.parse_args()
if not args.target:
    parser.print_help()
    sys.exit(1)

arp = scapy.ARP(pdst=args.target)
eth = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
pkt = eth/arp
answered, _ = scapy.srp(pkt, timeout=1, verbose=False)
print(answered.summary())
```

### ¿Qué añade?

* Entrada por línea de comandos (`-t/--target`) para especificar objetivo.
* Manejo de `SIGINT` (Ctrl+C) para salir limpiamente.
* Uso de `answered.summary()` para una salida compacta similar al ejemplo original.

### ¿Por qué es útil?

* Permite ejecutar el PoC desde terminal con distintos objetivos.
* Hace el script más robusto frente a interrupciones del usuario.

---

## Tercer script: Entrada flexible (CIDR, rangos y listas) y salida parseable

```python
#!/usr/bin/env python3
# arp_input_flexible.py
import argparse, sys, signal, ipaddress
import scapy.all as scapy

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(0)
signal.signal(signal.SIGINT, def_handler)

def expand_target(t):
    if '/' in t:
        return [str(ip) for ip in ipaddress.IPv4Network(t)]
    if '-' in t:
        base, rng = t.rsplit('.', 1)
        start, end = rng.split('-')
        return [f"{base}.{i}" for i in range(int(start), int(end)+1)]
    return [h.strip() for h in t.split(',')]

parser = argparse.ArgumentParser()
parser.add_argument("-t","--target", dest="target", required=True,
                    help="CIDR (192.168.1.0/24), rango (192.168.1.1-100) o lista (a,b,c)")
args = parser.parse_args()

hosts = expand_target(args.target)
targets = ",".join(hosts)
arp = scapy.ARP(pdst=targets)
eth = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
pkt = eth/arp
answered, _ = scapy.srp(pkt, timeout=1, verbose=False)

results = []
for sent, recv in answered:
    results.append({"ip": recv.psrc, "mac": recv.hwsrc})

for r in results:
    print(r["ip"], r["mac"])
```

### ¿Qué añade?

* Soporte para CIDR, rangos tipo `192.168.1.1-100` y listas separadas por coma.
* Convierte las respuestas en una estructura (lista de diccionarios) fácil de procesar.
* Mantiene manejo de señales y CLI.

### ¿Por qué es útil?

* Facilita el uso en scripts/automatización al poder parsear la salida.
* Permite un input más natural al trabajar con subredes o rangos concretos.

---

## Cuarto script: Versión final — salida limpia (tabla/JSON), recomendaciones y robustez

```python
#!/usr/bin/env python3
# scan_hosts_final.py
"""
PoC final: escáner ARP con Scapy — entrada flexible, manejo de señales y salida limpia (tabla / JSON).
Uso:
    sudo python3 scan_hosts_final.py -t 192.168.1.0/24 [--json]
"""
import argparse
import scapy.all as scapy
import sys
import signal
import ipaddress
import json

def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(0)

signal.signal(signal.SIGINT, def_handler)

def get_args():
    p = argparse.ArgumentParser(description='Escaner ARP de host')
    p.add_argument("-t", "--target", dest="target", required=True,
                   help='CIDR (192.168.1.0/24), rango (192.168.1.1-100) o lista (a,b,c)')
    p.add_argument("--json", dest="js", action="store_true", help="Salida en JSON")
    return p.parse_args()

def expand_target(target):
    if '/' in target:
        return [str(ip) for ip in ipaddress.IPv4Network(target)]
    if '-' in target:
        prefix, rng = target.rsplit('.', 1)
        start, end = rng.split('-')
        return [f"{prefix}.{i}" for i in range(int(start), int(end)+1)]
    if ',' in target:
        return [x.strip() for x in target.split(',')]
    return [target]

def scan(ip_list, timeout=1):
    pdst = ",".join(ip_list)
    arp_packet = scapy.ARP(pdst=pdst)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp_packet
    answered, _ = scapy.srp(packet, timeout=timeout, verbose=False)
    results = []
    for sent, recv in answered:
        results.append({"ip": recv.psrc, "mac": recv.hwsrc})
    return results

def print_table(results):
    # Impresión simple en tabla sin dependencias externas
    if not results:
        print("\n[!] No se detectaron hosts.\n")
        return
    print("\n=== Hosts detectados ===\n")
    print(f"{'IP':<16} {'MAC':<18}")
    print("-" * 35)
    for r in results:
        print(f"{r['ip']:<16} {r['mac']:<18}")

def main():
    args = get_args()
    targets = expand_target(args.target)
    results = scan(targets)
    if args.js:
        print(json.dumps(results, indent=4))
    else:
        print_table(results)

if __name__ == "__main__":
    main()
```

### ¿Qué añade?

* Salida en **tabla legible** por humanos y opción `--json` para integración automática.
* Entrada flexible y manejo de `SIGINT` heredados de etapas previas.
* Sin dependencias externas obligatorias para impresión tabular (fácil de incorporar en repositorios).

### ¿Por qué es útil?

* Permite usar el PoC tanto de forma interactiva como en pipelines (JSON).
* Facilita generar reportes y alimentar otras fases (fingerprinting, inventario).
* Es robusto y sencillo de entender/editar.

---

## Conclusión: ¿Por qué esta evolución?

* **Inicio sencillo (envío ARP)** → nos asegura que podemos detectar hosts a bajo nivel.
* **Interacción y control (CLI y señales)** → nos permite ejecutar y parar el PoC de forma limpia.
* **Flexibilidad de entradas** → facilita pruebas rápidas sobre CIDR, rangos o listas sin preprocesar.
* **Salida estructurada** → convierte un PoC en una pequeña herramienta usable: tabla para lectura humana y JSON para pipelines.

---
