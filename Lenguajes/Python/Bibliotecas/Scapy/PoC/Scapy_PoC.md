
# PoC — Scapy

---

## Resumen

Pequeña guía práctica (PoC) de Scapy orientada a uso en pruebas de seguridad y aprendizaje. Incluye instalación, ejemplos básicos de captura (`sniff`), creación y envío de paquetes (`send`, `sr`, `sr1`), parsing de respuestas y ejemplos típicos de uso en ciberseguridad (escaneo básico, manipulación de cabeceras, consultas DNS). 

[Ver tutorial sobre DNS_spoofing.py](../../Utilidades&20Ofensivas/DNS%2'Spoofing/dns_spoofing_tutorial.md) 

---

## Requisitos

- Python 3.8+ (preferible en un entorno virtual)
    
- Permisos de administrador/privilegio (alguna operaciones requieren raw sockets)
    
- Instalar Scapy: `pip install scapy` (en Debian/Ubuntu puede ser `sudo apt install python3-scapy`)
    

## Instalación rápida

```bash
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install scapy
```

> Nota: En sistemas Linux es posible que necesites ejecutar algunos scripts con `sudo` para acceso a raw sockets o usar capacidades POSIX (`setcap`).

---

## 1) Import básico y funciones principales

[sniff_icmp.py:](../Scripts/sniff_icmp.md)

```python
from scapy.all import *

# Mostrar versión
print("Scapy version:", conf.version)

# Construir un paquete IP + ICMP
pkt = IP(dst="8.8.8.8")/ICMP()

# Enviar y esperar respuesta (sr1 devuelve la primera respuesta recibida)
resp = sr1(pkt, timeout=2)
if resp:
    resp.show()
else:
    print("Sin respuesta")
```

### Cómo extraer programáticamente lo que me interesa

Puedo obtener los valores clave del objeto `resp` devuelto por `sr1` con expresiones como las siguientes:

```python
print(resp[IP].src)        # IP origen que respondió
print(resp[IP].dst)        # mi IP origen
print(resp[IP].ttl)        # TTL
print(resp[IP].len)        # longitud total
print(resp[ICMP].type)     # tipo ICMP (0 = echo-reply)
print(resp[ICMP].code)     # código ICMP
if resp.haslayer(Raw):
    print(resp[Raw].load)  # payload si existe
```

Con esos valores puedo registrar resultados, estimar RTT midiendo tiempo antes/después del `sr1`, y automatizar un flujo de trabajo: discovery ICMP → fingerprint mínimo → escaneo TCP dirigido a hosts vivos.

---

## 2) Sniffing básico

Capturar paquetes en una interfaz determinada y filtrar por BPF (p.ej. sólo ICMP).

[sniffing_basic.py:](../Scripts/sniffing_basic.md)

```python
from scapy.all import sniff

# Captura 10 paquetes ICMP
pkts = sniff(filter="icmp", count=10, iface="eth0")
for p in pkts:
    p.summary()
```

También es posible usar una función callback para procesar paquetes en tiempo real.

---

## 3) Escaneo TCP básico (SYN scan)

Ejemplo que envía SYN y analiza respuestas para detectar puertos abiertos/CLOSED.

[scan_tcp_basic.py:](../Scripts/scan_tcp_basic.md)

```python
from scapy.all import IP, TCP, sr

def syn_scan(target, ports):
    ans, _ = sr([IP(dst=target)/TCP(dport=p, flags='S') for p in ports], timeout=1, verbose=0)
    open_ports = []
    for s, r in ans:
        if r.haslayer(TCP) and r[TCP].flags == 0x12:  # SYN/ACK
            open_ports.append(s[TCP].dport)
    return open_ports

if __name__ == '__main__':
    print(syn_scan('192.168.1.100', [22,80,443,8080]))
```

---

## 4) ARP discovery (búsqueda de hosts en LAN)

[scan_hosts_basic.py:](../Scripts/scan_hosts_basic.md)

```python
from scapy.all import ARP, Ether, srp

def arp_scan(net):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=net)
    ans, _ = srp(pkt, timeout=2, verbose=0)
    return [(r.psrc, r.hwsrc) for s,r in ans]

print(arp_scan("192.168.1.0/24"))
```

---

## Buenas prácticas y recomendaciones

- Usar un entorno lab (máquinas virtuales, red aislada) y obtener permisos.
    
- Evitar dejar scripts automatizados con `sudo` en producción.
    
- Registrar resultados y pruebas para auditoría.
    
- Familiarizarse con `scapy.layers` para protocolos concretos (HTTP, DNS, 802.11, 802.3...).
    

---

## Recursos y enlaces rápidos (doc interno)

- Documentación oficial de Scapy: [https://scapy.net/](https://scapy.net/)
    
- Módulos útiles: `scapy.layers.inet`, `scapy.layers.l2`, `scapy.layers.dns`

---
