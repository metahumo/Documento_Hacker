
---

# PoC: Sniff ICMP con Scapy

## Introducción

En este ejemplo estamos utilizando **Scapy**, una potente librería de Python para la manipulación de paquetes de red, para construir, enviar y analizar paquetes **ICMP** (Internet Control Message Protocol). Este tipo de pruebas son comunes en **ciberseguridad ofensiva**, especialmente durante fases de **reconocimiento y enumeración de red**.

---

## Código explicado

```python
from scapy.all import *

# Mostrar version de Scapy
print("Scapy version:", conf.version)

# Construir un paquete IP + ICMP
pkt = IP(dst="<IP_Objetivo>")/ICMP()

# Enviar el paquete y esperar la primera respuesta
resp = sr1(pkt, timeout=2)

if resp:
    resp.show()
else:
    print("[!] Sin respuesta")
```

### Paso a paso:

1. **Importación de Scapy**  
    Importamos todas las funciones de Scapy con `from scapy.all import *`. Esto nos permite construir, enviar y recibir paquetes de red a bajo nivel.
    
2. **Mostrar versión de Scapy**  
    `conf.version` nos permite asegurarnos de que estamos usando la versión correcta y compatible para este PoC.
    
3. **Construcción del paquete**
    
    - `IP(dst="<IP_Objetivo>")` crea un encabezado IP con destino al host objetivo.
        
    - `/ICMP()` añade un paquete ICMP de tipo _echo request_ (ping) sobre la capa IP.  
        Esto nos permite simular un **ping manual**, pero con control completo sobre el paquete, a diferencia de la herramienta `ping` estándar.
        
4. **Envío y recepción de paquetes**
    
    - `sr1(pkt, timeout=2)` envía el paquete y espera la **primera respuesta**.
        
    - Si se recibe respuesta, `resp.show()` imprime toda la estructura del paquete de respuesta, incluyendo campos IP y ICMP.
        
    - Si no hay respuesta, se imprime un aviso de que no hubo comunicación con el host.
        

---

## Salida de ejemplo

```
Scapy version: 2.5.0
Begin emission:
Finished sending 1 packets.
.*
Received 2 packets, got 1 answers, remaining 0 packets
###[ IP ]###
  version   = 4
  ihl       = 5
  tos       = 0x0
  len       = 28
  id        = 63170
  ttl       = 64
  proto     = icmp
  src       = <IP_Objetivo>
  dst       = <IP_Atacante>
###[ ICMP ]###
     type      = echo-reply
     code      = 0
```

Esto indica que el host `<IP_Objetivo>` está activo y responde a ICMP, proporcionándonos información útil sobre su presencia y posibles configuraciones de red.

---

## Importancia en ciberseguridad ofensiva

1. **Reconocimiento activo de hosts**: Saber qué hosts están vivos es el primer paso en un pentest o auditoría de red.
    
2. **Detección de firewalls y filtros ICMP**: Si no hay respuesta, podría indicar que el host tiene filtros ICMP activos.
    
3. **Manipulación avanzada de paquetes**: A diferencia de herramientas estándar, podemos modificar cabeceras, flags, IDs y otros campos, lo que permite evadir sistemas de detección o hacer pruebas de **evasión y fingerprinting**.
    
4. **Automatización de pruebas**: Este tipo de scripts se puede integrar en auditorías automatizadas, escáneres de red personalizados o PoCs más complejas.
    

---

En resumen, este PoC nos permite **reconocer hosts, analizar respuestas ICMP y preparar la base para técnicas más avanzadas de pentesting**. Gracias a Scapy podemos interactuar con la red a nivel de paquete, lo cual es fundamental para ciberseguridad ofensiva.

---
