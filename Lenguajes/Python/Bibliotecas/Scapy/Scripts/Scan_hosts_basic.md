
---

# PoC: Escaneo de hosts con ARP usando Scapy

## Introducción

En este ejemplo estamos utilizando **Scapy** para realizar un **escaneo ARP** en una red local. Este tipo de prueba es muy útil en **ciberseguridad ofensiva** para descubrir qué hosts están activos dentro de un rango de IP sin depender de puertos abiertos o servicios específicos.

---

## Código explicado

```python
from scapy.all import ARP, Ether, srp

def arp_scan(net):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=net)
    ans, _ = srp(pkt, timeout=2, verbose=0)
    return [(r.psrc, r.hwsrc) for s,r in ans]

print(arp_scan("192.168.1.0/24"))
```

### Paso a paso:

1. **Importación de Scapy**  
    Importamos `ARP`, `Ether` y `srp`.
    
    - `ARP` permite construir paquetes ARP para descubrir hosts en la red.
        
    - `Ether` permite crear tramas Ethernet para la capa de enlace.
        
    - `srp` envía paquetes a la capa de enlace y espera respuestas.
        
2. **Construcción del paquete ARP**
    
    ```python
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=net)
    ```
    
    - `Ether(dst="ff:ff:ff:ff:ff:ff")` envía el paquete a **broadcast**, asegurando que todos los hosts de la red lo reciban.
        
    - `ARP(pdst=net)` indica el rango de IP que queremos escanear (por ejemplo, `"192.168.1.0/24"`).
        
3. **Envío de paquetes y recepción de respuestas**
    
    ```python
    ans, _ = srp(pkt, timeout=2, verbose=0)
    ```
    
    - `srp` envía el paquete a todos los hosts y devuelve las respuestas recibidas.
        
    - `timeout=2` espera hasta 2 segundos por respuesta.
        
    - `verbose=0` evita mensajes de salida adicionales.
        
4. **Recopilación de resultados**
    
    ```python
    return [(r.psrc, r.hwsrc) for s,r in ans]
    ```
    
    - `r.psrc` = IP del host que respondió.
        
    - `r.hwsrc` = MAC del host que respondió.
        
    - Devuelve una lista de tuplas con la IP y MAC de cada host activo.        

---

## Salida de ejemplo

```
[('<IP_1>', '<MAC_1>'), ('<IP_2>', '<MAC_2>'), ('<IP_3>', '<MAC_3>'), ('<IP_4>', '<MAC_4>'), ('<IP_Objetivo>', '<MAC_Objetivo>')]
```

- Cada tupla indica un **host activo** detectado en la red.
    
- Por ejemplo, `<IP_Objetivo>` es la máquina que queremos identificar, y `<MAC_Objetivo>` es su dirección MAC correspondiente.
    
---

## Importancia en ciberseguridad ofensiva

1. **Descubrimiento de hosts en la red**
    
    - Permite identificar todos los dispositivos conectados a una LAN sin depender de servicios específicos ni puertos abiertos.
        
2. **Reconocimiento pasivo y activo**
    
    - ARP scan es relativamente rápido y preciso en redes locales.
        
    - Nos ayuda a mapear la red y preparar ataques posteriores.
        
3. **Base para ataques de MITM**
    
    - Una vez identificadas IPs y MACs activas, se pueden planificar técnicas como **ARP spoofing** o **MITM (Man-in-the-Middle)** en entornos controlados para pruebas de pentesting.
        
4. **Automatización de auditorías**
    
    - Este tipo de scripts se puede integrar en **herramientas personalizadas de pentesting** para reconocimiento de red de manera automatizada.    

---

En resumen, este PoC nos permite **descubrir hosts activos en una red local usando ARP**, estableciendo la base para fases de reconocimiento y pruebas más avanzadas en ciberseguridad ofensiva.

---
