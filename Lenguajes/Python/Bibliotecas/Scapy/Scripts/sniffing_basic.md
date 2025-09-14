
---

# PoC: Sniffing ICMP con Scapy

## Introducción

En este ejemplo estamos utilizando **Scapy** para capturar y analizar paquetes **ICMP** en nuestra red. Este tipo de pruebas se usa comúnmente en **ciberseguridad ofensiva** durante fases de **reconocimiento pasivo**, para identificar hosts activos y analizar el tráfico ICMP sin generar mucho ruido en la red.

---

## Código explicado

```python
from scapy.all import sniff

# Captura 10 paquetes ICMP
pkts = sniff(filter="icmp", count=10, iface="ens33")
for p in pkts:
    print(p.summary())
```

### Paso a paso:

1. **Importación de Scapy**  
    Importamos la función `sniff` con `from scapy.all import sniff`. Esto nos permite capturar paquetes que atraviesan la interfaz de red seleccionada.
    
2. **Captura de paquetes ICMP**
    
    ```python
    pkts = sniff(filter="icmp", count=10, iface="ens33")
    ```
    
    - `filter="icmp"`: captura únicamente paquetes ICMP (como pings).
        
    - `count=10`: se detiene automáticamente tras capturar 10 paquetes.
        
    - `iface="ens33"`: indica la interfaz de red a monitorear. En nuestro entorno puede variar (`eth0`, `wlan0`, etc.).
        
3. **Resumen de paquetes**
    
    ```python
    for p in pkts:
        print(p.summary())
    ```
    
    - `p.summary()` genera un resumen conciso de cada paquete.
        
    - `print()` lo muestra en pantalla, permitiéndonos ver **IP de origen y destino, tipo de ICMP y el identificador de secuencia**.
        

---

## Salida de ejemplo

```
Ether / IP / ICMP <IP_Atacante> > <IP_Objetivo> echo-request 0 / Raw
Ether / IP / ICMP <IP_Objetivo> > <IP_Atacante> echo-reply 0 / Raw
Ether / IP / ICMP <IP_Atacante> > <IP_Objetivo> echo-request 1 / Raw
Ether / IP / ICMP <IP_Objetivo> > <IP_Atacante> echo-reply 1 / Raw
Ether / IP / ICMP <IP_Atacante> > <IP_Objetivo> echo-request 2 / Raw
Ether / IP / ICMP <IP_Objetivo> > <IP_Atacante> echo-reply 2 / Raw
...
```

- Cada línea muestra un paquete ICMP capturado:
    
    - **echo-request**: el host atacante envía un ping.
        
    - **echo-reply**: el host objetivo responde.
        
- Esto nos permite identificar **hosts activos** y analizar la comunicación ICMP entre ellos.
    

---

## Importancia en ciberseguridad ofensiva

1. **Reconocimiento pasivo de hosts**
    
    - Podemos detectar qué máquinas están activas sin generar tráfico adicional que llame la atención.
        
2. **Análisis de firewalls y filtros ICMP**
    
    - Si un host no responde, puede indicar que tiene **bloqueos ICMP** o configuraciones de firewall estrictas.
        
3. **Monitoreo de tráfico ICMP**
    
    - Nos permite identificar patrones de comunicación, posibles ataques o escaneos de red.
        
4. **PoC y auditorías automatizadas**
    
    - Scripts como este pueden integrarse en pruebas más avanzadas, combinando sniffing pasivo con técnicas de **enumeración de red y fingerprinting**.
        

---

En resumen, este PoC nos permite **capturar, analizar y resumir paquetes ICMP**, estableciendo una base sólida para técnicas de reconocimiento pasivo y pruebas avanzadas en ciberseguridad ofensiva.

---
