# PoC: Escaneo ARP de hosts con Scapy

## Introducción

Este PoC muestra un **escáner ARP simple** implementado con **Scapy** en Python. Es una herramienta rápida para **descubrir hosts activos en una red local** (subreds), útil en fases de reconocimiento de pruebas de pentesting en entornos controlados.
El script envía peticiones ARP en broadcast y muestra los pares **IP ⇢ MAC** que responden.

---

## Código (scan\_hosts.py)

```python
#!/usr/bin/env python3

import argparse
import scapy.all as scapy
import sys
import signal

def def_handler(sig, frame):
    print(f"\n[!] Saliendo...\n")

signal.signal(signal.SIGINT, def_handler)

def get_arguments():

    parser = argparse.ArgumentParser(description='Escaner ARP de host')
    parser.add_argument("-t", "--target", dest="target", help='Use -p 192.168.1.1-100 or nmap')
    options = parser.parse_args()
    
    if options.target is None:
        parser.print_help()
        sys.exit(1)

    return options.target

def scan(ip):
    # Esto crea un paquete ARP (1 de 2)

    arp_packet = scapy.ARP(pdst=ip) 
    # paquete broadcast (2 de 2)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # unimos los dos paquetes sobreescribiendo el valor de uno de ellos

    arp_packet = broadcast_packet/arp_packet
    # Para enviar paquete (.srp) recibimos dos valores, los contestan y los que no

    answered, unaswered = scapy.srp(arp_packet, timeout=1, verbose=False)
    
    # Almacenamos el comando summary (para ver mac)
    response = answered.summary()

    if response:
        print(response)

def main():
    target = get_arguments()
    scan(target)

if __name__ == '__main__':
    main()
```

---

## Explicación del código — paso a paso

1. **Manejo de interrupciones (Ctrl+C)**

   ```python
   import signal
   def def_handler(sig, frame):
       print(f"\n[!] Saliendo...\n")
   signal.signal(signal.SIGINT, def_handler)
   ```

   * Captura `SIGINT` para salir limpiamente mostrando un aviso.

2. **Argumentos de línea de comandos**

   ```python
   parser = argparse.ArgumentParser(description='Escaner ARP de host')
   parser.add_argument("-t", "--target", dest="target", help='Use -p 192.168.1.1-100 or nmap')
   ```

   * El script requiere `-t/--target` con rango o subred (`192.168.1.0/24`, `192.168.1.1-100`, etc.).
   * Si no se provee, muestra la ayuda y sale.

3. **Construcción del paquete ARP y broadcast Ethernet**

   ```python
   arp_packet = scapy.ARP(pdst=ip)
   broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
   arp_packet = broadcast_packet/arp_packet
   ```

   * `ARP(pdst=ip)` crea la consulta ARP dirigida al objetivo o rango.
   * `Ether(dst="ff:ff:ff:ff:ff:ff")` prepara la trama de broadcast para que la petición llegue a toda la LAN.
   * Al concatenarlos (`/`) se obtiene un paquete Ethernet+ARP listo para enviar.

4. **Envía y recibe respuestas con `srp`**

   ```python
   answered, unaswered = scapy.srp(arp_packet, timeout=1, verbose=False)
   ```

   * `srp` envía en capa 2 y espera respuestas.
   * `answered` contiene las respuestas; `unanswered` las no respondidas.
   * `timeout=1` hace que la espera sea corta (ajustable).

5. **Resumen de respuestas**

   ```python
   response = answered.summary()
   if response:
       print(response)
   ```

   * `answered.summary()` devuelve líneas tipo `Ether / ARP who has X says Y ==> Ether / ARP is at MAC says X / Padding`.
   * Se imprime solo si hay respuestas.

---

## Ejecución (ejemplo)

Comando usado:

```bash
python3 scan_hosts.py -t 192.168.1.0/24
```

Salida de ejemplo que generó el script:

```
Ether / ARP who has 192.168.1.1 says 192.168.1.66 ==> Ether / ARP is at cc:00:f1:c0:53:c0 says 192.168.1.1 / Padding
Ether / ARP who has 192.168.1.38 says 192.168.1.66 ==> Ether / ARP is at 94:bb:43:12:76:2c says 192.168.1.38 / Padding
Ether / ARP who has 192.168.1.110 says 192.168.1.66 ==> Ether / ARP is at 08:00:27:ca:1d:d2 says 192.168.1.110 / Padding
Ether / ARP who has 192.168.1.17 says 192.168.1.66 ==> Ether / ARP is at 22:74:ee:1b:8a:f2 says 192.168.1.17 / Padding
Ether / ARP who has 192.168.1.14 says 192.168.1.66 ==> Ether / ARP is at b6:f4:17:a4:60:70 says 192.168.1.14 / Padding
Ether / ARP who has 192.168.1.72 says 192.168.1.66 ==> Ether / ARP is at 9e:3e:ee:06:7a:13 says 192.168.1.72 / Padding
```

### Interpretación de la salida

Cada línea resume una transacción ARP:

* `Ether / ARP who has 192.168.1.1 says 192.168.1.66` → la petición ARP preguntaba "¿Quién tiene 192.168.1.1?" y fue enviada desde 192.168.1.66 (tu interfaz).
* `==> Ether / ARP is at cc:00:f1:c0:53:c0 says 192.168.1.1` → la respuesta indica que la IP `192.168.1.1` corresponde a la MAC `cc:00:f1:c0:53:c0`.
* `Padding` es relleno de la trama Ethernet; es normal en estas salidas.

De forma práctica, cada línea te da el par **IP ←→ MAC** detectado en la red.

---

## Importancia en ciberseguridad ofensiva

1. **Descubrimiento de hosts en LAN**

   * ARP scan permite mapear la red local con alta fiabilidad (no depende de puertos abiertos).

2. **Base para ataques/ pruebas posteriores**

   * Con IPs y MACs activas puedes planificar ARP spoofing, MITM o dirigir pruebas específicas contra hosts detectados (siempre en entornos controlados/consentidos).

3. **Velocidad y simplicidad**

   * Scapy permite construir y enviar paquetes a bajo nivel con mucha flexibilidad (p. ej. modificar TTLs, campos, crear respuestas malformadas para pruebas).

4. **Integración en pipelines**

   * Usar `answered` permite parsear resultados y alimentar otras fases (fingerprinting, enumeración de servicios, reportes).

---

## Recomendaciones y mejoras

* **Mostrar salida en formato tabular o JSON** para integrar mejor con otras herramientas (parseo automático).
* **Aumentar `timeout`** si la red es lenta, o lanzar múltiples intentos por host para mayor fiabilidad.
* **Soporte de rangos cortos** (`192.168.1.1-100`) parseando la entrada para iterar IPs sin usar CIDR.
* **Ejecutar con privilegios**: en la mayoría de sistemas enviar paquetes en capa 2 requiere permisos (ejecutar con `sudo` o privilegios adecuados).
* **Respetar entornos**: usar siempre en redes de laboratorio o con autorización explícita.

---

En resumen, `scan_hosts.py` es un PoC claro y compacto para **descubrir hosts activos en una LAN vía ARP** usando Scapy, y la salida `summary()` proporciona rápidamente los pares IP–MAC útiles para fases posteriores de reconocimiento y pruebas en entornos controlados.

---
