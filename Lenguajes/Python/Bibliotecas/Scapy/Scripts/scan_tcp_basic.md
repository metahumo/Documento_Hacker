
---

# PoC: Escaneo TCP SYN con Scapy

## Introducción

En este ejemplo estamos utilizando **Scapy** para realizar un **escaneo TCP SYN** (también llamado _half-open scan_). Este tipo de prueba es fundamental en **ciberseguridad ofensiva** para identificar **puertos abiertos** en un host objetivo sin establecer una conexión completa TCP.

---

## Código explicado

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
    print(syn_scan('<IP_Objetivo>', [22,80,111,443,8080]))
```

### Paso a paso:

1. **Importación de Scapy**  
    Importamos `IP`, `TCP` y `sr` para construir paquetes TCP/IP y enviarlos, esperando respuestas.
    
2. **Construcción de paquetes SYN**
    
    ```python
    [IP(dst=target)/TCP(dport=p, flags='S') for p in ports]
    ```
    
    - Creamos un paquete TCP para cada puerto en la lista.
        
    - La bandera `S` indica **SYN**, es decir, “quiero iniciar conexión”.
        
    - Esto permite comprobar si el puerto responde sin completar la conexión TCP.
        
3. **Envío y recepción de paquetes**
    
    ```python
    ans, _ = sr(..., timeout=1, verbose=0)
    ```
    
    - `sr` envía los paquetes y devuelve las respuestas recibidas.
        
    - `timeout=1` indica esperar un segundo por respuesta.
        
    - `verbose=0` evita que Scapy imprima información extra.
        
4. **Detección de puertos abiertos**
    
    ```python
    if r.haslayer(TCP) and r[TCP].flags == 0x12:
        open_ports.append(s[TCP].dport)
    ```
    
    - `0x12` = **SYN/ACK**, respuesta típica de un puerto abierto.
        
    - Si recibimos SYN/ACK, agregamos ese puerto a la lista de abiertos.
        
5. **Ejecución del escaneo**
    
    ```python
    print(syn_scan('<IP_Objetivo>', [22,80,111,443,8080]))
    ```
    
    - Escaneamos los puertos 22, 80, 111, 443 y 8080 del host objetivo.
        
    - Imprimimos los puertos detectados como abiertos.
        

---

## Salida de ejemplo

```
[111]
```

- Esto indica que **solo el puerto 111** está abierto en `<IP_Objetivo>`.
    
- Los demás puertos (22, 80, 443, 8080) no respondieron con SYN/ACK, por lo que están **cerrados o filtrados**.
    

---

## Importancia en ciberseguridad ofensiva

1. **Reconocimiento activo de puertos**
    
    - Saber qué servicios están disponibles nos ayuda a planificar ataques más específicos (SSH, HTTP, RPC, etc.).
        
2. **Escaneo discreto (half-open scan)**
    
    - El escaneo SYN evita completar la conexión TCP, reduciendo el riesgo de ser detectados por algunos IDS/IPS.
        
3. **Base para exploits posteriores**
    
    - Una vez identificados los puertos abiertos, podemos probar **vulnerabilidades específicas de cada servicio**.
        
4. **Automatización de pruebas**
    
    - Este tipo de script puede integrarse en auditorías y herramientas de pentesting personalizadas.
        

---

En resumen, este PoC nos permite **identificar rápidamente puertos abiertos mediante TCP SYN**, estableciendo la base para un reconocimiento activo y planificado durante pruebas de ciberseguridad ofensiva.

---
