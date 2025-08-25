
---

# Uso básico para la enumeración de servicios y puertos

## Escaneo de puertos y servicios con Nmap

```bash
nmap -sV --open -oA initial_scan -n -Pn -sS -v IP_Objetivo
```

[i]  El primer escaneo de Nmap lo iniciamos utilizando la lista de puertos más comunes que Nmap escanea por defecto cuando no se especifican puertos (es decir, al no usar el parámetro `-p` con un rango de puertos o `-p-`, Nmap escanea los 1000 puertos más comunes).

[i] El parámetro `--open` hace que Nmap solo reporte los puertos abiertos, lo cual es útil cuando queremos centrarnos exclusivamente en los servicios activos y no perder tiempo con puertos cerrados.

[i] El parámetros `-n` se utiliza para agilizar el proceso, ya que evita la resolución DNS (es decir, Nmap no intentará traducir las direcciones IP a nombres de dominio). Además, esto ayuda a minimizar el tráfico DNS, lo cual es relevante en pruebas de penetración donde se desea mantener un perfil bajo y evitar la detección temprana.

[i] El parámetro `-Pn` evita que Nmap realice una verificación de hosts con ping (ICMP), lo cual es necesario si el objetivo tiene medidas de protección contra este tipo de escaneos. En redes donde los hosts no responden a pings, este parámetro garantiza que el escaneo se realice sin fallar en la detección del host.

[i] El parámetro `-sV` se utiliza para identificar la versión de los servicios que están corriendo en los puertos abiertos, lo cual es crucial para detectar vulnerabilidades conocidas asociadas a versiones específicas de los servicios.

[i] El parámetro `-sS` realiza un "SYN scan", que es una técnica rápida y sigilosa. Este tipo de escaneo no completa el handshake TCP, lo que permite detectar puertos abiertos sin dejar muchas huellas en el sistema de destino, lo que lo hace más difícil de detectar por medidas de seguridad.

[+] Ahora, el paso lógico sería proceder con la enumeración de exhaustiva de cada puerto detectado. Para este ejemplo numeramos los puertos **22** y **80**

```bash
nmap -p22,80 -Pn -n -sS -v -sC -oA port_scan 10.129.168.126
```

[ i ] El parámetro `-sC` ejecuta un serie de scripts predeterminados por nmap, de esta forma podemos hacer una primera aproximación con más detalle de cada puerto numerado.

[ i ] El parámetro `-sU` en Nmap permite realizar un escaneo de **puertos UDP**, en lugar de los tradicionales puertos TCP.

🔹 Ejemplo de uso:

```bash
nmap -sU -p 53,161,500 94.237.54.190
```

La técnica de escaneo ICMP scan en Nmap utiliza paquetes ICMP Echo Request para determinar si un host está activo en la red. Este tipo de escaneo es útil para descubrir hosts sin necesidad de escanear puertos TCP o UDP.

🔹 Comando de ejemplo:

```bash
nmap -sn 94.237.54.190
```

Escaneo **UDP**

```bash
sudo nmap -sU -p- <IP_objetivo>
```

---

## Escaneo de scripts NSE adicionales

[i] El parámetro `-sC` ejecuta los scripts por defecto de Nmap (NSE), pero podemos usar scripts específicos con `--script`:

```bash
nmap -p 22,80 --script=http-enum,ssh-hostkey -Pn -n -sS -v IP_Objetivo
```

[i] Esto permite enumerar rutas web, identificar versiones de SSH, detectar vulnerabilidades específicas o realizar tareas de información adicionales.

---

## Escaneo de todos los puertos

[i] Por defecto, Nmap escanea los 1000 puertos más comunes. Para escanear todos los puertos TCP:

```bash
nmap -p- -sV -Pn -n -sS -v IP_Objetivo
```

[i] Escanear todos los puertos puede ser útil si sospechamos servicios corriendo en puertos no estándar.

---

## Detección de sistema operativo

[i] Podemos intentar identificar el sistema operativo del objetivo con `-O`:

```bash
nmap -O -Pn -n -sS -v IP_Objetivo
```

[i] Nmap analiza distintos parámetros de la pila TCP/IP para hacer fingerprint del sistema operativo. Esto ayuda a determinar potenciales vectores de ataque específicos.

---

## Escaneo de versiones agresivo

[i] Para obtener información más detallada sobre servicios, podemos usar `-A`, que activa detección de SO, scripts NSE y traceroute:

```bash
nmap -A -p22,80 -Pn -n -sS -v IP_Objetivo
```

[i] Es un escaneo más ruidoso, pero nos da un panorama completo del host.

---

## Escaneo de puertos UDP

[i] Los puertos UDP no responden como TCP, por lo que requieren un escaneo específico con `-sU`:

```bash
sudo nmap -sU -p 53,161,500 -Pn -n -v IP_Objetivo
```

[i] Este escaneo puede ser más lento y requiere privilegios de administrador.

---

## Escaneo rápido sin verificación de puertos

[i] Si solo queremos saber qué hosts están activos:

```bash
nmap -sn -n IP_Objetivo/24
```

[i] Este escaneo solo hace ping (ICMP o ARP) y no escanea puertos. Es útil para mapeo rápido de red.

---

## Tuning de velocidad y evasión

[i] Nmap permite ajustar la velocidad de escaneo con `-T` (de 0 a 5) y algunos parámetros de evasión como fragmentación de paquetes `-f` o cambio de puerto fuente `--source-port`:

```bash
nmap -sS -p 1-65535 -Pn -n -T4 -f IP_Objetivo
```

[i] Esto ayuda a reducir la detección por IDS/IPS y a acelerar el escaneo en redes grandes.

---

> Con estos parámetros podemos adaptar nuestros escaneos de Nmap según el objetivo: rápida enumeración, descubrimiento completo de servicios, evasión de defensas o escaneo agresivo.

---

